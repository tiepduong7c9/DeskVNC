//! Per-host icons: the picture a host's dedicated window wears (PRD/05 §5).
//!
//! Two kinds of icon can sit in `hosts.icon`, and only one of them involves
//! this module. `builtin:<key>` names an image compiled into the shell and
//! needs nothing on disk. `file` means the user chose a picture of their own,
//! and that picture lives here, as `data_dir/host-icons/<host_id>.png`.
//!
//! The user's file is **copied, normalised and re-encoded**, never referenced
//! where it sat. Three reasons, in the order they bite:
//!
//! 1. A path into `~/Downloads` stops resolving the first time that folder is
//!    tidied, and an icon that silently stops drawing is worse than one that
//!    was never set.
//! 2. Window icons want modest, square-ish RGBA. A 12-megapixel JPEG would be
//!    decoded on every window open.
//! 3. Re-encoding means exactly one decoder runs against a user-supplied file,
//!    here, once, under a size and pixel limit, rather than on every platform
//!    icon path we hand the bytes to.

use std::path::{Path, PathBuf};

use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder, ImageReader};

use crate::{thumbs::encode_key, Error, Result, Store};

/// Longest edge of a stored host icon.
///
/// Every platform that draws a window icon picks the size it wants out of
/// what it is given; 256 is the largest any of them asks for, so this is the
/// point past which more pixels buy nothing.
pub const ICON_SIZE: u32 = 256;

/// Largest source file accepted from the picker.
///
/// This is a person choosing a picture, not a bulk import, so the bound is
/// about refusing to decode something absurd rather than about being tight.
pub const MAX_ICON_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

/// Pixel budget handed to the decoder, independent of the byte budget above.
///
/// A few kilobytes of PNG can declare a 30000x30000 canvas; the file-size
/// check alone would wave it through and the allocation would be measured in
/// gigabytes. `image`'s limits reject it before any buffer is reserved.
const MAX_ICON_PIXELS: u64 = 64 * 1024 * 1024;

/// The value stored in `hosts.icon` for a user-supplied picture.
pub const FILE_ICON_TAG: &str = "file";

/// Prefix of the stored value for an icon compiled into the shell.
pub const BUILTIN_ICON_PREFIX: &str = "builtin:";

/// Decode `source` and re-encode it as the PNG we would store for a host.
///
/// Writes nothing. This is split out from [`Store::import_host_icon`] so the
/// host editor can *show* what it would keep before the user commits to it:
/// the picker previews these bytes, and only a saved profile causes them to
/// be written. Without the split, picking a picture and then cancelling the
/// dialog would still have replaced the host's icon.
pub fn normalise_icon(source: &Path) -> Result<Vec<u8>> {
    let len = std::fs::metadata(source)?.len();
    if len > MAX_ICON_SOURCE_BYTES {
        return Err(Error::InvalidData(format!(
            "image is {len} bytes, the limit for a host icon is {MAX_ICON_SOURCE_BYTES}"
        )));
    }
    let bytes = std::fs::read(source)?;

    // The format is guessed from the content, not the extension: the picker
    // cannot stop someone choosing a JPEG named `.png`, and trusting the name
    // would turn that into a decode error rather than the icon they asked for.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(u32::MAX);
    limits.max_image_height = Some(u32::MAX);
    limits.max_alloc = Some(MAX_ICON_PIXELS * 4);
    let mut reader = ImageReader::new(std::io::Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|e| Error::Image(format!("could not read the image: {e}")))?;
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|e| Error::Image(format!("could not decode the image: {e}")))?;

    // Only ever downscale. Blowing a 32x32 favicon up to 256 would make it
    // look worse everywhere it is drawn, and the platforms scale it up
    // themselves if they want to.
    let resized = if decoded.width() > ICON_SIZE || decoded.height() > ICON_SIZE {
        decoded.resize(ICON_SIZE, ICON_SIZE, image::imageops::FilterType::Lanczos3)
    } else {
        decoded
    };
    let rgba = resized.into_rgba8();
    let (w, h) = rgba.dimensions();
    if w == 0 || h == 0 {
        return Err(Error::Image("the image has no pixels".into()));
    }

    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(rgba.as_raw(), w, h, ExtendedColorType::Rgba8)
        .map_err(|e| Error::Image(format!("png encode failed: {e}")))?;
    Ok(png)
}

impl Store {
    /// Path of the (possibly nonexistent) icon file for a host.
    pub fn host_icon_path(&self, host_id: &str) -> PathBuf {
        self.data_dir()
            .join("host-icons")
            .join(format!("{}.png", encode_key(host_id)))
    }

    /// Decode `source`, normalise it, and store it as this host's icon.
    ///
    /// Returns the stored PNG bytes, which are not always what was picked:
    /// an oversized image comes back visibly resized.
    ///
    /// Writing the file does **not** set `hosts.icon`. That is the profile
    /// save's job, and this call is made from the same save, so the two land
    /// together: a dialog the user cancels writes neither.
    pub fn import_host_icon(&self, host_id: &str, source: &Path) -> Result<Vec<u8>> {
        if host_id.is_empty() {
            return Err(Error::InvalidData("empty icon key".into()));
        }
        let png = normalise_icon(source)?;

        let dir = self.data_dir().join("host-icons");
        std::fs::create_dir_all(&dir)?;
        let path = self.host_icon_path(host_id);
        let tmp = dir.join(format!("{}.png.tmp", encode_key(host_id)));
        std::fs::write(&tmp, &png)?;
        // Rename, so a window opening at this moment reads either the old icon
        // or the new one and never a half-written file.
        std::fs::rename(&tmp, &path)?;
        Ok(png)
    }

    /// The stored PNG bytes for a host's own icon, or `None` if there is none.
    ///
    /// Answers only for the `file` form. A `builtin:` icon is compiled into
    /// the shell and is resolved there.
    pub fn load_host_icon(&self, host_id: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.host_icon_path(host_id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a host's icon file. A missing file is not an error.
    pub fn delete_host_icon(&self, host_id: &str) -> Result<()> {
        match std::fs::remove_file(self.host_icon_path(host_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        (dir, store)
    }

    /// Encode a solid RGBA image as a PNG, for feeding to the importer.
    fn png_of(w: u32, h: u32) -> Vec<u8> {
        let pixels = vec![0x7Fu8; (w * h * 4) as usize];
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(&pixels, w, h, ExtendedColorType::Rgba8)
            .unwrap();
        out
    }

    #[test]
    fn an_oversized_picture_is_stored_within_the_icon_size() {
        let (dir, store) = temp_store();
        let src = dir.path().join("big.png");
        std::fs::write(&src, png_of(900, 600)).unwrap();

        let stored = store.import_host_icon("host-1", &src).unwrap();
        let img = image::load_from_memory(&stored).unwrap();
        assert!(img.width() <= ICON_SIZE && img.height() <= ICON_SIZE);
        // Aspect preserved, so the longest edge is the one that hit the cap.
        assert_eq!(img.width(), ICON_SIZE);
        assert_eq!(store.load_host_icon("host-1").unwrap().unwrap(), stored);
    }

    #[test]
    fn a_small_picture_is_not_blown_up() {
        let (dir, store) = temp_store();
        let src = dir.path().join("small.png");
        std::fs::write(&src, png_of(32, 32)).unwrap();

        let stored = store.import_host_icon("host-1", &src).unwrap();
        let img = image::load_from_memory(&stored).unwrap();
        assert_eq!((img.width(), img.height()), (32, 32));
    }

    #[test]
    fn a_file_that_is_not_an_image_is_refused_rather_than_stored() {
        let (dir, store) = temp_store();
        let src = dir.path().join("notes.txt");
        std::fs::write(&src, b"this is not a picture").unwrap();

        assert!(store.import_host_icon("host-1", &src).is_err());
        assert!(store.load_host_icon("host-1").unwrap().is_none());
    }

    #[test]
    fn deleting_an_icon_twice_is_not_an_error() {
        let (dir, store) = temp_store();
        let src = dir.path().join("x.png");
        std::fs::write(&src, png_of(64, 64)).unwrap();
        store.import_host_icon("host-1", &src).unwrap();

        store.delete_host_icon("host-1").unwrap();
        store.delete_host_icon("host-1").unwrap();
        assert!(store.load_host_icon("host-1").unwrap().is_none());
    }

    /// Deleting a host takes its picture with it. Without this the data
    /// directory accumulates icons for machines that no longer exist, and a
    /// recycled id would inherit a stranger's icon.
    #[test]
    fn deleting_a_host_removes_its_icon() {
        let (dir, store) = temp_store();
        let host = crate::HostProfile {
            icon: Some(crate::FILE_ICON_TAG.into()),
            ..Default::default()
        };
        store.save_host(&host).unwrap();

        let src = dir.path().join("x.png");
        std::fs::write(&src, png_of(48, 48)).unwrap();
        store.import_host_icon(&host.id, &src).unwrap();
        assert!(store.load_host_icon(&host.id).unwrap().is_some());

        store.delete_host(&host.id).unwrap();
        assert!(store.load_host_icon(&host.id).unwrap().is_none());
    }

    /// The key reaches the filesystem, and a discovered host's key is not a
    /// UUID. It must not be able to name a file outside the icon directory.
    #[test]
    fn a_key_with_separators_in_it_stays_inside_the_icon_directory() {
        let (_dir, store) = temp_store();
        let path = store.host_icon_path("../../etc/passwd");
        assert_eq!(path.parent().unwrap(), store.data_dir().join("host-icons"));
    }
}

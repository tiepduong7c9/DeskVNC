//! Per-host window icons: what `hosts.icon` names, and how it becomes a
//! picture on a dedicated session window (PRD/05 §5).
//!
//! # What the platforms actually do with this
//!
//! A window icon is not a portable idea, and this is the honest summary:
//!
//! - **Windows** draws it in the taskbar button and the window's title bar,
//!   per window. This is where the feature does the most work.
//! - **Linux/X11** publishes it as `_NET_WM_ICON`, which panels and task
//!   lists read per window.
//! - **Linux/Wayland** ignores it. A Wayland compositor takes a window's icon
//!   from the `.desktop` file its `app_id` matches, and every window this
//!   process opens shares one `app_id`, so the dock keeps showing the
//!   application icon. Nothing here is broken; there is no per-window icon to
//!   set. GNOME users see the effect in the library, not the dash.
//! - **macOS** has no per-window icon at all: the Dock is per application by
//!   design, so the call is a no-op.
//!
//! This is why the icon is also drawn on the host tile. On the two platforms
//! above that ignore it, the tile is the only place the choice is visible, and
//! a setting with no visible effect anywhere is a setting nobody trusts.

use tauri::image::Image;

/// An icon compiled into the binary: the stable key stored in `hosts.icon`
/// (as `builtin:<key>`), the name shown in the picker, and the PNG.
pub struct Builtin {
    pub key: &'static str,
    pub label: &'static str,
    pub png: &'static [u8],
}

macro_rules! builtin {
    ($key:literal, $label:literal) => {
        Builtin {
            key: $key,
            label: $label,
            png: include_bytes!(concat!("../icons/hosts/", $key, ".png")),
        }
    };
}

/// The bundled palette.
///
/// Colour rather than iconography, deliberately. These exist so a row of
/// dedicated windows can be told apart at a glance in a taskbar, where the
/// image is perhaps 16 pixels across and a hue is the only thing that
/// survives; anyone who wants a distribution logo or a company mark picks
/// their own file instead.
///
/// The keys are storage, not copy: renaming one silently blanks the icon of
/// every host that chose it, so they never change. The labels are free to.
pub const BUILTINS: &[Builtin] = &[
    builtin!("blue", "Blue"),
    builtin!("green", "Green"),
    builtin!("purple", "Purple"),
    builtin!("orange", "Orange"),
    builtin!("red", "Red"),
    builtin!("teal", "Teal"),
    builtin!("pink", "Pink"),
    builtin!("slate", "Slate"),
];

/// The PNG for `builtin:<key>`, or `None` for a key this build does not have.
///
/// `None` is the whole point of looking it up rather than trusting the stored
/// string: a profile written by a build with a larger palette must still open,
/// wearing the application icon, rather than failing to open at all.
pub fn builtin_png(key: &str) -> Option<&'static [u8]> {
    BUILTINS.iter().find(|b| b.key == key).map(|b| b.png)
}

/// Resolve a stored `hosts.icon` value to PNG bytes.
///
/// `None` covers every way a host can end up with no icon of its own, and all
/// of them are ordinary: the column is null, the key belongs to a newer build,
/// the user's file was removed from under us, or the value is a form this
/// build does not know.
pub fn resolve(store: &vnc_store::Store, host_id: &str, spec: Option<&str>) -> Option<Vec<u8>> {
    match spec?.trim() {
        vnc_store::FILE_ICON_TAG => store.load_host_icon(host_id).ok().flatten(),
        s => {
            let key = s.strip_prefix(vnc_store::BUILTIN_ICON_PREFIX)?;
            builtin_png(key).map(<[u8]>::to_vec)
        }
    }
}

/// Decode PNG bytes into the RGBA image the window builder wants.
///
/// Returns `None` rather than an error on a file that will not decode. The
/// caller is opening a session, and an icon is decoration: a window with the
/// default icon is a far better outcome than a connection that refused to
/// start because a picture was corrupt.
pub fn to_image(png: &[u8]) -> Option<Image<'static>> {
    match Image::from_bytes(png) {
        Ok(image) => Some(image),
        Err(e) => {
            tracing::warn!("ignoring a host icon that would not decode: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_decodes_as_an_image() {
        // These are compiled in, so a broken one is a broken build, not a bad
        // input. Catching it here beats catching it as a window that opens
        // without the icon somebody chose.
        for b in BUILTINS {
            assert!(
                to_image(b.png).is_some(),
                "builtin icon {} does not decode",
                b.key
            );
        }
    }

    #[test]
    fn builtin_keys_are_unique() {
        // The key is what `hosts.icon` stores. A duplicate would make two
        // entries in the picker save the same value.
        let mut keys: Vec<&str> = BUILTINS.iter().map(|b| b.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate builtin icon key");
    }

    #[test]
    fn an_unknown_builtin_key_resolves_to_no_icon() {
        assert!(builtin_png("chartreuse").is_none());
    }
}

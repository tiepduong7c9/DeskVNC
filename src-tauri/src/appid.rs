//! Giving a session window its own identity to the desktop, so a dock can
//! show it as something other than "another DeskVNCViewer window" (PRD/05 §5).
//!
//! # Why a per-window icon is not enough
//!
//! GNOME's dash, and dash-to-dock with it, groups by *application*, not by
//! window, and takes each icon from the `.desktop` file that the window's
//! `app_id` matches. It never looks at the per-window icon. That is true under
//! X11 as well, so this is not a Wayland quirk that a different session type
//! would avoid: every window one process opens shares one `app_id`, so the
//! dock has exactly one entry to draw.
//!
//! The way out is the one browsers already use for profiles: give the window
//! an `app_id` of its own and put a `.desktop` file where the shell will find
//! it. That is what this module does, for hosts that have chosen an icon.
//!
//! # What it writes, and where
//!
//! One file per such host in the user's `applications` directory, named for
//! the `app_id` it declares, because GNOME matches a Wayland `app_id` against
//! the desktop file's *id*, which is its file name. It is removed when the
//! host is deleted or gives up its icon.
//!
//! Writing outside our own data directory is not something to do lightly, and
//! it is why this is opt-in per host: a library where nobody sets an icon
//! writes nothing at all.
//!
//! # A delay we cannot remove
//!
//! *Changing* a host's icon takes a second or two to reach the dock, and
//! connecting inside that window shows the previous icon once.
//!
//! The desktop file's name never changes, so GNOME keeps matching the window
//! to the right entry throughout; what it serves is the icon it cached the
//! last time it read that entry. It re-reads on a directory monitor that GIO
//! rate-limits and GNOME debounces again on top, and there is no call to make
//! it look now. Writing the entry when the host is saved buys as much of that
//! delay back as exists to buy.
//!
//! Confirmed rather than assumed: the stale icon is the *previous* one, not a
//! generic fallback, which is only possible if the match already succeeded.
//! An `app_id` that had failed to match would draw neither.
//!
//! It costs nothing after the change has settled, and nothing at all when an
//! icon is set for the first time, because there is no earlier icon to cache.
//!
//! Linux only. Windows draws a per-window icon by itself, and macOS has one
//! Dock tile per application by design, with no `app_id` equivalent to set.

use std::path::{Path, PathBuf};

use tauri::WebviewWindow;

/// Prefix of both the `app_id` and the desktop file name.
///
/// Distinct enough that a file here can never collide with a real
/// application's, and greppable when someone finds one and wonders what wrote
/// it.
const APP_ID_PREFIX: &str = "deskvncviewer-host-";

/// The `app_id` for a host, or `None` for an id that must not reach a path.
///
/// Host ids are UUIDs, but they arrive from the store rather than from a
/// generator we control, and this value becomes a file name. Anything outside
/// `[A-Za-z0-9-]` is refused rather than escaped: the cost of refusing is one
/// host without a dock icon, and the cost of getting the escaping subtly wrong
/// is a write outside the applications directory.
pub fn app_id_for(host_id: &str) -> Option<String> {
    if host_id.is_empty() || host_id.len() > 64 {
        return None;
    }
    if !host_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return None;
    }
    Some(format!("{APP_ID_PREFIX}{host_id}"))
}

/// `$XDG_DATA_HOME/applications`, or the specification's default for it.
fn applications_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
        })?;
    Some(base.join("applications"))
}

/// Where this host's desktop file lives, whether or not it exists.
pub fn entry_path(host_id: &str) -> Option<PathBuf> {
    let app_id = app_id_for(host_id)?;
    Some(applications_dir()?.join(format!("{app_id}.desktop")))
}

/// The `app_id` for a host whose desktop entry is already on disk.
///
/// What a window opening should ask. Publishing from there instead would
/// rewrite the file at the exact moment the window maps, and a rewrite makes
/// GNOME re-read it, which is the race that writing at save time avoids. The
/// answer being `None` is the caller's cue to publish and accept the race, for
/// the one case that needs it: an entry that has gone missing under us.
pub fn app_id_if_published(host_id: &str) -> Option<String> {
    let app_id = app_id_for(host_id)?;
    entry_path(host_id)?.is_file().then_some(app_id)
}

/// Where the icons desktop files point at are kept.
///
/// A separate copy from `host-icons/`, because a bundled icon has no file at
/// all (it is compiled into the binary) and `Icon=` needs a path on disk. One
/// place for both kinds keeps the write and the cleanup single-branched.
fn icon_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("desktop-icons")
}

/// A short, content-derived tag for a picture.
///
/// FNV-1a, and nothing turns on it being hard to collide: this exists to make
/// two different pictures land on two different file names, not to
/// authenticate anything.
fn content_tag(png: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in png {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Where this host's icon goes, named for the picture it holds.
///
/// The content tag in the name is load bearing. GNOME caches the icon it
/// loaded for an application and only reconsiders when the `.desktop` file
/// changes; writing different pixels to the same path leaves both the file and
/// the cache untouched, so changing a host's icon changed nothing in the dock.
/// A new picture means a new path, which means a changed `Icon=` line, which
/// is what makes the shell look again.
pub fn icon_path(data_dir: &Path, host_id: &str, png: &[u8]) -> Option<PathBuf> {
    let app_id = app_id_for(host_id)?;
    Some(icon_dir(data_dir).join(format!("{app_id}-{tag}.png", tag = content_tag(png))))
}

/// Delete every icon file belonging to a host, except `keep`.
///
/// Icons are content-named, so changing one leaves the previous file behind.
/// The prefix match also catches the un-tagged name an earlier build wrote,
/// which would otherwise sit there forever.
fn prune_icons(data_dir: &Path, host_id: &str, keep: Option<&Path>) {
    let Some(app_id) = app_id_for(host_id) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(icon_dir(data_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if Some(path.as_path()) == keep {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `<app_id>-<tag>.png`, or `<app_id>.png` from before tags existed.
        // Anchored on the separator so one host id cannot match another's
        // files by being a prefix of it.
        let mine = name == format!("{app_id}.png")
            || (name.starts_with(&format!("{app_id}-")) && name.ends_with(".png"));
        if mine {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Escape a value for a desktop entry.
///
/// The friendly name is whatever the user typed. A newline in it would end the
/// `Name=` line and let the rest be read as another key, so the three escapes
/// the specification defines are applied and any other control character is
/// dropped.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// The desktop entry's text.
///
/// `NoDisplay=true` keeps these out of the application grid, where one entry
/// per saved host would be noise. It does not stop the shell matching a window
/// to them, which is all we need them for.
///
/// No `TryExec`. It would make the shell ignore the whole file when the named
/// binary is not on `PATH`, which is exactly the case during development, and
/// the symptom would be "the icon just does not work" with nothing to see.
fn entry_text(app_id: &str, name: &str, icon: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={name}\n\
         Comment=DeskVNCViewer remote session\n\
         Exec=deskvncviewer\n\
         Icon={icon}\n\
         Terminal=false\n\
         NoDisplay=true\n\
         StartupWMClass={app_id}\n\
         X-DeskVNC-Generated=true\n",
        name = escape(name),
        icon = escape(&icon.to_string_lossy()),
        app_id = app_id,
    )
}

/// Write (or refresh) the desktop entry and the icon it points at.
///
/// Called when a host's icon is saved and again at startup, NOT when a window
/// opens. GNOME notices a new `.desktop` file through a directory monitor and
/// takes a moment over it; a file written milliseconds before its window maps
/// loses that race and the first session comes up unmatched. Written at save
/// time it has been there for as long as the host has.
///
/// Returns the `app_id` to put on the window, or `None` when there is nothing
/// to match against: no icon, an unusable host id, or a write that failed.
/// Every one of those is a session that opens with the ordinary application
/// icon, never a session that fails to open.
pub fn publish(data_dir: &Path, host_id: &str, name: &str, icon_png: &[u8]) -> Option<String> {
    let app_id = app_id_for(host_id)?;
    let icon = icon_path(data_dir, host_id, icon_png)?;
    let entry = entry_path(host_id)?;

    if let Err(e) = write_file(&icon, icon_png) {
        tracing::warn!(host = %host_id, "could not write the dock icon: {e}");
        return None;
    }
    if let Err(e) = write_file(&entry, entry_text(&app_id, name, &icon).as_bytes()) {
        tracing::warn!(host = %host_id, "could not write the desktop entry: {e}");
        return None;
    }
    // After the entry points at the new file, never before: a crash in between
    // leaves a spare icon on disk, which is harmless, rather than an entry
    // naming one that is gone.
    prune_icons(data_dir, host_id, Some(&icon));
    Some(app_id)
}

/// Create the parent directory and write the file, replacing what was there.
///
/// A write whose content matches what is already on disk is skipped. That is
/// not about saving the write: touching a file in the applications directory
/// makes GNOME re-read it, and doing that on every startup and every save
/// would keep re-running the matching this whole module exists to get right.
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

/// Remove a host's desktop entry and its icon. Missing files are not an error.
///
/// Called when a host is deleted or stops using an icon. Leaving the file
/// would put a stale entry in the user's applications directory, naming a
/// machine their library no longer has.
pub fn withdraw(data_dir: &Path, host_id: &str) {
    if let Some(path) = entry_path(host_id) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(path = %path.display(), "could not remove: {e}"),
        }
    }
    prune_icons(data_dir, host_id, None);
}

/// Tell the compositor this window is its own application.
///
/// Best effort in every direction. A window that keeps the shared `app_id`
/// shows the application icon, which is what it did before any of this
/// existed, so nothing here is worth failing a connection over.
///
/// X11 is not covered. GTK 3 sets `WM_CLASS` once per process at realize time
/// and deprecated the only call that changed it, so the per-window icon
/// already set through `set_icon` remains the X11 answer.
pub fn set_app_id(window: &WebviewWindow, app_id: &str) {
    use gtk::glib::translate::ToGlibPtr;
    use gtk::prelude::*;

    let gtk_window = match window.gtk_window() {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!("no gtk window to give an app id to: {e}");
            return;
        }
    };
    // The `app_id` lives on the GdkWindow, which exists once the widget is
    // realized, and a built window already is. Deliberately NOT realized by
    // hand here: doing that to a window tao had not shown yet left GTK's
    // titlebar buttons unresponsive while the compositor's own window menu
    // still worked.
    let Some(gdk_window) = gtk_window.window() else {
        tracing::debug!("gtk window is not realized, leaving the app id alone");
        return;
    };
    let Ok(app_id) = std::ffi::CString::new(app_id) else {
        return;
    };

    // SAFETY: `ptr` is the live GdkWindow owned by `gdk_window`, borrowed for
    // the length of this call and not stored. The type check is what makes the
    // cast sound: `gdk_wayland_window_set_application_id` is only valid on a
    // Wayland window, and under X11 the same pointer is a GdkX11Window.
    unsafe {
        let ptr: *mut gtk::gdk::ffi::GdkWindow = gdk_window.to_glib_none().0;
        let is_wayland = gtk::glib::gobject_ffi::g_type_check_instance_is_a(
            ptr as *mut gtk::glib::gobject_ffi::GTypeInstance,
            gdk_wayland_sys::gdk_wayland_window_get_type(),
        );
        if is_wayland == 0 {
            tracing::debug!("not a wayland window, leaving the app id alone");
            return;
        }
        if gdk_wayland_sys::gdk_wayland_window_set_application_id(ptr as *mut _, app_id.as_ptr())
            == 0
        {
            tracing::debug!("the compositor did not take the app id");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_that_could_escape_the_applications_directory_is_refused() {
        // This value becomes a file name. Refusing is one host without a dock
        // icon; getting it wrong is a write somewhere else entirely.
        for bad in ["../../evil", "a/b", "a\\b", "", "with space", "a\nb"] {
            assert!(app_id_for(bad).is_none(), "{bad:?} should be refused");
        }
        assert_eq!(
            app_id_for("3f2504e0-4f89-11d3-9a0c-0305e82c3301").as_deref(),
            Some("deskvncviewer-host-3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        );
    }

    #[test]
    fn the_desktop_file_is_named_for_the_app_id_it_declares() {
        // GNOME matches a Wayland app_id against the desktop file's id, which
        // is its file name. If these two drift the window matches nothing and
        // the dock silently keeps the application icon.
        let host = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let app_id = app_id_for(host).unwrap();
        let path = entry_path(host).unwrap();
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("{app_id}.desktop")
        );
        let text = entry_text(&app_id, "Studio", Path::new("/tmp/i.png"));
        assert!(text.contains(&format!("StartupWMClass={app_id}\n")));
    }

    #[test]
    fn a_friendly_name_cannot_forge_another_key() {
        // The name is whatever the user typed. A raw newline would end the
        // Name= line and let the rest be read as a key of its own.
        let text = entry_text(
            "deskvncviewer-host-x",
            "Evil\nExec=/bin/sh -c 'rm -rf ~'",
            Path::new("/tmp/i.png"),
        );
        let names: Vec<&str> = text.lines().filter(|l| l.starts_with("Name=")).collect();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], r"Name=Evil\nExec=/bin/sh -c 'rm -rf ~'");
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Exec=")).count(),
            1,
            "the name must not be able to add a second Exec"
        );
    }

    /// The point of naming icons by content. GNOME only reconsiders an
    /// application's icon when its `.desktop` file changes, so a new picture
    /// has to arrive at a new path or the dock keeps showing the old one.
    #[test]
    fn a_different_picture_lands_on_a_different_path() {
        let dir = Path::new("/data");
        let host = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let one = icon_path(dir, host, b"first picture").unwrap();
        let two = icon_path(dir, host, b"second picture").unwrap();
        assert_ne!(one, two);
        // And the same picture is stable, or every save would rewrite the
        // entry and make the shell re-read it for nothing.
        assert_eq!(icon_path(dir, host, b"first picture").unwrap(), one);

        let entry_one = entry_text("deskvncviewer-host-x", "Studio", &one);
        let entry_two = entry_text("deskvncviewer-host-x", "Studio", &two);
        assert_ne!(
            entry_one, entry_two,
            "the entry must change when the icon does, or nothing re-reads it"
        );
    }

    #[test]
    fn changing_an_icon_leaves_no_stale_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path();
        let host = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

        let first = icon_path(data, host, b"first").unwrap();
        write_file(&first, b"first").unwrap();
        // The un-tagged name an earlier build wrote, which must also go.
        let legacy = icon_dir(data).join(format!("{}.png", app_id_for(host).unwrap()));
        write_file(&legacy, b"legacy").unwrap();
        // Another host's icon, which must NOT go.
        let other = icon_path(data, "11111111-2222-3333-4444-555555555555", b"x").unwrap();
        write_file(&other, b"x").unwrap();

        let second = icon_path(data, host, b"second").unwrap();
        write_file(&second, b"second").unwrap();
        prune_icons(data, host, Some(&second));

        assert!(second.is_file(), "the current icon must survive");
        assert!(!first.exists(), "the replaced icon must go");
        assert!(!legacy.exists(), "an untagged icon must go");
        assert!(other.is_file(), "another host's icon must be left alone");

        withdraw(data, host);
        assert!(!second.exists(), "withdrawing takes the current icon too");
        assert!(other.is_file());
    }

    /// Proven by making the file unwritable rather than by watching its
    /// timestamp: mtime resolution is a filesystem property, and on one with
    /// second granularity both writes land in the same second and the test
    /// passes whether or not the skip works.
    #[test]
    fn a_write_of_identical_content_does_not_touch_the_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("x.desktop");
        write_file(&path, b"first").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        // Identical: skipped, so the read-only file is never opened for
        // writing and this succeeds.
        write_file(&path, b"first").expect("an unchanged write must be skipped");

        // Different: actually attempted, and the read-only file refuses it.
        // That is what proves the first call skipped rather than succeeded by
        // some other route.
        assert!(
            write_file(&path, b"second").is_err(),
            "a changed write must really write"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_file(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn the_entry_is_hidden_from_the_grid_but_still_matchable() {
        let text = entry_text("deskvncviewer-host-x", "Studio", Path::new("/tmp/i.png"));
        assert!(text.contains("NoDisplay=true"));
        // TryExec would make the shell skip the file when the binary is not on
        // PATH, which is every development build.
        assert!(!text.contains("TryExec"));
    }
}

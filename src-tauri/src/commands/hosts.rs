//! Host-library commands: profiles, groups, tags, history, thumbnails.
//!
//! All storage calls are synchronous SQLite (`vnc_store::Store`), so every
//! command hops to `spawn_blocking` via [`super::blocking`].

use tauri::{AppHandle, State};
use vnc_store::{Group, HistoryEntry, HostProfile, Tag};

use crate::state::AppState;

#[tauri::command]
pub async fn list_hosts(state: State<'_, AppState>) -> Result<Vec<HostProfile>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_hosts()).await
}

#[tauri::command]
pub async fn get_host(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<Option<HostProfile>, String> {
    let store = state.store.clone();
    super::blocking(move || store.get_host(&host_id)).await
}

#[tauri::command]
pub async fn save_host(
    state: State<'_, AppState>,
    profile: HostProfile,
) -> Result<HostProfile, String> {
    let store = state.store.clone();
    if profile.protocol == "boundary" {
        return Err("Boundary invitations are temporary. Start a new support connection instead of saving a host".into());
    }
    let returned = profile.clone();
    super::blocking(move || store.save_host(&profile)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_host(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_host(&host_id)).await
}

/// Bump `last_connected`/`connect_count` after a successful connect.
#[tauri::command]
pub async fn touch_connected(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.touch_connected(&host_id)).await
}

#[tauri::command]
pub async fn list_groups(state: State<'_, AppState>) -> Result<Vec<Group>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_groups()).await
}

#[tauri::command]
pub async fn save_group(state: State<'_, AppState>, group: Group) -> Result<Group, String> {
    let store = state.store.clone();
    let returned = group.clone();
    super::blocking(move || store.save_group(&group)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_group(state: State<'_, AppState>, group_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_group(&group_id)).await
}

#[tauri::command]
pub async fn list_tags(state: State<'_, AppState>) -> Result<Vec<Tag>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_tags()).await
}

#[tauri::command]
pub async fn save_tag(state: State<'_, AppState>, tag: Tag) -> Result<Tag, String> {
    let store = state.store.clone();
    let returned = tag.clone();
    super::blocking(move || store.save_tag(&tag)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_tag(state: State<'_, AppState>, tag_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_tag(&tag_id)).await
}

/// Replace the full tag set of a host.
#[tauri::command]
pub async fn set_host_tags(
    state: State<'_, AppState>,
    host_id: String,
    tag_ids: Vec<String>,
) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.set_host_tags(&host_id, &tag_ids)).await
}

/// Move a multi-selection of hosts into a group in one atomic call, or out of
/// every group when `group_id` is `None`. See `Store::set_hosts_group`.
#[tauri::command]
pub async fn set_hosts_group(
    state: State<'_, AppState>,
    host_ids: Vec<String>,
    group_id: Option<String>,
) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.set_hosts_group(&host_ids, group_id.as_deref())).await
}

/// Add one tag to a multi-selection of hosts without disturbing their other
/// tags. See `Store::add_tag_to_hosts`.
#[tauri::command]
pub async fn add_tag_to_hosts(
    state: State<'_, AppState>,
    host_ids: Vec<String>,
    tag_id: String,
) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.add_tag_to_hosts(&host_ids, &tag_id)).await
}

/// Remove one tag from a multi-selection of hosts without disturbing their
/// other tags. See `Store::remove_tag_from_hosts`.
#[tauri::command]
pub async fn remove_tag_from_hosts(
    state: State<'_, AppState>,
    host_ids: Vec<String>,
    tag_id: String,
) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.remove_tag_from_hosts(&host_ids, &tag_id)).await
}

/// Connection history, newest first. `host_id = None` means all hosts.
#[tauri::command]
pub async fn list_history(
    state: State<'_, AppState>,
    host_id: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<HistoryEntry>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_history(host_id.as_deref(), limit.unwrap_or(100))).await
}

/// Thumbnail PNG for a host tile.
///
/// Returns the raw PNG bytes via `tauri::ipc::Response`, the binary
/// fast path, NOT base64 JSON. The webview receives an `ArrayBuffer`:
/// `new Blob([await invoke("get_thumbnail", { hostId })])`. An empty body
/// means "no thumbnail yet".
#[tauri::command]
pub async fn get_thumbnail(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<tauri::ipc::Response, String> {
    let store = state.store.clone();
    let bytes: Option<Vec<u8>> = super::blocking(move || store.load_thumbnail(&host_id)).await?;
    Ok(tauri::ipc::Response::new(bytes.unwrap_or_default()))
}

/// The bundled icon palette, ready to draw in the picker.
///
/// One call returns the whole set as data URLs rather than a file name per
/// entry, because these images are compiled into the binary and have no path
/// the webview could fetch. They total a few tens of kilobytes and the picker
/// needs all of them at once, so a round trip each would buy nothing.
#[tauri::command]
pub fn builtin_host_icons() -> Vec<BuiltinHostIcon> {
    use base64::Engine as _;
    crate::hosticon::BUILTINS
        .iter()
        .map(|b| BuiltinHostIcon {
            key: b.key,
            label: b.label,
            data_url: format!(
                "data:image/png;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(b.png)
            ),
        })
        .collect()
}

/// One entry of [`builtin_host_icons`].
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltinHostIcon {
    /// Stored in `hosts.icon` as `builtin:<key>`.
    pub key: &'static str,
    pub label: &'static str,
    /// `data:image/png;base64,...`, safe in an `img` src under the app CSP
    /// (`img-src` already allows `data:` for exactly this kind of thing).
    pub data_url: String,
}

/// Decode the picture at `path` and hand back what we *would* store for it.
///
/// Writes nothing and needs no host id, which is what lets the editor preview
/// a choice for a host that has not been saved yet. It also means picking a
/// picture and then cancelling the dialog changes nothing on disk: the write
/// happens on save, through [`import_host_icon`].
///
/// The returned bytes are the normalised ones, so an oversized image previews
/// visibly resized rather than at its original size.
#[tauri::command]
pub async fn preview_host_icon(path: String) -> Result<tauri::ipc::Response, String> {
    let png =
        super::blocking(move || vnc_store::normalise_icon(std::path::Path::new(&path))).await?;
    Ok(tauri::ipc::Response::new(png))
}

/// Normalise the picture at `path` and store it as this host's icon.
///
/// Called from the profile save, not from the picker, so the file and the
/// `hosts.icon` value that points at it are written by the same gesture.
#[tauri::command]
pub async fn import_host_icon(
    state: State<'_, AppState>,
    host_id: String,
    path: String,
) -> Result<tauri::ipc::Response, String> {
    let store = state.store.clone();
    let png =
        super::blocking(move || store.import_host_icon(&host_id, std::path::Path::new(&path)))
            .await?;
    Ok(tauri::ipc::Response::new(png))
}

/// This host's own icon file, or no bytes at all.
///
/// Only the `file` form is served here; a `builtin:` icon is already in the
/// webview's hands from [`builtin_host_icons`], so fetching it back over IPC
/// per tile would be pure overhead. Empty means "draw no icon", which is the
/// answer for a host that never had one and for one whose file has gone
/// missing alike: neither is an error worth interrupting the library for.
#[tauri::command]
pub async fn get_host_icon(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<tauri::ipc::Response, String> {
    let store = state.store.clone();
    let bytes: Option<Vec<u8>> = super::blocking(move || store.load_host_icon(&host_id)).await?;
    Ok(tauri::ipc::Response::new(bytes.unwrap_or_default()))
}

/// Forget a host's imported icon file.
///
/// Called when the user switches that host to a bundled icon or to none, so
/// the picture they replaced does not sit in the data directory forever.
/// Clearing `hosts.icon` itself is the profile save's job.
#[tauri::command]
pub async fn clear_host_icon(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_host_icon(&host_id)).await
}

/// Read a global app setting from the store's KV table.
///
/// Used for preferences the Rust side must consult at connect time (so they
/// cannot live in the webview's localStorage), e.g. `lossless_refresh`.
#[tauri::command]
pub async fn get_app_setting(
    state: State<'_, AppState>,
    key: String,
) -> Result<Option<String>, String> {
    state.store.get_setting(&key).map_err(|e| e.to_string())
}

/// Write a global app setting.
///
/// One setting has an effect beyond being stored: `agent_plane_enabled` binds
/// or unlinks the `dvvp.v1` socket. It is applied here rather than at the next
/// launch so that switching the plane on is a switch and not a restart, and so
/// that switching it off means the socket is gone at that moment rather than
/// at the next one. `app` is injected by Tauri and is not part of the invoke
/// surface, so the webview's call is unchanged.
#[tauri::command]
pub async fn set_app_setting(
    app: AppHandle,
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> Result<(), String> {
    state
        .store
        .set_setting(&key, &value)
        .map_err(|e| e.to_string())?;
    if key == crate::agent::AGENT_PLANE_ENABLED_KEY {
        crate::commands::agent::apply(&app, crate::agent::plane_enabled(Some(&value)));
    }
    Ok(())
}

/**
 * Per-host icons: resolving what `HostProfile.icon` names into something an
 * `<img>` can show.
 *
 * The stored value is a short tag, never image data (see
 * `crates/vnc-store/src/icons.rs`):
 *
 * - `null` — no icon of its own, the window wears the application icon.
 * - `builtin:<key>` — one of the pictures compiled into the shell, fetched
 *   once for the whole app by `builtinHostIcons()`.
 * - `file` — the picture the user chose, kept as
 *   `<data_dir>/host-icons/<host id>.png` and read back per host.
 *
 * Where this is *visible* is not the same everywhere. The icon's main job is
 * the dedicated session window, and Wayland and macOS both ignore per-window
 * icons (`src-tauri/src/hosticon.rs` says which and why), so the library tile
 * is the one place every platform shows the user what they picked.
 */
import { inTauri, safeInvoke } from "./tauri";

/** Prefix of a stored value naming a bundled icon. */
export const BUILTIN_ICON_PREFIX = "builtin:";
/** The stored value for a picture the user supplied. */
export const FILE_ICON_TAG = "file";

/** One entry of the bundled palette. Mirrors Rust `BuiltinHostIcon`. */
export interface BuiltinHostIcon {
  /** Stored as `builtin:<key>`. */
  key: string;
  label: string;
  /** `data:image/png;base64,...` */
  dataUrl: string;
}

/**
 * The bundled palette, fetched once per app run.
 *
 * Cached as the *promise*, not the result, so the several components that
 * want it during one render pass share a single round trip rather than racing
 * to start their own. The images are compiled into the binary and cannot
 * change while the app runs, so there is nothing to invalidate.
 *
 * Empty in the plain-browser dev server, where there is no shell to ask. The
 * picker degrades to its file button there, the same way the rest of the host
 * editor degrades without a keychain or a native file dialog.
 */
let builtinsPromise: Promise<BuiltinHostIcon[]> | null = null;

export function builtinHostIcons(): Promise<BuiltinHostIcon[]> {
  builtinsPromise ??= safeInvoke<BuiltinHostIcon[]>("builtin_host_icons", undefined, []).then(
    (list) => (Array.isArray(list) ? list : []),
  );
  return builtinsPromise;
}

/**
 * Blob URLs for the `file` form, keyed by host id.
 *
 * Module scope rather than React state on purpose: the same host is drawn by
 * a tile, a tab and the host editor at once, and one blob shared between them
 * is one read instead of three. `bumpHostIcon` is what makes a re-import
 * visible; nothing else invalidates, because nothing else can change the file.
 */
const fileIcons = new Map<string, string | null>();
const fileIconsPending = new Map<string, Promise<string | null>>();

/**
 * Anyone currently drawing a file icon.
 *
 * The cache is module scope, so clearing it is invisible to React on its own:
 * a tile whose host still says `"file"` would keep showing the picture it had
 * until something unrelated re-rendered it. These listeners are what turn a
 * re-import into a repaint.
 */
const listeners = new Set<() => void>();

/** Subscribe to file-icon invalidations. Returns the unsubscribe. */
export function subscribeHostIcons(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Drop a cached file icon, so the next read picks up a freshly imported one. */
export function bumpHostIcon(hostId: string): void {
  const old = fileIcons.get(hostId);
  if (old) URL.revokeObjectURL(old);
  fileIcons.delete(hostId);
  fileIconsPending.delete(hostId);
  for (const fn of listeners) fn();
}

/** Read this host's imported icon, `null` when it has none or it will not load. */
export function hostIconFileUrl(hostId: string): Promise<string | null> {
  if (!hostId || !inTauri()) return Promise.resolve(null);
  const cached = fileIcons.get(hostId);
  if (cached !== undefined) return Promise.resolve(cached);
  const pending = fileIconsPending.get(hostId);
  if (pending) return pending;

  const read = safeInvoke<ArrayBuffer | number[] | null>("get_host_icon", { hostId }, null)
    .then((data) => {
      let url: string | null = null;
      if (data) {
        const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data);
        // Empty is the shell's answer for "no icon", not a failure: a host
        // that never had one and a host whose file has gone both land here.
        if (bytes.byteLength > 0) {
          url = URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer], { type: "image/png" }));
        }
      }
      fileIcons.set(hostId, url);
      fileIconsPending.delete(hostId);
      return url;
    })
    .catch(() => {
      fileIconsPending.delete(hostId);
      return null;
    });
  fileIconsPending.set(hostId, read);
  return read;
}

/** Turn an IPC byte reply into a blob URL, or `null` if it carried nothing. */
function blobUrl(data: ArrayBuffer | number[] | null): string | null {
  if (!data) return null;
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data);
  if (bytes.byteLength === 0) return null;
  return URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer], { type: "image/png" }));
}

/**
 * What we *would* store for this picture, without storing it.
 *
 * The bytes come back normalised, so an oversized image previews visibly
 * resized rather than at its original size, and the resize is not a surprise
 * that only appears after saving.
 *
 * Nothing is written and no host id is needed, which is what makes the picker
 * safe to cancel: a host that has never been saved can still preview a
 * choice, and a host that has does not lose the icon it already had.
 */
export async function previewHostIcon(path: string): Promise<string | null> {
  return blobUrl(await safeInvoke<ArrayBuffer | number[] | null>("preview_host_icon", { path }, null));
}

/**
 * Write a picture as this host's icon. Called from the profile save.
 *
 * Pairs with the save that sets `HostProfile.icon` to `"file"`, so the file
 * and the value pointing at it are written by one gesture; see
 * `previewHostIcon` for why the picker does not do this itself.
 */
export async function importHostIcon(hostId: string, path: string): Promise<string | null> {
  const url = blobUrl(
    await safeInvoke<ArrayBuffer | number[] | null>("import_host_icon", { hostId, path }, null),
  );
  bumpHostIcon(hostId);
  if (url) fileIcons.set(hostId, url);
  return url;
}

/** Delete this host's imported icon file. Clearing `icon` is the save's job. */
export async function clearHostIcon(hostId: string): Promise<void> {
  if (!hostId) return;
  await safeInvoke<null>("clear_host_icon", { hostId }, null);
  bumpHostIcon(hostId);
}

/**
 * Resolve a stored spec to a URL, given an already-loaded palette.
 *
 * Synchronous and total: an unknown spec, a key from a build with a larger
 * palette, or a palette that has not arrived yet all give `null`, which draws
 * as no icon rather than as a broken image.
 */
export function resolveHostIcon(
  spec: string | null | undefined,
  hostId: string,
  builtins: BuiltinHostIcon[],
  fileUrl: string | null,
): string | null {
  const tag = spec?.trim();
  if (!tag) return null;
  if (tag === FILE_ICON_TAG) return hostId ? fileUrl : null;
  if (tag.startsWith(BUILTIN_ICON_PREFIX)) {
    const key = tag.slice(BUILTIN_ICON_PREFIX.length);
    return builtins.find((b) => b.key === key)?.dataUrl ?? null;
  }
  return null;
}

/** Resolve a host's icon spec to a URL an `<img>` can show. See `lib/hostIcon.ts`. */
import { useEffect, useState } from "react";

import {
  builtinHostIcons,
  FILE_ICON_TAG,
  hostIconFileUrl,
  resolveHostIcon,
  subscribeHostIcons,
  type BuiltinHostIcon,
} from "../lib/hostIcon";

/**
 * The bundled palette, as React state.
 *
 * Every caller shares one fetch (`builtinHostIcons` caches the promise); this
 * only exists so the answer arriving causes a render.
 */
export function useBuiltinHostIcons(): BuiltinHostIcon[] {
  const [icons, setIcons] = useState<BuiltinHostIcon[]>([]);
  useEffect(() => {
    let cancelled = false;
    void builtinHostIcons().then((list) => {
      if (!cancelled) setIcons(list);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return icons;
}

/**
 * The icon URL for one host, or `null` when it has none.
 *
 * `null` is the normal answer for most hosts and is never an error: it means
 * "draw nothing here", which is what a host without an icon should look like.
 */
export function useHostIcon(hostId: string, spec: string | null | undefined): string | null {
  const builtins = useBuiltinHostIcons();
  const [fileUrl, setFileUrl] = useState<string | null>(null);
  const wantsFile = spec?.trim() === FILE_ICON_TAG && !!hostId;

  useEffect(() => {
    if (!wantsFile) {
      setFileUrl(null);
      return;
    }
    let cancelled = false;
    const read = (): void => {
      void hostIconFileUrl(hostId).then((url) => {
        if (!cancelled) setFileUrl(url);
      });
    };
    read();
    // A re-import replaces the file under us; re-read rather than keep showing
    // the picture that was replaced.
    const unsubscribe = subscribeHostIcons(read);
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [hostId, wantsFile]);

  return resolveHostIcon(spec, hostId, builtins, fileUrl);
}

import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";

const VISIBLE_INTERVAL_MS = 2500;
const HIDDEN_INTERVAL_MS = 30_000;

// Protection lives in the daemon. Hidden windows only need a slow status
// heartbeat; revealing the window requests a fresh snapshot immediately.
export function useStatusPolling(
  enabled: boolean,
  refresh: () => Promise<unknown>,
) {
  useEffect(() => {
    if (!enabled) return;
    let disposed = false;
    let visible = !document.hidden;
    let visibilityRevision = 0;
    let timer: number | undefined;
    let running = false;
    let refreshOnCompletion = false;
    const unlisteners: Array<() => void> = [];

    const schedule = (delay: number) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void poll(), delay);
    };

    const poll = async () => {
      window.clearTimeout(timer);
      if (disposed) return;
      if (running) {
        refreshOnCompletion = true;
        return;
      }
      running = true;
      try {
        await refresh();
      } catch {
        // The status command owns error presentation. Keep the timer bounded.
      } finally {
        running = false;
        if (!disposed) {
          const delay = refreshOnCompletion && visible
            ? 0
            : visible ? VISIBLE_INTERVAL_MS : HIDDEN_INTERVAL_MS;
          refreshOnCompletion = false;
          schedule(delay);
        }
      }
    };

    const setVisible = (next: boolean) => {
      if (disposed) return;
      visibilityRevision++;
      if (next === visible) return;
      visible = next;
      if (visible) void poll();
      else schedule(HIDDEN_INTERVAL_MS);
    };

    const track = (registration: Promise<() => void>) => {
      void registration.then((unlisten) => {
        if (disposed) unlisten();
        else unlisteners.push(unlisten);
      }).catch(() => { /* browser preview has no native window */ });
    };

    const win = getCurrentWindow();
    const readVisibility = () => {
      const revision = visibilityRevision;
      void win.isVisible().then((nativeVisible) => {
        if (revision === visibilityRevision) {
          setVisible(nativeVisible && !document.hidden);
        }
      }).catch(() => {
        if (revision === visibilityRevision) setVisible(!document.hidden);
      });
    };
    const onVisibility = () => {
      visibilityRevision++;
      if (document.hidden) setVisible(false);
      else readVisibility();
    };

    track(listen("window-dismissing", () => setVisible(false)));
    track(listen("window-revealing", () => setVisible(true)));
    track(win.onFocusChanged(({ payload: focused }) => {
      if (focused) setVisible(true);
      else readVisibility();
    }));
    document.addEventListener("visibilitychange", onVisibility);
    schedule(VISIBLE_INTERVAL_MS);
    readVisibility();

    return () => {
      disposed = true;
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      for (const unlisten of unlisteners) unlisten();
    };
  }, [enabled, refresh]);
}

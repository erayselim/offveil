import { invoke } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";

/** No newer artifact on the GitHub Releases endpoint (including 404). */
export function isNoNewerRelease(err: unknown): boolean {
  const s = String(err).toLowerCase();
  return (
    s.includes("404") ||
    s.includes("not found") ||
    s.includes("could not fetch") ||
    s.includes("error sending request") ||
    s.includes("failed to fetch") ||
    s.includes("no release")
  );
}

export async function checkAppUpdate(): Promise<Update | null> {
  return check({ timeout: 20_000 });
}

export async function downloadAppUpdate(
  update: Update,
  onProgress: (percent: number) => void,
): Promise<void> {
  let downloaded = 0;
  let contentLength = 0;
  await update.download((event) => {
    switch (event.event) {
      case "Started":
        contentLength = event.data.contentLength ?? 0;
        onProgress(0);
        break;
      case "Progress":
        downloaded += event.data.chunkLength;
        if (contentLength > 0) {
          onProgress(
            Math.min(100, Math.round((downloaded / contentLength) * 100)),
          );
        }
        break;
      case "Finished":
        onProgress(100);
        break;
    }
  });
}

export async function installDownloadedUpdate(update: Update): Promise<void> {
  await invoke("prepare_update");
  await update.install();
}

export function discardUpdate(update: Update | null) {
  if (!update) return;
  void update.close().catch(() => {
    /* already consumed or dropped */
  });
}

export type UpdateUiPhase =
  | "idle"
  | "checking"
  | "upToDate"
  | "failed"
  | "available"
  | "downloading"
  | "ready"
  | "installing";

export function isUpdateActionPhase(phase: UpdateUiPhase): boolean {
  return (
    phase === "available" ||
    phase === "downloading" ||
    phase === "ready" ||
    phase === "installing"
  );
}

export function isUpdateBusyPhase(phase: UpdateUiPhase): boolean {
  return phase === "checking" || phase === "installing";
}

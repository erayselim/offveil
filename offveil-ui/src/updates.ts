import { invoke } from "@tauri-apps/api/core";
import { Update } from "@tauri-apps/plugin-updater";

/** An unpublished feed is allowed; network failures must be shown as failures. */
export function isNoNewerRelease(err: unknown): boolean {
  const s = String(err).toLowerCase();
  if (s.includes("mac update discovery:") || s.includes("mac release json:")) {
    return false;
  }
  return s.includes("404") || s.includes("no release");
}

export async function checkAppUpdate(): Promise<Update | null> {
  const metadata = await invoke<ConstructorParameters<typeof Update>[0] | null>(
    "check_app_update",
  );
  return metadata ? new Update(metadata) : null;
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
  try {
    await invoke("prepare_update");
    await update.install();
    await invoke("finish_update");
  } catch (error) {
    await invoke("cancel_update").catch(() => {});
    throw error;
  }
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

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  formatUpdateHint,
  formatUpdatePct,
  type Locale,
  type Messages,
} from "./i18n";
import type { UpdateUiPhase } from "./updates";

export function UpdateFlowDialog({
  open,
  phase,
  locale,
  version,
  notes,
  downloadPct,
  error,
  m,
  onOpenChange,
  onPrimary,
}: {
  open: boolean;
  phase: UpdateUiPhase;
  locale: Locale;
  version: string;
  notes: string | null;
  downloadPct: number;
  error: string | null;
  m: Messages;
  onOpenChange: (open: boolean) => void;
  onPrimary: () => void;
}) {
  const installing = phase === "installing";
  const downloading = phase === "downloading";
  const progress = downloading || installing;
  const ready = phase === "ready";

  const title = installing
    ? m.updating
    : downloading
      ? m.updateDownloading
      : ready
        ? m.updateInstallCta
        : m.updateAvailableTitle;

  const hint = installing
    ? m.updating
    : downloading
      ? formatUpdatePct(locale, downloadPct)
      : ready
        ? m.updateRestartHint
        : formatUpdateHint(locale, version);

  const primaryLabel = ready ? m.updateInstall : m.updateDownloadAndInstall;
  const showNotes = !progress && !ready && Boolean(notes);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && installing) return;
        onOpenChange(next);
      }}
    >
      <DialogContent
        showCloseButton={false}
        overlayClassName="bg-foreground/25"
        className="max-w-72 gap-4 overflow-hidden rounded-2xl p-5"
        onPointerDownOutside={(event) => {
          if (installing) event.preventDefault();
        }}
        onEscapeKeyDown={(event) => {
          if (installing) event.preventDefault();
        }}
      >
        <DialogHeader className="gap-1">
          <DialogTitle className="app-page-title">{title}</DialogTitle>
          <DialogDescription className="pref-hint">{hint}</DialogDescription>
        </DialogHeader>
        {showNotes && <p className="update-notes">{notes}</p>}
        {error && !progress && <p className="update-dialog-error">{error}</p>}
        {progress ? (
          <>
            <div className="update-progress">
              <div className="update-progress-track">
                <div
                  className="update-progress-fill"
                  style={{
                    width: `${installing ? 100 : downloadPct}%`,
                  }}
                />
              </div>
            </div>
            {!installing && (
              <div className="confirm-actions confirm-actions-single">
                <DialogClose asChild>
                  <button type="button">{m.updateLater}</button>
                </DialogClose>
              </div>
            )}
          </>
        ) : (
          <div className="confirm-actions">
            <DialogClose asChild>
              <button type="button">{m.updateLater}</button>
            </DialogClose>
            <button
              type="button"
              className="is-confirm"
              onClick={() => onPrimary()}
            >
              {primaryLabel}
            </button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

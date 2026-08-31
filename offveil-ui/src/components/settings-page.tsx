import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { CircleAlertIcon } from "lucide-react";

import { Lockup } from "@/brand";
import { AppPage, ChoiceSeg } from "@/components/app-page";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import type { Locale, Messages } from "@/i18n";
import { bundledWhatsNew } from "@/whats-new";

const LICENSE_URL = "https://github.com/erayselim/offveil/blob/main/LICENSE";
const AUTHOR_URL = "https://github.com/erayselim";
const AUTHOR_NAME = "erayselim";

export function SettingsPage({
  m,
  locale,
  onLocale,
  onBack,
  autostartOn,
  onAutostartToggle,
  autoconnectOn,
  onAutoconnectToggle,
  autoCheckOn,
  onAutoCheckToggle,
  autoDownloadOn,
  onAutoDownloadToggle,
  busy,
  protection,
  onConnectionTest,
  onDiagnostics,
  testNote,
  diagNote,
  error,
  diagPath,
  onOpenDiagFolder,
  onShareIssue,
}: {
  m: Messages;
  locale: Locale;
  onLocale: (next: Locale) => void;
  onBack: () => void;
  autostartOn: boolean;
  onAutostartToggle: () => void;
  autoconnectOn: boolean;
  onAutoconnectToggle: () => void;
  autoCheckOn: boolean;
  onAutoCheckToggle: () => void;
  autoDownloadOn: boolean;
  onAutoDownloadToggle: () => void;
  busy: boolean;
  protection: boolean;
  onConnectionTest: () => void;
  onDiagnostics: () => void;
  testNote: string | null;
  diagNote: string | null;
  error: string | null;
  diagPath: string | null;
  onOpenDiagFolder: () => void;
  onShareIssue: () => void;
}) {
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [whatsNewOpen, setWhatsNewOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void getVersion()
      .then((version) => {
        if (!cancelled) setAppVersion(version);
      })
      .catch(() => {
        if (!cancelled) setAppVersion(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const whatsNewNotes = bundledWhatsNew(appVersion, locale);

  return (
    <AppPage title={m.settings} backLabel={m.back} onBack={onBack}>
      <div className="field-block">
        <div className="pref-label" id="language-label">
          {m.language}
        </div>
        <ChoiceSeg
          labelledBy="language-label"
          value={locale}
          onChange={(value) => {
            if (value === "tr" || value === "en") onLocale(value);
          }}
          options={[
            { value: "tr", label: m.langTr },
            { value: "en", label: m.langEn },
          ]}
        />
      </div>

      <div className="pref-row">
        <label htmlFor="autostart" className="pref-copy">
          <span className="pref-label">{m.autostart}</span>
          <span className="pref-hint">{m.autostartHint}</span>
        </label>
        <Switch
          id="autostart"
          checked={autostartOn}
          onCheckedChange={() => onAutostartToggle()}
        />
      </div>

      <div className="pref-row">
        <label htmlFor="autoconnect" className="pref-copy">
          <span className="pref-label">{m.autoconnect}</span>
          <span className="pref-hint">{m.autoconnectHint}</span>
        </label>
        <Switch
          id="autoconnect"
          checked={autoconnectOn}
          onCheckedChange={() => onAutoconnectToggle()}
        />
      </div>

      <div className="pref-row">
        <label htmlFor="auto-check" className="pref-copy">
          <span className="pref-label">{m.autoCheckUpdates}</span>
          <span className="pref-hint">{m.autoCheckUpdatesHint}</span>
        </label>
        <Switch
          id="auto-check"
          checked={autoCheckOn}
          onCheckedChange={() => onAutoCheckToggle()}
        />
      </div>

      <div className="pref-row">
        <label htmlFor="auto-download" className="pref-copy">
          <span className="pref-label">{m.autoDownloadUpdates}</span>
          <span className="pref-hint">{m.autoDownloadUpdatesHint}</span>
        </label>
        <Switch
          id="auto-download"
          checked={autoDownloadOn}
          onCheckedChange={() => onAutoDownloadToggle()}
        />
      </div>

      <button
        type="button"
        className="pref-row pref-row-btn"
        onClick={() => setWhatsNewOpen(true)}
      >
        <span className="pref-copy">
          <span className="pref-label">{m.whatsNew}</span>
          <span className="pref-hint">
            {appVersion ? `v${appVersion}` : m.whatsNewEmpty}
          </span>
        </span>
      </button>

      <div className="tool-stack">
        <div className="tool-item">
          <Button
            type="button"
            variant="secondary"
            size="lg"
            className="w-full"
            disabled={busy || !protection}
            onClick={() => onConnectionTest()}
          >
            {m.connectionTest}
          </Button>
          {!protection && <p className="pref-hint">{m.connectionTestOff}</p>}
          {testNote && <p className="tool-status">{testNote}</p>}
        </div>
        <div className="tool-item">
          <Button
            type="button"
            variant="secondary"
            size="lg"
            className="w-full"
            disabled={busy}
            onClick={() => onDiagnostics()}
          >
            {m.diagnostics}
          </Button>
          {diagNote && <p className="tool-status">{diagNote}</p>}
          {diagPath && (
            <div className="tool-result-actions">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onOpenDiagFolder()}
              >
                {m.openFolder}
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onShareIssue()}
              >
                {m.shareIssue}
              </Button>
            </div>
          )}
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>{error}</AlertTitle>
        </Alert>
      )}

      <div className="credits">
        <div className="credits-brand">
          <Lockup className="credits-logo" />
          {appVersion && (
            <span className="credits-version">v{appVersion}</span>
          )}
        </div>
        <p className="credits-desc">{m.creditsDesc}</p>
        <div className="credits-meta">
          <button
            type="button"
            className="credits-link"
            onClick={() => void openUrl(LICENSE_URL)}
          >
            {m.creditsLicense}
          </button>
          <span className="credits-sep" aria-hidden="true">
            •
          </span>
          <button
            type="button"
            className="credits-link"
            onClick={() => void openUrl(AUTHOR_URL)}
          >
            {m.creditsDevelopedBy}{" "}
            <span className="credits-author">{AUTHOR_NAME}</span>
          </button>
        </div>
      </div>

      <Dialog open={whatsNewOpen} onOpenChange={setWhatsNewOpen}>
        <DialogContent
          showCloseButton={false}
          overlayClassName="bg-foreground/25"
          className="max-w-72 gap-4 overflow-hidden rounded-2xl p-5"
        >
          <DialogHeader className="gap-1">
            <DialogTitle className="app-page-title">{m.whatsNew}</DialogTitle>
            <DialogDescription className="pref-hint">
              {appVersion ? `v${appVersion}` : ""}
            </DialogDescription>
          </DialogHeader>
          <p className="update-notes">
            {whatsNewNotes ?? m.whatsNewEmpty}
          </p>
          <div className="confirm-actions confirm-actions-single">
            <DialogClose asChild>
              <button type="button" className="is-confirm">
                {m.close}
              </button>
            </DialogClose>
          </div>
        </DialogContent>
      </Dialog>
    </AppPage>
  );
}

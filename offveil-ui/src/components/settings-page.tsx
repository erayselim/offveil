import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { CircleAlertIcon } from "lucide-react";

import { Lockup } from "@/brand";
import { AppPage, ChoiceSeg } from "@/components/app-page";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import type { Locale, Messages } from "@/i18n";

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
  busy,
  protection,
  onConnectionTest,
  onDiagnostics,
  note,
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
  busy: boolean;
  protection: boolean;
  onConnectionTest: () => void;
  onDiagnostics: () => void;
  note: string | null;
  error: string | null;
  diagPath: string | null;
  onOpenDiagFolder: () => void;
  onShareIssue: () => void;
}) {
  const [appVersion, setAppVersion] = useState<string | null>(null);

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
        </div>
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
      </div>

      {note && (
        <div className="tool-result">
          <p>{note}</p>
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
      )}

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
    </AppPage>
  );
}

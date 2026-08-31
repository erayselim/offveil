import { useCallback, useEffect, useRef, useState } from "react";
import type { Update } from "@tauri-apps/plugin-updater";
import type { Locale } from "./i18n";
import {
  detectUpdatePrefs,
  persistUpdatePrefs,
  type UpdatePrefs,
} from "./update-prefs";
import {
  checkAppUpdate,
  discardUpdate,
  downloadAppUpdate,
  installDownloadedUpdate,
  isNoNewerRelease,
  type UpdateUiPhase,
} from "./updates";
import { notesFromUpdateBody } from "./whats-new";

const FLASH_MS = 5000;
const AUTO_CHECK_DELAY_MS = 600;

export function useAppUpdates({
  busy,
  locale,
  protection,
}: {
  busy: boolean;
  locale: Locale;
  protection: boolean;
}) {
  const [prefs, setPrefsState] = useState<UpdatePrefs>(() =>
    detectUpdatePrefs(),
  );
  const [phase, setPhase] = useState<UpdateUiPhase>("idle");
  const [pending, setPending] = useState<Update | null>(null);
  const [downloadPct, setDownloadPct] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const pendingRef = useRef<Update | null>(null);
  const phaseRef = useRef<UpdateUiPhase>("idle");
  const installAfterRef = useRef(false);
  const autoDownloadedVer = useRef<string | null>(null);
  const flashTimer = useRef<number | null>(null);
  const inFlight = useRef(false);
  const userWaitingRef = useRef(false);

  const setPhaseBoth = (next: UpdateUiPhase) => {
    phaseRef.current = next;
    setPhase(next);
  };

  const replacePending = useCallback((update: Update | null) => {
    if (pendingRef.current && pendingRef.current !== update) {
      discardUpdate(pendingRef.current);
    }
    pendingRef.current = update;
    setPending(update);
  }, []);

  const clearFlashTimer = () => {
    if (flashTimer.current) {
      window.clearTimeout(flashTimer.current);
      flashTimer.current = null;
    }
  };

  const flash = useCallback(
    (kind: "upToDate" | "failed") => {
      clearFlashTimer();
      replacePending(null);
      setPhaseBoth(kind);
      flashTimer.current = window.setTimeout(() => {
        if (phaseRef.current === kind) setPhaseBoth("idle");
        flashTimer.current = null;
      }, FLASH_MS);
    },
    [replacePending],
  );

  const runCheck = useCallback(
    async (silent: boolean) => {
      const current = phaseRef.current;
      if (
        current === "downloading" ||
        current === "installing" ||
        current === "available" ||
        current === "ready"
      ) {
        return;
      }
      if (inFlight.current) {
        if (!silent) {
          userWaitingRef.current = true;
          clearFlashTimer();
          setPhaseBoth("checking");
        }
        return;
      }

      inFlight.current = true;
      if (!silent) {
        userWaitingRef.current = true;
        clearFlashTimer();
        setPhaseBoth("checking");
      }
      setDialogError(null);
      try {
        const update = await checkAppUpdate();
        const showResult = userWaitingRef.current;
        userWaitingRef.current = false;
        if (!update) {
          replacePending(null);
          if (showResult) flash("upToDate");
          else setPhaseBoth("idle");
          return;
        }
        replacePending(update);
        setDownloadPct(0);
        autoDownloadedVer.current = null;
        setPhaseBoth("available");
      } catch (e) {
        const showResult = userWaitingRef.current;
        userWaitingRef.current = false;
        replacePending(null);
        if (isNoNewerRelease(e)) {
          if (showResult) flash("upToDate");
          else setPhaseBoth("idle");
        } else if (showResult) {
          flash("failed");
        } else {
          setPhaseBoth("idle");
        }
      } finally {
        inFlight.current = false;
      }
    },
    [flash, replacePending],
  );

  const installOnly = useCallback(async () => {
    const update = pendingRef.current;
    if (!update || phaseRef.current === "installing") return;
    setDialogOpen(true);
    setDialogError(null);
    setPhaseBoth("installing");
    try {
      await installDownloadedUpdate(update);
    } catch (e) {
      setDialogError(String(e));
      setPhaseBoth("ready");
    }
  }, []);

  const startDownload = useCallback(
    async (installAfter: boolean) => {
      const update = pendingRef.current;
      if (!update) return;
      const current = phaseRef.current;
      if (current === "installing") return;
      if (current === "downloading") {
        if (installAfter) installAfterRef.current = true;
        setDialogOpen(true);
        return;
      }
      if (current === "ready") {
        if (installAfter) await installOnly();
        return;
      }

      installAfterRef.current = installAfter;
      setDialogError(null);
      setDownloadPct(0);
      setPhaseBoth("downloading");
      if (installAfter) setDialogOpen(true);
      try {
        await downloadAppUpdate(update, setDownloadPct);
        setPhaseBoth("ready");
        if (installAfterRef.current) await installOnly();
      } catch (e) {
        setDialogError(String(e));
        setDownloadPct(0);
        setPhaseBoth("available");
      }
    },
    [installOnly],
  );

  const onButtonClick = useCallback(() => {
    const current = phaseRef.current;
    if (current === "checking" || current === "installing") return;
    if (
      current === "available" ||
      current === "downloading" ||
      current === "ready"
    ) {
      setDialogOpen(true);
      return;
    }
    void runCheck(false);
  }, [runCheck]);

  const onPrimary = useCallback(() => {
    if (phaseRef.current === "ready") {
      void installOnly();
      return;
    }
    void startDownload(true);
  }, [installOnly, startDownload]);

  const closeDialog = useCallback(() => {
    if (phaseRef.current === "installing") return;
    setDialogOpen(false);
  }, []);

  const setPrefs = useCallback((next: UpdatePrefs) => {
    setPrefsState(next);
    persistUpdatePrefs(next);
  }, []);

  useEffect(() => {
    if (!prefs.autoCheck || busy) return;
    const timer = window.setTimeout(() => {
      void runCheck(true);
    }, AUTO_CHECK_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [prefs.autoCheck, busy, protection, runCheck]);

  useEffect(() => {
    if (!prefs.autoDownload) return;
    if (phase !== "available" || !pending) return;
    if (autoDownloadedVer.current === pending.version) return;
    autoDownloadedVer.current = pending.version;
    void startDownload(false);
  }, [prefs.autoDownload, phase, pending, startDownload]);

  useEffect(() => {
    return () => {
      clearFlashTimer();
      discardUpdate(pendingRef.current);
      pendingRef.current = null;
    };
  }, []);

  const notes = notesFromUpdateBody(pending?.body, locale);

  return {
    prefs,
    setPrefs,
    phase,
    pending,
    downloadPct,
    dialogOpen,
    dialogError,
    notes,
    onButtonClick,
    onPrimary,
    closeDialog,
  };
}

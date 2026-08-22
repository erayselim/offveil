import {
  forwardRef,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { Update } from "@tauri-apps/plugin-updater";
import { X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { AppearancePage } from "@/components/appearance-page";
import {
  ChevronDownIcon,
  type ChevronDownIconHandle,
} from "@/components/icons/chevron-down";
import {
  CloudDownloadIcon,
  type CloudDownloadIconHandle,
} from "@/components/icons/cloud-download";
import { DeleteIcon, type DeleteIconHandle } from "@/components/icons/delete";
import { PaletteIcon, type PaletteIconHandle } from "@/components/icons/palette";
import {
  SettingsIcon,
  type SettingsIconHandle,
} from "@/components/icons/settings";
import { SettingsPage } from "@/components/settings-page";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ProtectionPad } from "@/components/protection-pad";
import {
  dismissTooltips,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  applyAppIcon,
  detectAppIcon,
  persistAppIcon,
  type AppIconVariant,
} from "./app-icon";
import { Lockup } from "./brand";
import {
  detectLocale,
  formatDiagLine,
  formatTestLine,
  formatUpdateHint,
  formatUpdatePct,
  persistLocale,
  t,
  type Locale,
} from "./i18n";
import {
  checkAppUpdate,
  discardUpdate,
  installAppUpdate,
  isNoNewerRelease,
} from "./updates";
import {
  applyTheme,
  detectThemePref,
  persistThemePref,
  type ThemePref,
} from "./theme";

type BootstrapState = "ready" | "needs_install";

type BootstrapInfo = {
  state: BootstrapState;
  message: string;
  core_path: string | null;
  service_installed: boolean;
  pipe_ok: boolean;
};

function requiresAdminSetup(b: BootstrapInfo | null): boolean {
  return b?.state === "needs_install";
}

function isNeedsInstallError(e: unknown): boolean {
  return String(e).includes("needs_install:");
}

type TargetStatus = {
  id: string;
  label: string;
  outcome: string;
  path: string;
};

type Status = {
  state: string;
  protection: boolean;
  summary: string;
  outbound_hint?: string | null;
  targets: TargetStatus[];
  last_error?: string | null;
  tunnel?: { retry_hint?: boolean } | null;
};

type TestReport = {
  asn: string;
  isp_hint?: string;
  results: { target: string; class: string; path: string; ok: boolean }[];
};

type DiagnosticsBundle = {
  path: string;
  created_at: string;
  sha256: string;
  version: string;
  note?: string;
};

type UiPhase = "loading" | "setup" | "ready" | "busy" | "error";
type Panel = "home" | "settings" | "appearance";
type BusyKind = "connect" | "disconnect" | "refresh" | "reset" | null;

const PANEL_EASE = [0.22, 1, 0.36, 1] as const;

function isBroken(status: Status | null): boolean {
  if (!status?.protection) return false;
  if (status.state === "degraded") return true;
  if (status.last_error) return true;
  if (!status.tunnel || typeof status.tunnel !== "object") return false;
  return Boolean((status.tunnel as { retry_hint?: boolean }).retry_hint);
}

function copyFor(
  locale: Locale,
  phase: UiPhase,
  status: Status | null,
  busyKind: BusyKind,
): { title: string; hint: string } {
  const m = t(locale);
  if (phase === "loading") return { title: m.notProtected, hint: m.preparing };
  if (phase === "setup") {
    return {
      title: m.notProtected,
      hint: busyKind ? m.waitingAdmin : m.needsAdmin,
    };
  }
  if (busyKind === "refresh") {
    return { title: m.broken, hint: m.refreshing };
  }
  if (busyKind === "reset") {
    return { title: m.notProtected, hint: m.resetting };
  }
  if (busyKind === "disconnect") {
    return { title: m.protected, hint: m.disconnecting };
  }
  if (busyKind === "connect") {
    return { title: m.notProtected, hint: m.starting };
  }
  if (status?.state === "starting") {
    return { title: m.notProtected, hint: m.starting };
  }
  if (isBroken(status)) {
    return { title: m.broken, hint: m.brokenHint };
  }
  if (status?.protection) {
    return { title: m.protected, hint: m.protectedHint };
  }
  return { title: m.notProtected, hint: m.notProtectedHint };
}

const MIN_BUSY_MS = 800;

async function holdBusy(started: number) {
  const left = MIN_BUSY_MS - (Date.now() - started);
  if (left > 0) {
    await new Promise((resolve) => setTimeout(resolve, left));
  }
}

function HeaderIconButton({
  label,
  pressed,
  onClick,
  onMouseEnter,
  onMouseLeave,
  children,
}: {
  label: string;
  pressed?: boolean;
  onClick: () => void;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="header-icon-btn"
          aria-label={label}
          aria-pressed={pressed}
          onClick={() => {
            setOpen(false);
            onClick();
          }}
          onMouseEnter={onMouseEnter}
          onMouseLeave={onMouseLeave}
        >
          {children}
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}

const PanelFrame = forwardRef<HTMLDivElement, { children: ReactNode }>(
  function PanelFrame({ children }, ref) {
    const reduce = useReducedMotion();
    return (
      <motion.div
        ref={ref}
        className="flex min-h-0 flex-1 flex-col"
        initial={reduce ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={reduce ? undefined : { opacity: 0, y: -6 }}
        transition={{ duration: reduce ? 0 : 0.22, ease: PANEL_EASE }}
      >
        {children}
      </motion.div>
    );
  },
);

export default function App() {
  const [locale, setLocale] = useState<Locale>(() => detectLocale());
  const [themePref, setThemePref] = useState<ThemePref>(() => detectThemePref());
  const [appIcon, setAppIconPref] = useState<AppIconVariant>(() =>
    detectAppIcon(),
  );
  const [phase, setPhase] = useState<UiPhase>("loading");
  const [bootstrap, setBootstrap] = useState<BootstrapInfo | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyKind, setBusyKind] = useState<BusyKind>(null);
  const [testNote, setTestNote] = useState<string | null>(null);
  const [diagNote, setDiagNote] = useState<string | null>(null);
  const [autostartOn, setAutostartOn] = useState(true);
  const [autoconnectOn, setAutoconnectOn] = useState(true);
  const [diagPath, setDiagPath] = useState<string | null>(null);
  const [panel, setPanel] = useState<Panel>("home");
  const [quitOpen, setQuitOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [pendingUpdate, setPendingUpdate] = useState<Update | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updateHint, setUpdateHint] = useState<"upToDate" | "failed" | null>(
    null,
  );
  const [resetHint, setResetHint] = useState(false);
  const [installingUpdate, setInstallingUpdate] = useState(false);
  const [downloadPct, setDownloadPct] = useState(0);
  const pollRef = useRef<number | null>(null);
  const updateHintTimer = useRef<number | null>(null);
  const resetHintTimer = useRef<number | null>(null);
  const paletteIconRef = useRef<PaletteIconHandle>(null);
  const settingsIconRef = useRef<SettingsIconHandle>(null);
  const chevronIconRef = useRef<ChevronDownIconHandle>(null);
  const deleteIconRef = useRef<DeleteIconHandle>(null);
  const cloudIconRef = useRef<CloudDownloadIconHandle>(null);
  const m = t(locale);

  const fail = (e: unknown) => {
    setError(String(e));
  };

  const flashUpdateHint = (kind: "upToDate" | "failed") => {
    setUpdateHint(kind);
    if (updateHintTimer.current) window.clearTimeout(updateHintTimer.current);
    updateHintTimer.current = window.setTimeout(() => {
      setUpdateHint(null);
      updateHintTimer.current = null;
    }, 5000);
  };

  const flashResetHint = () => {
    setResetHint(true);
    if (resetHintTimer.current) window.clearTimeout(resetHintTimer.current);
    resetHintTimer.current = window.setTimeout(() => {
      setResetHint(false);
      resetHintTimer.current = null;
    }, 5000);
  };

  const setLang = (next: Locale) => {
    setLocale(next);
    persistLocale(next);
    document.documentElement.lang = next;
  };

  const setTheme = (next: ThemePref) => {
    setThemePref(next);
    persistThemePref(next);
    applyTheme(next);
  };

  const setAppIcon = (next: AppIconVariant) => {
    setAppIconPref(next);
    persistAppIcon(next);
    applyAppIcon(next);
  };

  useEffect(() => {
    applyTheme(themePref);
    document.documentElement.lang = locale;
    void invoke("set_tray_locale", { locale }).catch(() => {
      /* not running inside Tauri */
    });
  }, [themePref, locale]);

  useEffect(() => {
    applyAppIcon(appIcon);
  }, [appIcon]);

  useEffect(() => {
    if (themePref !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => applyTheme("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [themePref]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || panel === "home" || quitOpen) return;
      e.preventDefault();
      setPanel("home");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panel, quitOpen]);

  useEffect(() => {
    let cancelled = false;
    const unlisteners: Array<() => void> = [];
    const win = getCurrentWindow();
    const track = (pending: Promise<() => void>) => {
      void pending
        .then((fn) => {
          if (cancelled) {
            fn();
            return;
          }
          unlisteners.push(fn);
        })
        .catch(() => {
          /* not running inside Tauri */
        });
    };

    track(
      win.onFocusChanged(({ payload: focused }) => {
        if (!focused) dismissTooltips();
      }),
    );
    track(listen("window-dismissing", () => dismissTooltips()));
    track(listen("window-revealing", () => dismissTooltips()));

    return () => {
      cancelled = true;
      for (const unlisten of unlisteners) unlisten();
    };
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await invoke<Status>("get_status");
      setStatus(s);
      setError(null);
      setPhase("ready");
      return s;
    } catch (e) {
      const msg = String(e);
      if (msg.includes("not_connected")) {
        const b = await invoke<BootstrapInfo>("probe_bootstrap");
        setBootstrap(b);
        setStatus(null);
        setPhase(requiresAdminSetup(b) ? "setup" : "ready");
      } else {
        setError(msg);
        setPhase("error");
      }
      return null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const b = await invoke<BootstrapInfo>("probe_bootstrap");
        if (cancelled) return;
        setBootstrap(b);
        if (requiresAdminSetup(b)) {
          setPhase("setup");
        } else {
          await refreshStatus();
        }
      } catch (e) {
        if (!cancelled) {
          setError(String(e));
          setPhase("error");
        }
      }
      try {
        const on = await invoke<boolean>("autostart_is_enabled");
        if (!cancelled) setAutostartOn(on);
      } catch {
        /* keep default on */
      }
      try {
        const on = await invoke<boolean>("autoconnect_is_enabled");
        if (!cancelled) setAutoconnectOn(on);
      } catch {
        /* keep default on */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshStatus]);

  useEffect(() => {
    if (phase !== "ready" || busy) {
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    pollRef.current = window.setInterval(() => {
      void refreshStatus();
    }, 2500);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [phase, busy, refreshStatus]);

  useEffect(() => {
    return () => {
      if (updateHintTimer.current) window.clearTimeout(updateHintTimer.current);
      if (resetHintTimer.current) window.clearTimeout(resetHintTimer.current);
    };
  }, []);

  async function onInstall() {
    setBusy(true);
    setBusyKind("connect");
    setError(null);
    const started = Date.now();
    try {
      const b = await invoke<BootstrapInfo>("ensure_service");
      setBootstrap(b);
      if (b.pipe_ok) {
        await refreshStatus();
      } else {
        setPhase("setup");
        setError(m.setupDoneNoPipe);
      }
    } catch (e) {
      fail(e);
      setPhase("setup");
    } finally {
      await holdBusy(started);
      setBusy(false);
      setBusyKind(null);
    }
  }

  async function onToggle() {
    if (busy) return;
    const next = !(status?.protection ?? false);
    setBusy(true);
    setBusyKind(next ? "connect" : "disconnect");
    setError(null);
    const started = Date.now();
    try {
      const s = await invoke<Status>("set_protection", { enabled: next });
      setStatus(s);
      setPhase("ready");
    } catch (e) {
      const b = await invoke<BootstrapInfo>("probe_bootstrap");
      setBootstrap(b);
      if (requiresAdminSetup(b) || isNeedsInstallError(e)) {
        setPhase("setup");
      } else {
        fail(e);
      }
    } finally {
      await holdBusy(started);
      setBusy(false);
      setBusyKind(null);
    }
  }

  async function onRefresh() {
    setBusy(true);
    setBusyKind("refresh");
    setError(null);
    const started = Date.now();
    try {
      const s = await invoke<Status>("restart_protection");
      setStatus(s);
      setTestNote(null);
      setDiagNote(null);
      setPhase("ready");
    } catch (e) {
      if (isNeedsInstallError(e)) {
        setPhase("setup");
      } else {
        fail(e);
        try {
          await refreshStatus();
        } catch {
          /* keep prior status */
        }
      }
    } finally {
      await holdBusy(started);
      setBusy(false);
      setBusyKind(null);
    }
  }

  async function onPad() {
    if (busy) return;
    if (phase === "setup" || (phase === "error" && requiresAdminSetup(bootstrap))) {
      await onInstall();
      return;
    }
    if (isBroken(status)) {
      await onRefresh();
      return;
    }
    await onToggle();
  }

  async function onConnectionTest() {
    if (busy || !(status?.protection ?? false)) return;
    setBusy(true);
    setError(null);
    try {
      const rep = await invoke<TestReport>("run_connection_test");
      const line = formatTestLine(locale, rep);
      setTestNote(line);
      await refreshStatus();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  async function onDiagnostics() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const bundle = await invoke<DiagnosticsBundle>("export_diagnostics");
      setDiagPath(bundle.path);
      const line = formatDiagLine(locale, bundle.path);
      setDiagNote(line);
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  async function onAutostartToggle() {
    const next = !autostartOn;
    try {
      const on = await invoke<boolean>("autostart_set", { enabled: next });
      setAutostartOn(on);
    } catch (e) {
      fail(e);
    }
  }

  async function onAutoconnectToggle() {
    const next = !autoconnectOn;
    try {
      const on = await invoke<boolean>("autoconnect_set", { enabled: next });
      setAutoconnectOn(on);
    } catch (e) {
      fail(e);
    }
  }

  async function onOpenDiagFolder() {
    if (!diagPath) return;
    try {
      await invoke("open_diag_folder", { path: diagPath });
    } catch (e) {
      fail(e);
    }
  }

  async function onShareIssue() {
    try {
      await openUrl(
        "https://github.com/erayselim/offveil/issues/new?template=beta.yml",
      );
    } catch (e) {
      fail(e);
    }
  }

  function hideToTray() {
    dismissTooltips();
    void invoke("hide_to_tray");
  }

  function confirmQuit() {
    setQuitOpen(false);
    void invoke("tray_quit");
  }

  function closeUpdateDialog() {
    if (installingUpdate) return;
    discardUpdate(pendingUpdate);
    setPendingUpdate(null);
    setDownloadPct(0);
    setUpdateOpen(false);
  }

  async function onCheckUpdates() {
    if (busy || checkingUpdates || installingUpdate) return;
    setCheckingUpdates(true);
    setError(null);
    try {
      const update = await checkAppUpdate();
      if (!update) {
        flashUpdateHint("upToDate");
        return;
      }
      setPendingUpdate(update);
      setUpdateOpen(true);
    } catch (e) {
      if (isNoNewerRelease(e)) {
        flashUpdateHint("upToDate");
      } else {
        flashUpdateHint("failed");
      }
    } finally {
      setCheckingUpdates(false);
    }
  }

  async function onInstallUpdate() {
    if (!pendingUpdate || installingUpdate) return;
    const update = pendingUpdate;
    setInstallingUpdate(true);
    setDownloadPct(0);
    setError(null);
    try {
      await installAppUpdate(update, setDownloadPct);
    } catch (e) {
      fail(e);
      try {
        await refreshStatus();
      } catch {
        /* keep prior status */
      }
    } finally {
      discardUpdate(update);
      setPendingUpdate(null);
      setInstallingUpdate(false);
      setDownloadPct(0);
    }
  }

  async function onRevert() {
    if (busy) return;
    setResetOpen(false);
    setBusy(true);
    setBusyKind("reset");
    setError(null);
    const started = Date.now();
    try {
      const s = await invoke<Status>("revert_network");
      setStatus(s);
      setTestNote(null);
      setDiagNote(null);
      setPhase("ready");
      flashResetHint();
    } catch (e) {
      if (isNeedsInstallError(e)) {
        setPhase("setup");
      } else {
        fail(e);
        try {
          await refreshStatus();
        } catch {
          /* keep prior status */
        }
      }
    } finally {
      await holdBusy(started);
      setBusy(false);
      setBusyKind(null);
    }
  }

  const protection = status?.protection ?? false;
  const broken = isBroken(status);
  const on = protection && !broken;
  const { title, hint } = copyFor(locale, phase, status, busyKind);
  const padOn = on || broken;

  return (
    <TooltipProvider>
      <div className="relative flex h-full flex-col overflow-hidden bg-background">
        <div className="relative flex min-h-0 flex-1 flex-col pt-[22px] pb-6">
          <header className="flex h-8 shrink-0 items-center justify-between gap-4 px-8">
            <div
              className="flex h-full min-w-0 flex-1 items-center"
              data-tauri-drag-region
            >
              <Lockup className="pointer-events-none block h-[26px] w-auto" />
            </div>
            <div className="flex shrink-0 items-center gap-0.5">
              <HeaderIconButton
                label={m.appearance}
                pressed={panel === "appearance"}
                onClick={() => {
                  setPanel((p) => (p === "appearance" ? "home" : "appearance"));
                }}
                onMouseEnter={() => paletteIconRef.current?.startAnimation()}
                onMouseLeave={() => paletteIconRef.current?.stopAnimation()}
              >
                <PaletteIcon ref={paletteIconRef} size={17} />
              </HeaderIconButton>
              <HeaderIconButton
                label={m.settings}
                pressed={panel === "settings"}
                onClick={() => {
                  setPanel((p) => (p === "settings" ? "home" : "settings"));
                }}
                onMouseEnter={() => settingsIconRef.current?.startAnimation()}
                onMouseLeave={() => settingsIconRef.current?.stopAnimation()}
              >
                <SettingsIcon ref={settingsIconRef} size={17} />
              </HeaderIconButton>
              <HeaderIconButton
                label={m.hideToTray}
                onClick={hideToTray}
                onMouseEnter={() => chevronIconRef.current?.startAnimation()}
                onMouseLeave={() => chevronIconRef.current?.stopAnimation()}
              >
                <ChevronDownIcon ref={chevronIconRef} size={17} />
              </HeaderIconButton>
              <HeaderIconButton
                label={m.close}
                onClick={() => setQuitOpen(true)}
              >
                <X size={17} strokeWidth={2} />
              </HeaderIconButton>
            </div>
          </header>

          <AnimatePresence mode="wait" initial={false}>
            <PanelFrame key={panel}>
              {panel === "home" && (
                <>
                  <section
                    className="flex min-h-0 flex-1 flex-col items-center justify-center px-8"
                    aria-live="polite"
                  >
                    <ProtectionPad
                      on={padOn}
                      busy={busy}
                      label={protection ? m.toggleOn : m.toggleOff}
                      onClick={() => void onPad()}
                    />
                    <div className="protection-status">
                      <h2>{title}</h2>
                      <p>{hint}</p>
                    </div>
                  </section>

                  <footer className="flex shrink-0 flex-col gap-4 px-8 pt-4">
                    <Separator />
                    <div className="flex items-center justify-between gap-3">
                      <button
                        type="button"
                        className="home-foot-btn"
                        disabled={busy}
                        onClick={() => setResetOpen(true)}
                        onMouseEnter={() =>
                          deleteIconRef.current?.startAnimation()
                        }
                        onMouseLeave={() =>
                          deleteIconRef.current?.stopAnimation()
                        }
                      >
                        <DeleteIcon ref={deleteIconRef} size={16} />
                        {busyKind === "reset"
                          ? m.resetting
                          : resetHint
                            ? m.resetDone
                            : m.reset}
                      </button>
                      <button
                        type="button"
                        className="home-foot-btn"
                        disabled={busy || checkingUpdates || installingUpdate}
                        onClick={() => void onCheckUpdates()}
                        onMouseEnter={() =>
                          cloudIconRef.current?.startAnimation()
                        }
                        onMouseLeave={() =>
                          cloudIconRef.current?.stopAnimation()
                        }
                      >
                        <CloudDownloadIcon ref={cloudIconRef} size={16} />
                        {checkingUpdates
                          ? m.checkingUpdates
                          : updateHint === "upToDate"
                            ? m.upToDate
                            : updateHint === "failed"
                              ? m.updateCheckFailed
                              : m.checkUpdates}
                      </button>
                    </div>
                  </footer>
                </>
              )}

              {panel === "settings" && (
                <SettingsPage
                  m={m}
                  locale={locale}
                  onLocale={setLang}
                  onBack={() => setPanel("home")}
                  autostartOn={autostartOn}
                  onAutostartToggle={() => void onAutostartToggle()}
                  autoconnectOn={autoconnectOn}
                  onAutoconnectToggle={() => void onAutoconnectToggle()}
                  busy={busy}
                  protection={protection}
                  onConnectionTest={() => void onConnectionTest()}
                  onDiagnostics={() => void onDiagnostics()}
                  testNote={testNote}
                  diagNote={diagNote}
                  error={error}
                  diagPath={diagPath}
                  onOpenDiagFolder={() => void onOpenDiagFolder()}
                  onShareIssue={() => void onShareIssue()}
                />
              )}

              {panel === "appearance" && (
                <AppearancePage
                  themePref={themePref}
                  onChange={setTheme}
                  appIcon={appIcon}
                  onAppIconChange={setAppIcon}
                  onBack={() => setPanel("home")}
                  m={m}
                />
              )}
            </PanelFrame>
          </AnimatePresence>
        </div>
        <Dialog open={quitOpen} onOpenChange={setQuitOpen}>
          <DialogContent
            showCloseButton={false}
            overlayClassName="bg-foreground/25"
            className="max-w-72 gap-5 rounded-2xl p-5"
          >
            <DialogHeader className="gap-1">
              <DialogTitle className="app-page-title">
                {m.closeConfirmTitle}
              </DialogTitle>
              <DialogDescription className="pref-hint">
                {m.closeConfirmHint}
              </DialogDescription>
            </DialogHeader>
            <div className="confirm-actions">
              <DialogClose asChild>
                <button type="button">{m.cancel}</button>
              </DialogClose>
              <button
                type="button"
                className="is-confirm"
                onClick={confirmQuit}
              >
                {m.close}
              </button>
            </div>
          </DialogContent>
        </Dialog>
        <Dialog open={resetOpen} onOpenChange={setResetOpen}>
          <DialogContent
            showCloseButton={false}
            overlayClassName="bg-foreground/25"
            className="max-w-72 gap-5 rounded-2xl p-5"
          >
            <DialogHeader className="gap-1">
              <DialogTitle className="app-page-title">
                {m.resetConfirmTitle}
              </DialogTitle>
              <DialogDescription className="pref-hint">
                {m.resetConfirmHint}
              </DialogDescription>
            </DialogHeader>
            <div className="confirm-actions">
              <DialogClose asChild>
                <button type="button">{m.cancel}</button>
              </DialogClose>
              <button
                type="button"
                className="is-confirm"
                disabled={busy}
                onClick={() => void onRevert()}
              >
                {m.resetConfirm}
              </button>
            </div>
          </DialogContent>
        </Dialog>
        <Dialog
          open={updateOpen}
          onOpenChange={(open) => {
            if (!open) closeUpdateDialog();
          }}
        >
          <DialogContent
            showCloseButton={false}
            overlayClassName="bg-foreground/25"
            className="max-w-72 gap-5 rounded-2xl p-5"
            onPointerDownOutside={(event) => {
              if (installingUpdate) event.preventDefault();
            }}
            onEscapeKeyDown={(event) => {
              if (installingUpdate) event.preventDefault();
            }}
          >
            <DialogHeader className="gap-1">
              <DialogTitle className="app-page-title">
                {installingUpdate
                  ? downloadPct >= 100
                    ? m.updating
                    : m.updateDownloading
                  : m.updateAvailableTitle}
              </DialogTitle>
              <DialogDescription className="pref-hint">
                {installingUpdate
                  ? formatUpdatePct(locale, downloadPct)
                  : formatUpdateHint(locale, pendingUpdate?.version ?? "")}
              </DialogDescription>
            </DialogHeader>
            {installingUpdate ? (
              <div className="update-progress">
                <div className="update-progress-track">
                  <div
                    className="update-progress-fill"
                    style={{ width: `${downloadPct}%` }}
                  />
                </div>
              </div>
            ) : (
              <div className="confirm-actions">
                <DialogClose asChild>
                  <button type="button">{m.cancel}</button>
                </DialogClose>
                <button
                  type="button"
                  className="is-confirm"
                  onClick={() => void onInstallUpdate()}
                >
                  {m.updateInstall}
                </button>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}

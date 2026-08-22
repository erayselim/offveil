export type Locale = "tr" | "en";

export type Messages = {
  protected: string;
  protectedHint: string;
  notProtected: string;
  notProtectedHint: string;
  broken: string;
  brokenHint: string;
  preparing: string;
  waitingAdmin: string;
  needsAdmin: string;
  starting: string;
  disconnecting: string;
  refresh: string;
  refreshing: string;
  connectionTest: string;
  diagnostics: string;
  autostart: string;
  autoconnect: string;
  toggleOn: string;
  toggleOff: string;
  show: string;
  quit: string;
  setupDoneNoPipe: string;
  openFolder: string;
  shareIssue: string;
  langTr: string;
  langEn: string;
  language: string;
  appearance: string;
  themeSystem: string;
  themeSystemHint: string;
  themeDark: string;
  themeDarkHint: string;
  themeLight: string;
  themeLightHint: string;
  appIcon: string;
  appIconHint: string;
  appIconDefault: string;
  appIconLight: string;
  appIconDark: string;
  autostartHint: string;
  autoconnectHint: string;
  connectionTestOff: string;
  settings: string;
  back: string;
  hideToTray: string;
  close: string;
  cancel: string;
  closeConfirmTitle: string;
  closeConfirmHint: string;
  reset: string;
  resetConfirmTitle: string;
  resetConfirmHint: string;
  resetConfirm: string;
  resetting: string;
  resetDone: string;
  checkUpdates: string;
  checkingUpdates: string;
  upToDate: string;
  updateCheckFailed: string;
  updateAvailableTitle: string;
  updateAvailableHint: string;
  updateInstall: string;
  updating: string;
  updateDownloading: string;
  updateDownloadPct: string;
  creditsDesc: string;
  creditsLicense: string;
  creditsDevelopedBy: string;
};

const tr: Messages = {
  protected: "Koruma Aktif",
  protectedHint: "Güvenli gezinme ve tam erişim etkin",
  notProtected: "Koruma Kapalı",
  notProtectedHint: "Korumayı açmak için dokunun",
  broken: "Bozuldu",
  brokenHint: "Yenilemek için dokun.",
  preparing: "Hazırlanıyor…",
  waitingAdmin: "UAC penceresini onaylayın.",
  needsAdmin: "Yönetici onayı gerekli.",
  starting: "Bağlanıyor…",
  disconnecting: "Kesiliyor…",
  refresh: "Yenile",
  refreshing: "Yenileniyor…",
  connectionTest: "Bağlantıyı kontrol et",
  diagnostics: "Destek dosyası al",
  autostart: "Başlangıçta çalıştır",
  autoconnect: "Otomatik bağlan",
  toggleOn: "Korumayı kapat",
  toggleOff: "Korumayı aç",
  show: "Göster",
  quit: "Çıkış",
  setupDoneNoPipe: "Kurulum tamamlandı ama servis henüz yanıt vermiyor.",
  openFolder: "Klasörü aç",
  shareIssue: "Issue’ya ekle",
  langTr: "Türkçe",
  langEn: "English",
  language: "Dil",
  appearance: "Görünüm",
  themeSystem: "Sistem",
  themeSystemHint: "Sistem temasını kullan",
  themeDark: "Koyu",
  themeDarkHint: "Koyu görünümü kullan",
  themeLight: "Açık",
  themeLightHint: "Açık görünümü kullan",
  appIcon: "Uygulama ikonu",
  appIconHint: "Sistem tepsisinde görünür.",
  appIconDefault: "Varsayılan",
  appIconLight: "Açık",
  appIconDark: "Koyu",
  autostartHint: "Uygulama açılışta otomatik başlar.",
  autoconnectHint: "Uygulama açılınca koruma da başlar.",
  connectionTestOff: "Önce korumayı aç.",
  settings: "Ayarlar",
  back: "Geri",
  hideToTray: "Gizle",
  close: "Kapat",
  cancel: "Vazgeç",
  closeConfirmTitle: "offveil kapatılsın mı?",
  closeConfirmHint: "Koruma durur.",
  reset: "Değişiklikleri geri al",
  resetConfirmTitle: "Değişiklikler geri alınsın mı?",
  resetConfirmHint: "Koruma kapanır. DNS ve ağ ayarları eski haline döner.",
  resetConfirm: "Geri al",
  resetting: "Geri alınıyor…",
  resetDone: "Ağ ayarları geri alındı.",
  checkUpdates: "Güncellemeleri denetle",
  checkingUpdates: "Denetleniyor…",
  upToDate: "Güncelsiniz.",
  updateCheckFailed: "Güncelleme kontrol edilemedi.",
  updateAvailableTitle: "Güncelleme var",
  updateAvailableHint: "{version} sürümü indirilmeye hazır.",
  updateInstall: "Kur",
  updating: "Güncelleme hazırlanıyor…",
  updateDownloading: "İndiriliyor…",
  updateDownloadPct: "{percent}% indirildi",
  creditsDesc: "Özel ve açık erişim için yerel koruma.",
  creditsLicense: "Apache-2.0",
  creditsDevelopedBy: "Geliştiren",
};

const en: Messages = {
  protected: "Protected",
  protectedHint: "Safe browsing and full access are active",
  notProtected: "Not Protected",
  notProtectedHint: "Tap to enable protection",
  broken: "Broken",
  brokenHint: "Tap to refresh.",
  preparing: "Preparing…",
  waitingAdmin: "Approve the UAC prompt.",
  needsAdmin: "Administrator approval needed.",
  starting: "Connecting…",
  disconnecting: "Disconnecting…",
  refresh: "Refresh",
  refreshing: "Refreshing…",
  connectionTest: "Check connection",
  diagnostics: "Save a support file",
  autostart: "Start on startup",
  autoconnect: "Auto-connect",
  toggleOn: "Turn protection off",
  toggleOff: "Turn protection on",
  show: "Show",
  quit: "Quit",
  setupDoneNoPipe: "Setup finished but the service is not responding yet.",
  openFolder: "Open folder",
  shareIssue: "Attach to issue",
  langTr: "Türkçe",
  langEn: "English",
  language: "Language",
  appearance: "Appearance",
  themeSystem: "System",
  themeSystemHint: "Use system setting",
  themeDark: "Dark",
  themeDarkHint: "Use dark appearance",
  themeLight: "Light",
  themeLightHint: "Use light appearance",
  appIcon: "App icon",
  appIconHint: "Shown in the system tray.",
  appIconDefault: "Default",
  appIconLight: "Light",
  appIconDark: "Dark",
  autostartHint: "Start automatically with your device.",
  autoconnectHint: "Turn protection on when the app starts.",
  connectionTestOff: "Turn protection on first.",
  settings: "Settings",
  back: "Back",
  hideToTray: "Hide",
  close: "Close",
  cancel: "Cancel",
  closeConfirmTitle: "Close offveil?",
  closeConfirmHint: "Protection will stop.",
  reset: "Revert changes",
  resetConfirmTitle: "Revert changes?",
  resetConfirmHint: "Protection will stop. DNS and leftover network settings are restored.",
  resetConfirm: "Revert",
  resetting: "Reverting…",
  resetDone: "Network settings restored.",
  checkUpdates: "Check for Updates",
  checkingUpdates: "Checking…",
  upToDate: "You're up to date.",
  updateCheckFailed: "Couldn't check for updates.",
  updateAvailableTitle: "Update available",
  updateAvailableHint: "{version} is ready to install.",
  updateInstall: "Install",
  updating: "Preparing the update…",
  updateDownloading: "Downloading…",
  updateDownloadPct: "{percent}% downloaded",
  creditsDesc: "Local protection for private, open access.",
  creditsLicense: "Apache-2.0",
  creditsDevelopedBy: "Developed by",
};

const STORAGE_KEY = "offveil.locale";

export function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "tr" || saved === "en") return saved;
  } catch {
    /* ignore */
  }
  const nav = (navigator.language || "en").toLowerCase();
  return nav.startsWith("tr") ? "tr" : "en";
}

export function persistLocale(locale: Locale) {
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    /* ignore */
  }
}

export function t(locale: Locale): Messages {
  return locale === "tr" ? tr : en;
}

export function formatTestLine(
  locale: Locale,
  rep: {
    asn: string;
    isp_hint?: string;
    results: { target: string; class: string; path: string; ok: boolean }[];
  },
): string {
  const asn = rep.asn || "?";
  const isp = rep.isp_hint ? ` · ${rep.isp_hint}` : "";
  const label = locale === "tr" ? "Test" : "Test";
  if (!rep.results?.length) return `${label} · ASN ${asn}${isp}`;
  const r = rep.results[0];
  return `${label} · ${r.target} · ${r.class} → ${r.path} · ASN ${asn}${isp}`;
}

export function formatDiagLine(locale: Locale, path: string): string {
  return locale === "tr"
    ? `Destek dosyası hazır · ${path}`
    : `Support file ready · ${path}`;
}

export function formatUpdateHint(locale: Locale, version: string): string {
  return t(locale).updateAvailableHint.replace("{version}", version);
}

export function formatUpdatePct(locale: Locale, percent: number): string {
  return t(locale).updateDownloadPct.replace("{percent}", String(percent));
}

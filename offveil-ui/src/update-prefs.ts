export type UpdatePrefs = {
  autoCheck: boolean;
  autoDownload: boolean;
};

const STORAGE_KEY = "offveil.updatePrefs";

const DEFAULTS: UpdatePrefs = {
  autoCheck: true,
  autoDownload: false,
};

function parsePrefs(raw: string | null): UpdatePrefs {
  if (!raw) return { ...DEFAULTS };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return { ...DEFAULTS };
    const rec = parsed as Record<string, unknown>;
    return {
      autoCheck:
        typeof rec.autoCheck === "boolean" ? rec.autoCheck : DEFAULTS.autoCheck,
      autoDownload:
        typeof rec.autoDownload === "boolean"
          ? rec.autoDownload
          : DEFAULTS.autoDownload,
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export function detectUpdatePrefs(): UpdatePrefs {
  try {
    return parsePrefs(localStorage.getItem(STORAGE_KEY));
  } catch {
    return { ...DEFAULTS };
  }
}

export function persistUpdatePrefs(prefs: UpdatePrefs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* ignore */
  }
}

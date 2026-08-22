import { invoke } from "@tauri-apps/api/core";

export type ThemePref = "system" | "dark" | "light";
export type ResolvedTheme = "dark" | "light";

const STORAGE_KEY = "offveil.theme";

export function detectThemePref(): ThemePref {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "system" || saved === "dark" || saved === "light") {
      return saved;
    }
  } catch {
    /* ignore */
  }
  return "system";
}

export function persistThemePref(pref: ThemePref) {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* ignore */
  }
}

export function resolveTheme(pref: ThemePref): ResolvedTheme {
  if (pref === "light" || pref === "dark") return pref;
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

export function applyTheme(pref: ThemePref) {
  const resolved = resolveTheme(pref);
  const root = document.documentElement;
  root.classList.remove("light", "dark");
  root.classList.add(resolved);
  root.dataset.theme = resolved;
  root.style.colorScheme = resolved;
  void invoke("set_native_theme", { dark: resolved === "dark" }).catch(() => {
    /* not running inside Tauri */
  });
}

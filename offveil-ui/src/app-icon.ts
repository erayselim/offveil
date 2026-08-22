import { invoke } from "@tauri-apps/api/core";

export type AppIconVariant = "default" | "light" | "dark";

export const APP_ICON_VARIANTS: AppIconVariant[] = ["default", "light", "dark"];

const STORAGE_KEY = "offveil.app-icon";

export function detectAppIcon(): AppIconVariant {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "default" || saved === "light" || saved === "dark") {
      return saved;
    }
  } catch {
    /* ignore */
  }
  return "default";
}

export function persistAppIcon(variant: AppIconVariant) {
  try {
    localStorage.setItem(STORAGE_KEY, variant);
  } catch {
    /* ignore */
  }
}

export function applyAppIcon(variant: AppIconVariant) {
  void invoke("set_app_icon", { variant }).catch(() => {
    /* not running inside Tauri */
  });
}

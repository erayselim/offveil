import { invoke } from "@tauri-apps/api/core";

export type AppIconVariant = "system" | "default";

export const APP_ICON_VARIANTS: AppIconVariant[] = ["system", "default"];

const STORAGE_KEY = "offveil.app-icon";

export function detectAppIcon(): AppIconVariant {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "system" || saved === "default") {
      return saved;
    }
  } catch {
    /* ignore */
  }
  // Retired light/dark preferences follow the system, as do new installs.
  return "system";
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

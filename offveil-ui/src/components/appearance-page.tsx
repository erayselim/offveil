import { Check, Monitor, Moon, Sun, type LucideIcon } from "lucide-react";
import { useRef, type KeyboardEvent } from "react";

import iconDefault from "@/assets/brand/offveil-icon-default.svg";
import iconDark from "@/assets/brand/offveil-icon-dark.svg";
import iconLight from "@/assets/brand/offveil-icon-light.svg";
import { AppPage } from "@/components/app-page";
import { APP_ICON_VARIANTS, type AppIconVariant } from "@/app-icon";
import type { Messages } from "@/i18n";
import type { ThemePref } from "@/theme";

const OPTIONS: ThemePref[] = ["system", "dark", "light"];

const ICONS: Record<ThemePref, LucideIcon> = {
  system: Monitor,
  dark: Moon,
  light: Sun,
};

const ICON_SRC: Record<AppIconVariant, string> = {
  default: iconDefault,
  light: iconLight,
  dark: iconDark,
};

export function AppearancePage({
  themePref,
  onChange,
  appIcon,
  onAppIconChange,
  onBack,
  m,
}: {
  themePref: ThemePref;
  onChange: (next: ThemePref) => void;
  appIcon: AppIconVariant;
  onAppIconChange: (next: AppIconVariant) => void;
  onBack: () => void;
  m: Messages;
}) {
  const themeRefs = useRef<Partial<Record<ThemePref, HTMLButtonElement | null>>>(
    {},
  );
  const iconRefs = useRef<
    Partial<Record<AppIconVariant, HTMLButtonElement | null>>
  >({});

  const copy: Record<ThemePref, { title: string; hint: string }> = {
    system: { title: m.themeSystem, hint: m.themeSystemHint },
    dark: { title: m.themeDark, hint: m.themeDarkHint },
    light: { title: m.themeLight, hint: m.themeLightHint },
  };

  const iconCopy: Record<AppIconVariant, string> = {
    default: m.appIconDefault,
    light: m.appIconLight,
    dark: m.appIconDark,
  };

  const selectTheme = (value: ThemePref, moveFocus = false) => {
    onChange(value);
    if (moveFocus) {
      requestAnimationFrame(() => themeRefs.current[value]?.focus());
    }
  };

  const selectIcon = (value: AppIconVariant, moveFocus = false) => {
    onAppIconChange(value);
    if (moveFocus) {
      requestAnimationFrame(() => iconRefs.current[value]?.focus());
    }
  };

  const onThemeKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = OPTIONS.indexOf(themePref);
    if (i < 0) return;
    if (e.key === "ArrowDown" || e.key === "ArrowRight") {
      e.preventDefault();
      selectTheme(OPTIONS[(i + 1) % OPTIONS.length], true);
    } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
      e.preventDefault();
      selectTheme(OPTIONS[(i - 1 + OPTIONS.length) % OPTIONS.length], true);
    }
  };

  const onIconKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = APP_ICON_VARIANTS.indexOf(appIcon);
    if (i < 0) return;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      e.preventDefault();
      selectIcon(APP_ICON_VARIANTS[(i + 1) % APP_ICON_VARIANTS.length], true);
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      e.preventDefault();
      selectIcon(
        APP_ICON_VARIANTS[
          (i - 1 + APP_ICON_VARIANTS.length) % APP_ICON_VARIANTS.length
        ],
        true,
      );
    }
  };

  return (
    <AppPage title={m.appearance} backLabel={m.back} onBack={onBack}>
      <div
        className="theme-list"
        role="radiogroup"
        aria-label={m.appearance}
        onKeyDown={onThemeKeyDown}
      >
        {OPTIONS.map((value) => {
          const opt = copy[value];
          const Icon = ICONS[value];
          return (
            <button
              key={value}
              ref={(el) => {
                themeRefs.current[value] = el;
              }}
              type="button"
              role="radio"
              aria-checked={themePref === value}
              tabIndex={themePref === value ? 0 : -1}
              className="theme-option"
              onClick={() => selectTheme(value)}
            >
              <Icon className="theme-option-icon" aria-hidden="true" />
              <span className="theme-option-copy">
                <span className="theme-option-title">{opt.title}</span>
                <span className="theme-option-hint">{opt.hint}</span>
              </span>
              <Check
                className="theme-option-check"
                aria-hidden={themePref !== value}
              />
            </button>
          );
        })}
      </div>

      <div className="field-block">
        <div className="pref-copy">
          <div className="pref-label" id="app-icon-label">
            {m.appIcon}
          </div>
          <p className="pref-hint">{m.appIconHint}</p>
        </div>
        <div
          className="icon-grid"
          role="radiogroup"
          aria-labelledby="app-icon-label"
          onKeyDown={onIconKeyDown}
        >
          {APP_ICON_VARIANTS.map((value) => (
            <button
              key={value}
              ref={(el) => {
                iconRefs.current[value] = el;
              }}
              type="button"
              role="radio"
              aria-checked={appIcon === value}
              tabIndex={appIcon === value ? 0 : -1}
              className="icon-option"
              onClick={() => selectIcon(value)}
            >
              <span className="icon-option-preview" data-variant={value}>
                <img src={ICON_SRC[value]} alt="" draggable={false} />
              </span>
              <span className="icon-option-label">{iconCopy[value]}</span>
              <Check
                className="icon-option-check"
                aria-hidden={appIcon !== value}
              />
            </button>
          ))}
        </div>
      </div>
    </AppPage>
  );
}

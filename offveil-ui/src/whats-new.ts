import type { Locale } from "./i18n";
import bundled from "./whats-new.json";

export type WhatsNewNotes = {
  tr: string;
  en: string;
};

export type WhatsNewDoc = {
  version: string;
  notes: WhatsNewNotes;
};

export function normalizeVersion(version: string): string {
  return version.trim().replace(/^v/i, "");
}

function pickNote(notes: WhatsNewNotes, locale: Locale): string | null {
  const preferred = notes[locale]?.trim() ?? "";
  if (preferred) return preferred;
  const fallback = (locale === "tr" ? notes.en : notes.tr)?.trim() ?? "";
  return fallback || null;
}

function parseNotesRecord(value: unknown): WhatsNewNotes | null {
  if (!value || typeof value !== "object") return null;
  const rec = value as Record<string, unknown>;
  const tr = typeof rec.tr === "string" ? rec.tr : "";
  const en = typeof rec.en === "string" ? rec.en : "";
  if (!tr.trim() && !en.trim()) return null;
  return { tr, en };
}

/** latest.json `notes` is a JSON string `{ tr, en }` when generated from whats-new.json. */
export function notesFromUpdateBody(
  body: string | null | undefined,
  locale: Locale,
): string | null {
  if (!body) return null;
  const raw = body.trim();
  if (!raw.startsWith("{")) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    const notes = parseNotesRecord(parsed);
    return notes ? pickNote(notes, locale) : null;
  } catch {
    return null;
  }
}

export function bundledWhatsNew(
  appVersion: string | null | undefined,
  locale: Locale,
): string | null {
  if (!appVersion) return null;
  const doc = bundled as WhatsNewDoc;
  if (normalizeVersion(doc.version) !== normalizeVersion(appVersion)) {
    return null;
  }
  return pickNote(doc.notes, locale);
}

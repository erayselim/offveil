import type { ReactNode } from "react";
import { ChevronLeft } from "lucide-react";

import { ScrollArea } from "@/components/ui/scroll-area";

export function AppPage({
  title,
  backLabel,
  onBack,
  children,
}: {
  title: string;
  backLabel: string;
  onBack: () => void;
  children: ReactNode;
}) {
  return (
    <section className="app-page" aria-label={title}>
      <button
        type="button"
        className="app-page-head"
        aria-label={backLabel}
        onClick={onBack}
      >
        <ChevronLeft strokeWidth={2} aria-hidden="true" />
        <span className="app-page-title">{title}</span>
      </button>
      <ScrollArea className="app-page-scroll">
        <div className="app-page-body">{children}</div>
      </ScrollArea>
    </section>
  );
}

export function ChoiceSeg({
  value,
  options,
  onChange,
  labelledBy,
}: {
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
  labelledBy: string;
}) {
  return (
    <div
      className="choice-seg"
      role="radiogroup"
      aria-labelledby={labelledBy}
      style={{
        gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))`,
      }}
    >
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

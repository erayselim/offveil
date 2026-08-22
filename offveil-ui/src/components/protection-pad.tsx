import { Power } from "lucide-react";
import { Mark } from "@/brand";
import { RingSpinner } from "@/components/ring-spinner";
import { cn } from "@/lib/utils";

type ProtectionPadProps = {
  on: boolean;
  busy: boolean;
  label: string;
  onClick: () => void;
};

export function ProtectionPad({ on, busy, label, onClick }: ProtectionPadProps) {
  return (
    <button
      type="button"
      className={cn("protection-pad", on && "is-on", busy && "is-busy")}
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={busy}
      onClick={onClick}
    >
      {busy ? (
        <RingSpinner key="loading" size={40} />
      ) : on ? (
        <Mark key="on" className="animate-pop-in protection-pad-mark" />
      ) : (
        <Power
          key="off"
          size={32}
          strokeWidth={2}
          className="animate-pop-in"
        />
      )}
    </button>
  );
}

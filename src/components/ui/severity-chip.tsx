import { SEVERITY, toSeverityKey } from "./severity";

/** Letter box (C/H/M/L/?). `severity` accepts any casing; unknown values render "?". */
export function SeverityChip({ severity, className = "" }: { severity: string | null | undefined; className?: string }) {
  const s = SEVERITY[toSeverityKey(severity)];
  return (
    <span
      role="img"
      title={s.label}
      aria-label={s.label}
      className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-[11px] font-bold leading-none ${className}`}
      style={{ background: s.bg, color: s.fg }}
    >
      {s.letter}
    </span>
  );
}

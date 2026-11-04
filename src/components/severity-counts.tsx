import { SeverityBar } from "./ui/severity-bar";
import { SEVERITY, type SeverityKey } from "./ui/severity";

export type SeverityMix = Partial<Record<SeverityKey, number>>;

const CHIP_KEYS = ["critical", "high", "medium", "low"] as const;

/** Severity bar plus C/H/M/L count chips: the one severity rendering used by dashboard tables. */
export function SeverityCounts({ counts }: { counts: SeverityMix }) {
  return (
    <div className="min-w-0">
      <SeverityBar counts={counts} />
      <div className="mt-1.5 flex flex-wrap gap-1" role="group" aria-label="Severity counts">
        {CHIP_KEYS.map((key) => {
          const s = SEVERITY[key];
          const count = counts[key] ?? 0;
          return (
            <span
              key={key}
              title={`${s.label} ${count}`}
              className={`inline-flex h-5 items-center gap-1 rounded px-1.5 font-mono text-[11px] font-bold leading-none ${count === 0 ? "opacity-40" : ""}`}
              style={{ background: s.bg, color: s.fg }}
            >
              {s.letter}
              <span>{count.toLocaleString()}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

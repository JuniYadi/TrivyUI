import { SEVERITY, type SeverityKey } from "./severity";

const ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];

/** Stacked mix bar. `counts` keyed by severity (lowercase). */
export function SeverityBar({ counts, className = "" }: { counts: Partial<Record<SeverityKey, number>>; className?: string }) {
  const total = ORDER.reduce((sum, k) => sum + (counts[k] ?? 0), 0);
  const summary = ORDER.map((k) => `${SEVERITY[k].label} ${counts[k] ?? 0}`).join(", ");
  return (
    <div role="img" aria-label={summary} title={summary} className={`flex h-1.5 w-full overflow-hidden rounded-full bg-line ${className}`}>
      {total > 0 &&
        ORDER.map((k) =>
          counts[k] ? <span key={k} style={{ width: `${((counts[k] ?? 0) / total) * 100}%`, background: SEVERITY[k].bar }} /> : null,
        )}
    </div>
  );
}

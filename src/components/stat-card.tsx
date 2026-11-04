import type { ReactNode } from "react";
import { SEVERITY } from "./ui/severity";

type Tone = "neutral" | "critical" | "high" | "success";

interface StatCardProps {
  label: string;
  value: number | string;
  tone?: Tone;
  /** Small line under the value, e.g. "+12 since previous scan". */
  sub?: ReactNode;
}

const TONE_COLOR: Record<Tone, string | undefined> = {
  neutral: undefined,
  critical: SEVERITY.critical.fg,
  high: SEVERITY.high.fg,
  success: "var(--color-success)",
};

export function StatCard({ label, value, tone = "neutral", sub }: StatCardProps) {
  return (
    <article className="min-w-0 rounded-xl border border-line bg-card p-3 sm:p-4">
      <div className="text-xs text-fg2 sm:text-[13px]">{label}</div>
      <div
        className="mt-1 text-3xl font-bold leading-none tracking-tight text-fg"
        style={TONE_COLOR[tone] ? { color: TONE_COLOR[tone] } : undefined}
      >
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      {sub !== undefined && <div className="mt-2 text-xs text-muted">{sub}</div>}
    </article>
  );
}

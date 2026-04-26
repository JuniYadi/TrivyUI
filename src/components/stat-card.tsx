interface StatCardProps {
  label: string;
  value: number;
  tone?: "neutral" | "critical" | "high" | "medium" | "low" | "unknown";
}

const TONE_CLASS: Record<NonNullable<StatCardProps["tone"]>, string> = {
  neutral: "stat-card--neutral",
  critical: "stat-card--critical",
  high: "stat-card--high",
  medium: "stat-card--medium",
  low: "stat-card--low",
  unknown: "stat-card--unknown",
};

export function StatCard({ label, value, tone = "neutral" }: StatCardProps) {
  return (
    <article className={`card stat-card ${TONE_CLASS[tone]}`}>
      <div className="stat-card__value">{value.toLocaleString()}</div>
      <div className="stat-card__label">{label}</div>
    </article>
  );
}

interface StatCardProps {
  label: string;
  value: number;
  tone?: "neutral" | "critical" | "high" | "medium" | "low" | "unknown";
}

const TONE_CLASS: Record<NonNullable<StatCardProps["tone"]>, string> = {
  neutral: "border-slate-700 bg-slate-900 text-slate-200",
  critical: "border-red-900 bg-red-950 text-red-200",
  high: "border-orange-900 bg-orange-950 text-orange-200",
  medium: "border-yellow-900 bg-yellow-950 text-yellow-200",
  low: "border-blue-900 bg-blue-950 text-blue-200",
  unknown: "border-gray-700 bg-gray-900 text-gray-300",
};

export function StatCard({ label, value, tone = "neutral" }: StatCardProps) {
  return (
    <article className={`rounded-xl border bg-slate-900/90 p-4 shadow-inner ${TONE_CLASS[tone]}`}>
      <div className="text-3xl font-bold leading-none">{value.toLocaleString()}</div>
      <div className="mt-1 text-sm opacity-90">{label}</div>
    </article>
  );
}

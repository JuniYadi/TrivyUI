import type { CSSProperties } from "react";

interface StatCardProps {
  label: string;
  value: number;
  tone?: "neutral" | "critical" | "high" | "medium" | "low" | "unknown";
}

const TONE: Record<NonNullable<StatCardProps["tone"]>, { border: string; text: string; bg: string }> = {
  neutral: { border: "#334155", text: "#e2e8f0", bg: "#0f172a" },
  critical: { border: "#7f1d1d", text: "#fecaca", bg: "#450a0a" },
  high: { border: "#7c2d12", text: "#fdba74", bg: "#431407" },
  medium: { border: "#854d0e", text: "#fef08a", bg: "#422006" },
  low: { border: "#1e3a8a", text: "#bfdbfe", bg: "#172554" },
  unknown: { border: "#374151", text: "#d1d5db", bg: "#111827" },
};

export function StatCard({ label, value, tone = "neutral" }: StatCardProps) {
  const palette = TONE[tone];

  const boxStyle: CSSProperties = {
    border: `1px solid ${palette.border}`,
    borderRadius: 12,
    background: palette.bg,
    color: palette.text,
    padding: "1rem",
    minWidth: 160,
  };

  return (
    <article style={boxStyle}>
      <div style={{ fontSize: "1.8rem", fontWeight: 700 }}>{value.toLocaleString()}</div>
      <div style={{ opacity: 0.9 }}>{label}</div>
    </article>
  );
}

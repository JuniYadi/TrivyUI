import type { CSSProperties } from "react";
import type { SeverityBreakdown } from "../services/types";

interface SeverityChartProps {
  bySeverity: SeverityBreakdown;
}

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#60a5fa",
  UNKNOWN: "#9ca3af",
};

export function SeverityChart({ bySeverity }: SeverityChartProps) {
  const total = Object.values(bySeverity).reduce((sum, value) => sum + value, 0);

  const segments = [
    { key: "CRITICAL", value: bySeverity.CRITICAL, color: COLORS.CRITICAL },
    { key: "HIGH", value: bySeverity.HIGH, color: COLORS.HIGH },
    { key: "MEDIUM", value: bySeverity.MEDIUM, color: COLORS.MEDIUM },
    { key: "LOW", value: bySeverity.LOW, color: COLORS.LOW },
    { key: "UNKNOWN", value: bySeverity.UNKNOWN, color: COLORS.UNKNOWN },
  ];

  let currentAngle = 0;
  const gradientStops = segments
    .map((segment) => {
      const percent = total === 0 ? 0 : (segment.value / total) * 100;
      const start = currentAngle;
      const end = currentAngle + percent;
      currentAngle = end;
      return `${segment.color} ${start}% ${end}%`;
    })
    .join(", ");

  const chartStyle: CSSProperties = {
    width: 160,
    height: 160,
    borderRadius: "50%",
    background: total === 0 ? "#1f2937" : `conic-gradient(${gradientStops})`,
    display: "grid",
    placeItems: "center",
    position: "relative",
  };

  return (
    <section style={{ border: "1px solid #334155", borderRadius: 12, padding: "1rem" }}>
      <h3 style={{ marginTop: 0 }}>Severity Distribution</h3>
      <div style={{ display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
        <div style={chartStyle} aria-label="severity-chart">
          <div
            style={{
              width: 90,
              height: 90,
              borderRadius: "50%",
              background: "#020617",
              border: "1px solid #334155",
              display: "grid",
              placeItems: "center",
              color: "#e2e8f0",
              fontSize: 14,
              textAlign: "center",
            }}
          >
            {total.toLocaleString()}
            <br />
            total
          </div>
        </div>

        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
          {segments.map((segment) => (
            <li key={segment.key}>
              <span style={{ color: segment.color, fontWeight: 700 }}>{segment.key}</span>: {segment.value}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

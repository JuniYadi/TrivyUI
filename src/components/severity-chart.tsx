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
} as const;

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
    background: total === 0 ? "#1f2937" : `conic-gradient(${gradientStops})`,
  };

  return (
    <section className="card">
      <h3 className="card-title">Severity Distribution</h3>
      <div className="severity-layout">
        <div className="severity-chart" aria-label="severity-chart" style={chartStyle}>
          <div className="severity-chart__center">
            {total.toLocaleString()}
            <br />
            total
          </div>
        </div>

        <ul className="severity-legend">
          {segments.map((segment) => (
            <li key={segment.key}>
              <span className="severity-legend__label" style={{ color: segment.color }}>
                {segment.key}
              </span>{" "}
              : {segment.value}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

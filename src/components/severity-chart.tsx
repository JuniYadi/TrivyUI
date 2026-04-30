import type { SeverityBreakdown } from "../services/types";

interface SeverityChartProps {
  bySeverity: SeverityBreakdown;
}

const COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#60a5fa",
  UNKNOWN: "#9ca3af",
};

export function SeverityChart({ bySeverity }: SeverityChartProps) {
  const total = Object.values(bySeverity).reduce((sum, v) => sum + v, 0);

  const segments = [
    { key: "CRITICAL", value: bySeverity.CRITICAL },
    { key: "HIGH", value: bySeverity.HIGH },
    { key: "MEDIUM", value: bySeverity.MEDIUM },
    { key: "LOW", value: bySeverity.LOW },
    { key: "UNKNOWN", value: bySeverity.UNKNOWN },
  ];

  const SIZE = 160;
  const CENTER = SIZE / 2;
  const RADIUS = 64;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

  let offset = 0;
  const rings = segments
    .filter((s) => s.value > 0)
    .map((segment) => {
      const fraction = total === 0 ? 0 : segment.value / total;
      const dashLength = fraction * CIRCUMFERENCE;
      const ringOffset = offset;
      offset += dashLength;
      return {
        key: segment.key,
        color: COLORS[segment.key],
        dashArray: `${dashLength} ${CIRCUMFERENCE - dashLength}`,
        rotation: -90 + (ringOffset / CIRCUMFERENCE) * 360,
      };
    });

  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
      <h3 className="mb-3 text-base font-semibold">Severity Distribution</h3>
      <div className="flex flex-wrap items-center gap-4">
        <svg
          width={SIZE}
          height={SIZE}
          viewBox={`0 0 ${SIZE} ${SIZE}`}
          aria-label="severity-chart"
          className="flex-shrink-0"
        >
          {rings.length === 0 ? (
            <circle
              cx={CENTER}
              cy={CENTER}
              r={RADIUS}
              fill="none"
              stroke="#1f2937"
              strokeWidth="24"
            />
          ) : (
            rings.map((ring) => (
              <circle
                key={ring.key}
                cx={CENTER}
                cy={CENTER}
                r={RADIUS}
                fill="none"
                stroke={ring.color}
                strokeWidth="24"
                strokeDasharray={ring.dashArray}
                strokeDashoffset="0"
                transform={`rotate(${ring.rotation} ${CENTER} ${CENTER})`}
                strokeLinecap="butt"
              />
            ))
          )}
          <circle cx={CENTER} cy={CENTER} r={RADIUS - 12} fill="#020617" />
          <text
            x={CENTER}
            y={CENTER - 6}
            textAnchor="middle"
            dominantBaseline="middle"
            fill="#e2e8f0"
            fontSize="22"
            fontWeight="700"
          >
            {total.toLocaleString()}
          </text>
          <text
            x={CENTER}
            y={CENTER + 14}
            textAnchor="middle"
            dominantBaseline="middle"
            fill="#94a3b8"
            fontSize="11"
          >
            total
          </text>
        </svg>

        <ul className="m-0 grid list-none gap-1.5 p-0">
          {segments.map((segment) => (
            <li key={segment.key} className="flex items-center gap-2 text-sm">
              <span
                className="inline-block h-3 w-3 rounded-full flex-shrink-0"
                style={{ backgroundColor: COLORS[segment.key] }}
              />
              <span className="font-bold" style={{ color: COLORS[segment.key] }}>
                {segment.key}
              </span>
              <span className="text-slate-400">: {segment.value}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

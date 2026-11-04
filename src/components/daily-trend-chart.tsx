import { useEffect, useMemo, useRef, useState } from "react";
import type { DashboardDailyTrendV2, SeverityCounts } from "../services/dashboard-types";
import { Card } from "./ui/card";
import { SEVERITY, type SeverityKey } from "./ui/severity";

export type DailyTrendWindow = 7 | 14 | 30;

const WINDOW_OPTIONS: Array<{ label: string; days: DailyTrendWindow }> = [
  { label: "7d", days: 7 },
  { label: "14d", days: 14 },
  { label: "30d", days: 30 },
];

const STACK_ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];

export function sliceDailyTrendsByWindow<T>(trends: T[], days: DailyTrendWindow): T[] {
  return trends.length <= days ? trends : trends.slice(-days);
}

function formatTrendDay(day: string): string {
  const [year, month, date] = day.split("-");
  return year && month && date ? `${month}/${date}` : day;
}

interface DailyTrendChartProps {
  trends: DashboardDailyTrendV2[];
  /** Current open counts, shown in the legend. */
  current: SeverityCounts;
}

export function DailyTrendChart({ trends, current }: DailyTrendChartProps) {
  const [windowDays, setWindowDays] = useState<DailyTrendWindow>(14);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartRef = useRef<{ destroy: () => void } | null>(null);

  const visibleTrends = useMemo(() => sliceDailyTrendsByWindow(trends, windowDays), [trends, windowDays]);

  useEffect(() => {
    let isCancelled = false;

    const renderChart = async () => {
      const canvas = canvasRef.current;
      const ctx = canvas?.getContext("2d");
      if (!canvas || !ctx) {
        return;
      }

      const chartModule = await import("chart.js/auto");
      if (isCancelled) {
        return;
      }

      chartRef.current?.destroy();

      const Chart = chartModule.default;
      chartRef.current = new Chart(ctx, {
        type: "bar",
        data: {
          labels: visibleTrends.map((point) => formatTrendDay(point.date)),
          datasets: STACK_ORDER.map((key) => ({
            label: SEVERITY[key].label,
            data: visibleTrends.map((point) => point[key]),
            backgroundColor: SEVERITY[key].bar,
            borderWidth: 0,
            borderRadius: 0,
            stack: "open",
          })),
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: { legend: { display: false } },
          scales: {
            x: { stacked: true, grid: { display: false }, ticks: { color: "#8b95a5", maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
            y: { stacked: true, beginAtZero: true, grid: { color: "rgba(139, 149, 165, 0.12)" }, ticks: { color: "#8b95a5", precision: 0 } },
          },
        },
      });
    };

    void renderChart();

    return () => {
      isCancelled = true;
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [visibleTrends]);

  return (
    <Card className="min-w-0">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-fg">Open vulnerabilities, last {windowDays} days</h2>
        <div className="inline-flex rounded-lg border border-line p-0.5" role="group" aria-label="trend-window-filter">
          {WINDOW_OPTIONS.map((option) => {
            const active = option.days === windowDays;
            return (
              <button
                key={option.days}
                type="button"
                className={[
                  "min-h-11 min-w-11 rounded-md px-2.5 text-xs font-semibold transition sm:min-h-8 sm:min-w-9",
                  active ? "bg-line text-fg" : "text-muted hover:text-fg",
                ].join(" ")}
                aria-pressed={active}
                onClick={() => setWindowDays(option.days)}
              >
                {option.label}
              </button>
            );
          })}
        </div>
      </div>
      <div className="h-56 sm:h-64">
        <canvas ref={canvasRef} role="img" aria-label="daily-trend-chart" />
      </div>
      <ul className="m-0 mt-3 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-xs text-fg2">
        {STACK_ORDER.map((key) => (
          <li key={key} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm" style={{ background: SEVERITY[key].bar }} />
            {SEVERITY[key].label} {current[key].toLocaleString()}
          </li>
        ))}
      </ul>
    </Card>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import type { DashboardDailyTrend } from "../services/types";

export type DailyTrendWindow = 7 | 14 | 30;

const WINDOW_OPTIONS: Array<{ label: string; days: DailyTrendWindow }> = [
  { label: "7d", days: 7 },
  { label: "14d", days: 14 },
  { label: "30d", days: 30 },
];

const DATASET_COLORS = {
  vulnerabilities: "#f97316",
  scanned: "#38bdf8",
  resolved: "#22c55e",
};

export function sliceDailyTrendsByWindow(trends: DashboardDailyTrend[], days: DailyTrendWindow): DashboardDailyTrend[] {
  if (trends.length <= days) {
    return trends;
  }

  return trends.slice(-days);
}

function formatTrendDay(day: string): string {
  const [year, month, date] = day.split("-");
  if (!year || !month || !date) {
    return day;
  }

  return `${month}/${date}`;
}

interface DailyTrendChartProps {
  trends: DashboardDailyTrend[];
}

export function DailyTrendChart({ trends }: DailyTrendChartProps) {
  const [windowDays, setWindowDays] = useState<DailyTrendWindow>(7);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartRef = useRef<{ destroy: () => void } | null>(null);

  const visibleTrends = useMemo(
    () => sliceDailyTrendsByWindow(trends, windowDays),
    [trends, windowDays]
  );

  useEffect(() => {
    let isCancelled = false;

    const renderChart = async () => {
      const canvas = canvasRef.current;
      if (!canvas) {
        return;
      }

      const ctx = canvas.getContext("2d");
      if (!ctx) {
        return;
      }

      const chartModule = await import("chart.js/auto");
      if (isCancelled) {
        return;
      }

      chartRef.current?.destroy();

      const Chart = chartModule.default;
      chartRef.current = new Chart(ctx, {
        type: "line",
        data: {
          labels: visibleTrends.map((point) => formatTrendDay(point.date)),
          datasets: [
            {
              label: "Vulnerabilities Detected",
              data: visibleTrends.map((point) => point.vulnerabilities_detected),
              borderColor: DATASET_COLORS.vulnerabilities,
              backgroundColor: DATASET_COLORS.vulnerabilities,
              pointRadius: 3,
              pointHoverRadius: 5,
              tension: 0.25,
              borderWidth: 2,
            },
            {
              label: "Packages Scanned",
              data: visibleTrends.map((point) => point.packages_scanned),
              borderColor: DATASET_COLORS.scanned,
              backgroundColor: DATASET_COLORS.scanned,
              pointRadius: 3,
              pointHoverRadius: 5,
              tension: 0.25,
              borderWidth: 2,
            },
            {
              label: "Packages Resolved",
              data: visibleTrends.map((point) => point.packages_resolved),
              borderColor: DATASET_COLORS.resolved,
              backgroundColor: DATASET_COLORS.resolved,
              pointRadius: 3,
              pointHoverRadius: 5,
              tension: 0.25,
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: "index",
            intersect: false,
          },
          plugins: {
            legend: {
              labels: {
                color: "#cbd5e1",
              },
            },
          },
          scales: {
            x: {
              grid: {
                color: "rgba(148, 163, 184, 0.12)",
              },
              ticks: {
                color: "#94a3b8",
              },
            },
            y: {
              beginAtZero: true,
              grid: {
                color: "rgba(148, 163, 184, 0.12)",
              },
              ticks: {
                color: "#94a3b8",
                precision: 0,
              },
            },
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
    <section className="rounded-xl border border-slate-700 bg-slate-900/80 p-4 shadow-inner">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="text-base font-semibold text-slate-100">Daily Vulnerability & Package Trend</h3>
        <div className="inline-flex rounded-lg border border-slate-700 bg-slate-900/70 p-1" role="group" aria-label="trend-window-filter">
          {WINDOW_OPTIONS.map((option) => {
            const active = option.days === windowDays;
            return (
              <button
                key={option.days}
                type="button"
                className={[
                  "rounded-md px-2.5 py-1 text-xs font-semibold transition",
                  active ? "bg-sky-500/20 text-sky-300" : "text-slate-300 hover:bg-slate-800 hover:text-slate-100",
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
      <div className="h-72">
        <canvas ref={canvasRef} aria-label="daily-trend-chart" />
      </div>
    </section>
  );
}

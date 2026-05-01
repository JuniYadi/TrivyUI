import { useNavigate, useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useImageDetail } from "../hooks/use-image-detail";
import type { ImageDetailResponse } from "../services/types";

function parseImageId(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const id = Number.parseInt(value, 10);
  return Number.isFinite(id) ? id : null;
}

function DetailSkeleton() {
  return (
    <section className="skeleton-stack">
      <div className="skeleton-block" />
      <div className="skeleton-block" />
      <div className="skeleton-block skeleton-block--tall" />
    </section>
  );
}

type RetryHandler = () => void | Promise<void>;

interface ImageDetailContentProps {
  data: ImageDetailResponse | null;
  loading: boolean;
  error: string | null;
  retry: RetryHandler;
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "rounded-full bg-red-950 px-2 py-0.5 text-xs font-bold text-red-200",
  HIGH: "rounded-full bg-orange-950 px-2 py-0.5 text-xs font-bold text-orange-200",
  MEDIUM: "rounded-full bg-yellow-950 px-2 py-0.5 text-xs font-bold text-yellow-200",
  LOW: "rounded-full bg-blue-950 px-2 py-0.5 text-xs font-bold text-blue-200",
  UNKNOWN: "rounded-full bg-gray-800 px-2 py-0.5 text-xs font-bold text-gray-300",
};

export function ImageDetailContent({ data, loading, error, retry }: ImageDetailContentProps) {
  const navigate = useNavigate();

  return (
    <>
      {loading && (
        <section className="grid gap-4">
          <div className="h-16 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
          <div className="h-56 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
          <div className="h-64 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
        </section>
      )}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}

      {!loading && !error && !data && (
        <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-5">
          <h2 className="mb-2 text-base font-semibold">Image not found</h2>
          <p className="mb-4 text-slate-400">This image does not exist or may have been removed.</p>
          <button
            type="button"
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500"
            onClick={() => void navigate({ to: "/images" })}
          >
            Back to Images
          </button>
        </section>
      )}

      {!loading && !error && data && (
        <section className="grid gap-4">
          <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="mt-0 text-xs font-semibold uppercase tracking-wide text-slate-400">Repository</p>
                <p className="mb-0 text-sm">{data.repository.name}</p>
              </div>
              <div>
                <p className="mt-0 text-xs font-semibold uppercase tracking-wide text-slate-400">Last scanned</p>
                <p className="mb-0 text-sm">{data.last_scanned_at ? new Date(data.last_scanned_at).toLocaleString() : "-"}</p>
              </div>
              <button
                type="button"
                className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500"
                onClick={() => void navigate({ to: "/images" })}
              >
                Back to Images
              </button>
            </div>
          </section>

          <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <StatCard label="Total Vulnerabilities" value={data.vulnerabilities.length} tone="neutral" />
            <StatCard label="Critical" value={data.by_severity.CRITICAL} tone="critical" />
            <StatCard label="High" value={data.by_severity.HIGH} tone="high" />
            <StatCard label="Medium" value={data.by_severity.MEDIUM} tone="medium" />
            <StatCard label="Low" value={data.by_severity.LOW} tone="low" />
            <StatCard label="Unknown" value={data.by_severity.UNKNOWN} tone="unknown" />
          </section>

          <section className="grid md:grid-cols-2 gap-4">
            <SeverityChart bySeverity={data.by_severity} />
            <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
              <h3 className="mb-3 text-base font-semibold">Image metadata</h3>
              <p className="text-sm text-slate-400">Created at: {new Date(data.created_at).toLocaleString()}</p>
              <button
                type="button"
                className="text-blue-400 hover:text-blue-300 hover:underline"
                onClick={() => void navigate({ to: "/repositories/$id", params: { id: String(data.repository.id) } })}
              >
                Open repository detail
              </button>
            </section>
          </section>

          <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner overflow-x-auto">
            <h3 className="mb-3 text-base font-semibold">Vulnerabilities</h3>
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-left">
                  <th className="pb-3 pr-4">CVE ID</th>
                  <th className="pb-3 pr-4">Severity</th>
                  <th className="pb-3 pr-4">Package</th>
                  <th className="pb-3 pr-4">Installed</th>
                  <th className="pb-3 pr-4">Fixed</th>
                  <th className="pb-3">Scanned At</th>
                </tr>
              </thead>
              <tbody>
                {data.vulnerabilities.map((item) => (
                  <tr key={item.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-3 pr-4">{item.cve_id}</td>
                    <td className="py-3 pr-4">
                      <span className={SEVERITY_STYLES[item.severity] || ""}>{item.severity}</span>
                    </td>
                    <td className="py-3 pr-4">{item.package_name}</td>
                    <td className="py-3 pr-4">{item.installed_version || "-"}</td>
                    <td className="py-3 pr-4">{item.fixed_version || "-"}</td>
                    <td className="py-3">{new Date(item.scanned_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>
      )}
    </>
  );
}

export function ImageDetailPage() {
  const { id: rawId } = useParams({ strict: false }) as { id?: string };
  const id = parseImageId(rawId);
  const { data, loading, error, retry } = useImageDetail(id);

  return (
    <AppShell activeRoute="/images/:id" title={data?.name || "Image Detail"} subtitle="Severity summary and vulnerability list for the selected image.">
      <ImageDetailContent data={data} loading={loading} error={error} retry={retry} />
    </AppShell>
  );
}

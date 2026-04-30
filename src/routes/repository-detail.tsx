import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useRepoDetail } from "../hooks/use-repo-detail";
import { navigate } from "../lib/navigation";
import type { RepositoryDetailResponse } from "../services/types";

function parseRepositoryId(pathname: string): number | null {
  const match = pathname.match(/^\/repositories\/(\d+)$/);
  if (!match) {
    return null;
  }

  const value = Number.parseInt(match[1] || "", 10);
  return Number.isFinite(value) ? value : null;
}

function parseRepositoryName(pathname: string): string | null {
  const match = pathname.match(/^\/repositories\/by-name\/(.+)$/);
  if (!match || !match[1]) {
    return null;
  }

  try {
    const decoded = decodeURIComponent(match[1]);
    return decoded.length > 0 ? decoded : null;
  } catch {
    return null;
  }
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

interface RepositoryDetailContentProps {
  data: RepositoryDetailResponse | null;
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

export function RepositoryDetailContent({ data, loading, error, retry }: RepositoryDetailContentProps) {
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
          <h2 className="mb-2 text-base font-semibold">Repository not found</h2>
          <p className="mb-4 text-slate-400">This repository does not exist or may have been removed.</p>
          <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500" onClick={() => navigate("/repositories")}>Back to Repositories</button>
        </section>
      )}

      {!loading && !error && data && (
        <section className="grid gap-4">
          <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="mt-0 text-xs font-semibold uppercase tracking-wide text-slate-400">Created at</p>
                <p className="mb-0 text-sm">{new Date(data.created_at).toLocaleString()}</p>
              </div>
              <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500" onClick={() => navigate("/repositories")}>Back to Repositories</button>
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
              <h3 className="mb-3 text-base font-semibold">Images in repository</h3>
              <ul className="m-0 list-none space-y-2 p-0">
                {data.images.map((image) => (
                  <li key={image.id} className="rounded-lg border border-slate-700/80 bg-slate-950/60 p-2">
                    <button type="button" className="text-blue-400 hover:text-blue-300 hover:underline" onClick={() => navigate(`/images/${image.id}`)}>
                      {image.name}
                    </button>{" "}
                    — {image.vulnerability_count} vulns ({image.critical_count} critical)
                  </li>
                ))}
              </ul>
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
                  <th className="pb-3 pr-4">Image</th>
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
                    <td className="py-3 pr-4">{item.image.name}</td>
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

export function RepositoryDetailPage() {
  const pathname = window.location.pathname;
  const id = parseRepositoryId(pathname);
  const repoName = parseRepositoryName(pathname);
  const identifier = id !== null ? { type: "id" as const, value: id } : repoName ? { type: "name" as const, value: repoName } : null;
  const { data, loading, error, retry } = useRepoDetail(identifier);

  return (
    <AppShell activeRoute="/repositories/:id" title={data?.name || "Repository Detail"} subtitle="Severity summary, images, and vulnerabilities for the selected repository.">
      <RepositoryDetailContent data={data} loading={loading} error={error} retry={retry} />
    </AppShell>
  );
}

import { useNavigate, useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useRepoDetail } from "../hooks/use-repo-detail";
import type { RepositoryDetailResponse } from "../services/types";

function parseRepositoryId(value: string | undefined): number | null {
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

interface RepositoryDetailContentProps {
  data: RepositoryDetailResponse | null;
  loading: boolean;
  error: string | null;
  retry: RetryHandler;
}

type ParsedImageRef = {
  registry: string;
  owner: string;
  region: string;
  image: string;
};

function parseImageReference(imageName: string): ParsedImageRef {
  const value = imageName.trim();
  if (!value) {
    return { registry: "Unknown", owner: "-", region: "-", image: imageName };
  }

  const ecrMatch = value.match(/^([^.]*)\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/(.+)$/i);
  if (ecrMatch) {
    const [, accountId, region, image] = ecrMatch;
    return { registry: "ECR", owner: accountId || "-", region: region || "-", image: image || "-" };
  }

  const slash = value.indexOf("/");
  const image = slash >= 0 ? value.slice(slash + 1) : value;

  return { registry: "Other", owner: "-", region: "-", image };
}

function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diffMs = Math.max(0, now - then);

  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;

  if (diffMs < hour) {
    const mins = Math.max(1, Math.floor(diffMs / minute));
    return `${mins}m ago`;
  }

  if (diffMs < day) {
    const hours = Math.max(1, Math.floor(diffMs / hour));
    return `${hours}h ago`;
  }

  const days = Math.max(1, Math.floor(diffMs / day));
  return `${days}d ago`;
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "rounded-full bg-red-950 px-2 py-0.5 text-xs font-bold text-red-200",
  HIGH: "rounded-full bg-orange-950 px-2 py-0.5 text-xs font-bold text-orange-200",
  MEDIUM: "rounded-full bg-yellow-950 px-2 py-0.5 text-xs font-bold text-yellow-200",
  LOW: "rounded-full bg-blue-950 px-2 py-0.5 text-xs font-bold text-blue-200",
  UNKNOWN: "rounded-full bg-gray-800 px-2 py-0.5 text-xs font-bold text-gray-300",
};

export function RepositoryDetailContent({ data, loading, error, retry }: RepositoryDetailContentProps) {
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
          <h2 className="mb-2 text-base font-semibold">Repository not found</h2>
          <p className="mb-4 text-slate-400">This repository does not exist or may have been removed.</p>
          <button
            type="button"
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500"
            onClick={() => void navigate({ to: "/repositories" })}
          >
            Back to Repositories
          </button>
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
              <button
                type="button"
                className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500"
                onClick={() => void navigate({ to: "/repositories" })}
              >
                Back to Repositories
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
            <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Package Coverage</h3>
              <div className="grid grid-cols-2 md:grid-cols-2 gap-3">
                <StatCard label="Packages Scanned" value={data.total_packages_scanned} tone="neutral" compact />
                <StatCard label="Clean Packages" value={data.total_clean_packages} tone="neutral" compact />
                <StatCard label="Vulnerable Packages" value={data.total_vulnerable_packages} tone="neutral" compact />
                <StatCard label="Clean Rate (%)" value={Math.round(data.clean_package_rate)} tone="neutral" compact />
              </div>
            </section>
          </section>

          <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
            <h3 className="mb-3 text-base font-semibold">Images in repository</h3>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-left text-slate-300">
                    <th className="py-2 pr-3 font-medium">Registry</th>
                    <th className="py-2 pr-3 font-medium">Owner</th>
                    <th className="py-2 pr-3 font-medium">Region</th>
                    <th className="py-2 pr-3 font-medium">Image</th>
                    <th className="py-2 pr-3 font-medium">Vulnerabilities</th>
                    <th className="py-2 pr-3 font-medium">Packages</th>
                    <th className="py-2 font-medium">Scanned</th>
                  </tr>
                </thead>
                <tbody>
                  {data.images.map((image) => {
                    const parsed = parseImageReference(image.name);

                    return (
                      <tr key={image.id} className="border-b border-slate-800/80 last:border-b-0">
                        <td className="py-2 pr-3 whitespace-nowrap">{parsed.registry}</td>
                        <td className="py-2 pr-3 whitespace-nowrap">{parsed.owner}</td>
                        <td className="py-2 pr-3 whitespace-nowrap">{parsed.region}</td>
                        <td className="py-2 pr-3">
                          <button
                            type="button"
                            className="block max-w-[320px] truncate text-blue-400 hover:text-blue-300 hover:underline"
                            title={image.name}
                            onClick={() => void navigate({ to: "/images/$id", params: { id: String(image.id) } })}
                          >
                            {parsed.image}
                          </button>
                        </td>
                        <td className="py-2 pr-3 whitespace-nowrap">
                          {image.vulnerability_count} total / {image.critical_count} critical
                        </td>
                        <td className="py-2 pr-3 whitespace-nowrap">
                          {image.package_count} total / {image.clean_package_count} clean / {image.vulnerable_package_count} vuln
                        </td>
                        <td className="py-2 whitespace-nowrap">{image.last_scanned_at ? formatRelativeTime(image.last_scanned_at) : "-"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
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
  const { id: rawId, repoName } = useParams({ strict: false }) as { id?: string; repoName?: string };
  const id = parseRepositoryId(rawId);
  const identifier = id !== null ? { type: "id" as const, value: id } : repoName ? { type: "name" as const, value: repoName } : null;
  const { data, loading, error, retry } = useRepoDetail(identifier);

  return (
    <AppShell activeRoute="/repositories/:id" title={data?.name || "Repository Detail"} subtitle="Severity summary, images, and vulnerabilities for the selected repository.">
      <RepositoryDetailContent data={data} loading={loading} error={error} retry={retry} />
    </AppShell>
  );
}

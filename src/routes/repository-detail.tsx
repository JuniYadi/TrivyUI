import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { CveDetailDrawer } from "../components/cve-detail-drawer";
import { ErrorBanner } from "../components/error-banner";
import { IgnoreVulnerabilityModal } from "../components/ignore-vulnerability-modal";
import { Pagination } from "../components/pagination";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useRepoDetail } from "../hooks/use-repo-detail";
import { createTrivyIgnoreRecord, fetchTrivyIgnores } from "../hooks/use-trivy-ignores";
import { fetchVulnerabilityDetail } from "../hooks/use-vulnerabilities";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { RepositoryDetailResponse, VulnerabilityDetailResponse, VulnerabilityWithRelations } from "../services/types";
import { filterVulnerabilitiesByGroup } from "../utils/filter-vulnerabilities-by-group";
import { applyIgnoreSubmitResult, openIgnoreModalState, submitIgnoreFlowAndRefresh } from "../utils/ignore-vulnerability-flow";
import { paginateList } from "../utils/paginate-list";

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
  state: VulnerabilityStateFilter;
  onStateChange: (next: VulnerabilityStateFilter) => void;
}

type VulnerabilityStateFilter = "open" | "done" | "all";

const STATE_FILTERS: VulnerabilityStateFilter[] = ["open", "done", "all"];

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

const STATE_STYLES: Record<string, string> = {
  open: "rounded-full bg-rose-950 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-rose-200",
  done: "rounded-full bg-emerald-950 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-emerald-200",
};

function formatScore(score: number | null): string {
  return score === null ? "-" : score.toFixed(1);
}

export function formatIgnoreDate(raw: string | null): string {
  if (!raw) {
    return "-";
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return raw;
  }

  return parsed.toLocaleString();
}

export function resolveIgnoreRuleStatus(expiresAt: string | null, nowMs: number = Date.now()): "Active" | "Expired" {
  if (!expiresAt) {
    return "Active";
  }

  const expiresMs = new Date(expiresAt).getTime();
  if (!Number.isFinite(expiresMs)) {
    return "Active";
  }

  return expiresMs < nowMs ? "Expired" : "Active";
}

export function formatIgnoreScopeAndTags(row: TrivyIgnoreRow): string {
  if (row.scope === "selected_tags") {
    const tags = row.tag_groups?.join(", ") || "";
    return tags ? `Selected: ${tags}` : "Selected tags";
  }

  return "All tags";
}

export function buildRepositoryIgnoreSummary(rows: TrivyIgnoreRow[], nowMs: number = Date.now()): {
  total: number;
  global: number;
  repository: number;
  active: number;
  expired: number;
} {
  let global = 0;
  let repository = 0;
  let active = 0;
  let expired = 0;

  for (const row of rows) {
    if (row.repository_id === null) {
      global += 1;
    } else {
      repository += 1;
    }

    const status = resolveIgnoreRuleStatus(row.expires_at, nowMs);
    if (status === "Active") {
      active += 1;
    } else {
      expired += 1;
    }
  }

  return {
    total: rows.length,
    global,
    repository,
    active,
    expired,
  };
}

interface RepositoryIgnoreTrackingPanelProps {
  items: TrivyIgnoreRow[];
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

export function RepositoryIgnoreTrackingPanel({ items, loading, error, onRetry }: RepositoryIgnoreTrackingPanelProps) {
  const summary = buildRepositoryIgnoreSummary(items);
  const hasRows = items.length > 0;

  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-base font-semibold">Trivy Ignore Tracking</h3>
        <a
          className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-blue-700"
          href="/trivy-ignore"
        >
          Manage Full
        </a>
      </div>
      <p className="mb-3 text-xs text-slate-400">Effective rules for this repo (Global + Repository).</p>

      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        <span className="rounded-full border border-slate-600 bg-slate-950 px-2 py-1 text-slate-200">Total: {summary.total}</span>
        <span className="rounded-full border border-slate-600 bg-slate-950 px-2 py-1 text-slate-200">Global: {summary.global}</span>
        <span className="rounded-full border border-slate-600 bg-slate-950 px-2 py-1 text-slate-200">Repository: {summary.repository}</span>
        <span className="rounded-full border border-emerald-700/60 bg-emerald-950/40 px-2 py-1 text-emerald-200">Active: {summary.active}</span>
        <span className="rounded-full border border-amber-700/60 bg-amber-950/40 px-2 py-1 text-amber-200">Expired: {summary.expired}</span>
      </div>

      {loading && !error && <p className="py-2 text-sm text-slate-400">Loading ignore rules...</p>}
      {error ? <ErrorBanner message={error} onRetry={onRetry} /> : null}
      {!loading && !error && !hasRows && (
        <p className="rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-300">
          No ignore rules currently affect this repository.
        </p>
      )}

      {!loading && !error && hasRows && (
        <section className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950/60">
          <table className="w-full table-fixed border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-left text-slate-300">
                <th className="w-[180px] px-3 py-2">CVE</th>
                <th className="w-[120px] px-3 py-2">Source</th>
                <th className="w-[220px] px-3 py-2">Scope / Tags</th>
                <th className="w-[170px] px-3 py-2">Reason</th>
                <th className="w-[160px] px-3 py-2">Expires</th>
                <th className="w-[160px] px-3 py-2">Created</th>
                <th className="w-[100px] px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => {
                const status = resolveIgnoreRuleStatus(row.expires_at);
                const expired = status === "Expired";

                return (
                  <tr key={row.id} className="border-b border-slate-800 last:border-0">
                    <td className="px-3 py-2">
                      <span className="block max-w-full truncate font-semibold" title={row.cve_id}>{row.cve_id}</span>
                    </td>
                    <td className="px-3 py-2">{row.repository_id === null ? "Global" : "Repository"}</td>
                    <td className="px-3 py-2">
                      <span className="block max-w-full truncate" title={formatIgnoreScopeAndTags(row)}>
                        {formatIgnoreScopeAndTags(row)}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className="block max-w-full truncate" title={row.reason || "-"}>
                        {row.reason || "-"}
                      </span>
                    </td>
                    <td className="px-3 py-2">{formatIgnoreDate(row.expires_at)}</td>
                    <td className="px-3 py-2">{formatIgnoreDate(row.created_at)}</td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          expired
                            ? "rounded-full bg-amber-950 px-2 py-0.5 text-xs font-bold text-amber-200"
                            : "rounded-full bg-emerald-950 px-2 py-0.5 text-xs font-bold text-emerald-200"
                        }
                      >
                        {status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </section>
  );
}

export function RepositoryDetailContent({ data, loading, error, retry, state, onStateChange }: RepositoryDetailContentProps) {
  const navigate = useNavigate();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detail, setDetail] = useState<VulnerabilityDetailResponse | null>(null);
  const [ignoreTarget, setIgnoreTarget] = useState<VulnerabilityWithRelations | null>(null);
  const [ignoreReason, setIgnoreReason] = useState("");
  const [ignoreExpiresAt, setIgnoreExpiresAt] = useState("");
  const [ignoreBusy, setIgnoreBusy] = useState(false);
  const [ignoreError, setIgnoreError] = useState<string | null>(null);
  const [ignoreNotice, setIgnoreNotice] = useState<string | null>(null);
  const [ignoreItems, setIgnoreItems] = useState<TrivyIgnoreRow[]>([]);
  const [ignoreLoading, setIgnoreLoading] = useState(false);
  const [ignoreLoadError, setIgnoreLoadError] = useState<string | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [vulnerabilityPage, setVulnerabilityPage] = useState(1);
  const [vulnerabilityLimit, setVulnerabilityLimit] = useState(10);
  const ignoreLoadRequestId = useRef(0);

  const openDetail = useCallback(async (id: number) => {
    setDrawerOpen(true);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);

    try {
      const result = await fetchVulnerabilityDetail(id);
      setDetail(result);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : "Failed to load vulnerability detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const groupSummary = useMemo(() => data?.group_summaries || [], [data?.group_summaries]);
  const filteredVulnerabilities = useMemo(() => {
    return filterVulnerabilitiesByGroup(data?.vulnerabilities || [], selectedGroup);
  }, [data?.vulnerabilities, selectedGroup]);

  const paginatedVulnerabilities = useMemo(() => {
    return paginateList(filteredVulnerabilities, vulnerabilityPage, vulnerabilityLimit);
  }, [filteredVulnerabilities, vulnerabilityLimit, vulnerabilityPage]);

  const refreshIgnores = useCallback(async (repositoryId: number | null | undefined) => {
    if (!repositoryId || repositoryId <= 0) {
      ignoreLoadRequestId.current += 1;
      setIgnoreItems([]);
      setIgnoreLoadError(null);
      setIgnoreLoading(false);
      return;
    }

    ignoreLoadRequestId.current += 1;
    const requestId = ignoreLoadRequestId.current;
    setIgnoreLoading(true);
    setIgnoreLoadError(null);

    try {
      const rows = await fetchTrivyIgnores(fetch, repositoryId);
      if (requestId === ignoreLoadRequestId.current) {
        setIgnoreItems(rows);
      }
    } catch (err) {
      if (requestId === ignoreLoadRequestId.current) {
        setIgnoreItems([]);
        setIgnoreLoadError(err instanceof Error ? err.message : "Failed to load repository ignores");
      }
    } finally {
      if (requestId === ignoreLoadRequestId.current) {
        setIgnoreLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    setVulnerabilityPage(1);
    setSelectedGroup(null);
  }, [data?.id]);

  useEffect(() => {
    setVulnerabilityPage(1);
  }, [selectedGroup]);

  useEffect(() => {
    void refreshIgnores(data?.id);
  }, [data?.id, refreshIgnores]);

  const onIgnoreRequest = useCallback((item: VulnerabilityWithRelations) => {
    const next = openIgnoreModalState({ item, previousNotice: ignoreNotice });
    setIgnoreTarget(next.target);
    setIgnoreReason(next.reason);
    setIgnoreExpiresAt(next.expiresAt);
    setIgnoreError(next.error);
    setIgnoreNotice(next.notice);
  }, [ignoreNotice]);

  const onCloseIgnoreModal = useCallback(() => {
    if (ignoreBusy) {
      return;
    }

    setIgnoreTarget(null);
    setIgnoreError(null);
  }, [ignoreBusy]);

  const onConfirmIgnore = useCallback(async () => {
    if (!ignoreTarget || ignoreBusy) {
      return;
    }

    setIgnoreBusy(true);
    setIgnoreError(null);

    try {
      const result = await submitIgnoreFlowAndRefresh({
        target: ignoreTarget,
        reason: ignoreReason,
        expiresAt: ignoreExpiresAt,
        createIgnore: (payload) => createTrivyIgnoreRecord(fetch, payload),
        refreshRepositoryIgnores: async (repositoryId) => {
          await refreshIgnores(repositoryId);
        },
      });

      const next = applyIgnoreSubmitResult({
        currentTarget: ignoreTarget,
        currentReason: ignoreReason,
        currentExpiresAt: ignoreExpiresAt,
        result,
      });
      setIgnoreNotice(next.notice);
      setIgnoreTarget(next.target);
      setIgnoreReason(next.reason);
      setIgnoreExpiresAt(next.expiresAt);
      setIgnoreError(next.error);
    } catch (error) {
      setIgnoreError(error instanceof Error ? error.message : "Failed to create ignore rule");
      setIgnoreNotice(null);
      setIgnoreTarget(ignoreTarget);
      setIgnoreReason(ignoreReason);
      setIgnoreExpiresAt(ignoreExpiresAt);
    } finally {
      setIgnoreBusy(false);
    }
  }, [ignoreTarget, ignoreBusy, ignoreReason, ignoreExpiresAt, refreshIgnores]);

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

          {groupSummary.length > 0 && (
            <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
              <h3 className="mb-3 text-base font-semibold">Tag Group Health</h3>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {groupSummary.map((group, index) => {
                  const groupName = group.group_name || "ungrouped";
                  const isSelected = selectedGroup === groupName;

                  return (
                  <button
                    key={`${groupName}-${index}`}
                    type="button"
                    className={
                      isSelected
                        ? "rounded-lg border border-blue-500 bg-blue-500/10 p-3 text-left"
                        : "rounded-lg border border-slate-700 bg-slate-950/60 p-3 text-left hover:border-slate-500"
                    }
                    onClick={() => setSelectedGroup((prev) => (prev === groupName ? null : groupName))}
                    title={isSelected ? "Clear tag group filter" : `Filter vulnerabilities by ${groupName}`}
                  >
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <p className={isSelected ? "m-0 text-sm font-semibold text-blue-300" : "m-0 text-sm font-semibold text-slate-100"}>{groupName}</p>
                      <span
                        className={
                          group.status === "at_risk"
                            ? "rounded-full bg-rose-950 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-rose-200"
                            : "rounded-full bg-emerald-950 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-emerald-200"
                        }
                      >
                        {group.status === "at_risk" ? "at risk" : "healthy"}
                      </span>
                    </div>
                    <p className="m-0 text-sm text-slate-300">Open vulnerabilities: {group.open_vulnerability_count}</p>
                    <p className="m-0 text-xs text-slate-400">
                      Last scan: {group.last_scan_at ? new Date(group.last_scan_at).toLocaleString() : "-"}
                    </p>
                  </button>
                  );
                })}
              </div>
            </section>
          )}

          <RepositoryIgnoreTrackingPanel
            items={ignoreItems}
            loading={ignoreLoading}
            error={ignoreLoadError}
            onRetry={() => {
              void refreshIgnores(data.id);
            }}
          />

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
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-base font-semibold">Vulnerabilities</h3>
              <div className="flex flex-wrap items-center gap-2">
                {STATE_FILTERS.map((item) => (
                  <button
                    key={item}
                    type="button"
                    className={
                      state === item
                        ? "rounded-full border border-blue-500 bg-blue-500/20 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-blue-200"
                        : "rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300 hover:border-slate-500"
                    }
                    onClick={() => onStateChange(item)}
                  >
                    {item}
                  </button>
                ))}
                {selectedGroup && (
                  <button
                    type="button"
                    className="rounded-full border border-blue-500/60 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-200"
                    onClick={() => setSelectedGroup(null)}
                  >
                    Group: {selectedGroup} x
                  </button>
                )}
              </div>
            </div>
            <p className="mb-3 text-xs text-slate-400">
              Showing {paginatedVulnerabilities.pagination.total_items} vulnerabilities{selectedGroup ? ` in group ${selectedGroup}` : ""}.
            </p>
            {ignoreNotice ? <p className="mb-3 rounded-lg border border-emerald-700/50 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-200">{ignoreNotice}</p> : null}
            <table className="w-full table-fixed border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-left">
                  <th className="pb-3 pr-4">CVE ID</th>
                  <th className="pb-3 pr-4">Severity</th>
                  <th className="pb-3 pr-4 w-[220px]">Package</th>
                  <th className="hidden md:table-cell pb-3 pr-4 w-[260px]">Image</th>
                  <th className="hidden md:table-cell pb-3 pr-4">Group</th>
                  <th className="hidden lg:table-cell pb-3 pr-4">State</th>
                  <th className="pb-3 pr-4">Installed</th>
                  <th className="hidden lg:table-cell pb-3 pr-4">Fixed</th>
                  <th className="pb-3 pr-4">Actions</th>
                  <th className="pb-3">Score</th>
                </tr>
              </thead>
              <tbody>
                {paginatedVulnerabilities.items.map((item) => (
                  <tr key={item.id} className="cursor-pointer border-b border-slate-800 last:border-0 hover:bg-slate-800/50" onClick={() => void openDetail(item.id)}>
                    <td className="py-3 pr-4">{item.cve_id}</td>
                    <td className="py-3 pr-4">
                      <span className={SEVERITY_STYLES[item.severity] || ""}>{item.severity}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className="block max-w-[220px] truncate" title={item.package_name}>
                        {item.package_name}
                      </span>
                    </td>
                    <td className="hidden md:table-cell py-3 pr-4">
                      <button
                        type="button"
                        className="block max-w-[260px] truncate text-blue-400 hover:text-blue-300 hover:underline"
                        title={item.image.name}
                        onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          void navigate({ to: "/images/$id", params: { id: String(item.image.id) } });
                        }}
                      >
                        {parseImageReference(item.image.name).image}
                      </button>
                    </td>
                    <td className="hidden md:table-cell py-3 pr-4">{item.tag_group || "ungrouped"}</td>
                    <td className="hidden lg:table-cell py-3 pr-4">
                      <span className={STATE_STYLES[item.state || ""] || "rounded-full bg-slate-800 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-slate-300"}>
                        {item.state || "-"}
                      </span>
                    </td>
                    <td className="py-3 pr-4">{item.installed_version || "-"}</td>
                    <td className="hidden lg:table-cell py-3 pr-4">{item.fixed_version || "-"}</td>
                    <td className="py-3 pr-4">
                      <button
                        type="button"
                        aria-label={`Ignore vulnerability ${item.cve_id} for ${item.repository.name}`}
                        className="rounded border border-red-700 bg-red-950/50 px-2 py-1 text-xs font-semibold text-red-200 transition hover:bg-red-900/70"
                        onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          onIgnoreRequest(item);
                        }}
                      >
                        Ignore
                      </button>
                    </td>
                    <td className="py-3">{formatScore(item.score)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <Pagination
              page={paginatedVulnerabilities.pagination.page}
              totalPages={paginatedVulnerabilities.pagination.total_pages}
              totalItems={paginatedVulnerabilities.pagination.total_items}
              limit={paginatedVulnerabilities.pagination.limit}
              onPageChange={(page) => setVulnerabilityPage(page)}
              onLimitChange={(limit) => {
                setVulnerabilityLimit(limit);
                setVulnerabilityPage(1);
              }}
            />
          </section>
        </section>
      )}

      <CveDetailDrawer
        open={drawerOpen}
        loading={detailLoading}
        error={detailError}
        data={detail}
        onClose={() => setDrawerOpen(false)}
      />

      <IgnoreVulnerabilityModal
        open={Boolean(ignoreTarget)}
        cveId={ignoreTarget?.cve_id || ""}
        repositoryName={ignoreTarget?.image.repository_name || ignoreTarget?.repository.name || "Unknown repository"}
        reason={ignoreReason}
        expiresAt={ignoreExpiresAt}
        busy={ignoreBusy}
        error={ignoreError}
        onReasonChange={setIgnoreReason}
        onExpiresAtChange={setIgnoreExpiresAt}
        onCancel={onCloseIgnoreModal}
        onConfirm={onConfirmIgnore}
      />
    </>
  );
}

export function RepositoryDetailPage() {
  const { id: rawId, repoName } = useParams({ strict: false }) as { id?: string; repoName?: string };
  const [state, setState] = useState<VulnerabilityStateFilter>("open");
  const id = parseRepositoryId(rawId);
  const identifier = id !== null ? { type: "id" as const, value: id } : repoName ? { type: "name" as const, value: repoName } : null;
  const { data, loading, error, retry } = useRepoDetail(identifier, state);

  return (
    <AppShell activeRoute="/repositories/:id" title={data?.name || "Repository Detail"} subtitle="Severity summary, images, and vulnerabilities for the selected repository.">
      <RepositoryDetailContent data={data} loading={loading} error={error} retry={retry} state={state} onStateChange={setState} />
    </AppShell>
  );
}

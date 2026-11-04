import { useEffect, useMemo, useState } from "react";
import { useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { Pagination } from "../components/pagination";
import {
  AppLink,
  ChipButton,
  Delta,
  FOCUS,
  LatestBadge,
  LinkButton,
  NotFoundCard,
  PageError,
  PageSkeleton,
  displayRepoName,
  formatDateTime,
  timeAgo,
  toBarCounts,
} from "../components/repo-ui";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";
import { SEVERITY, type SeverityKey } from "../components/ui/severity";
import { SeverityBar } from "../components/ui/severity-bar";
import { SeverityChip } from "../components/ui/severity-chip";
import { useRepoDetail, useRepoVulnerabilities } from "../hooks/use-repo-detail";
import { fetchTrivyIgnores } from "../hooks/use-trivy-ignores";
import type { RepoGroupHealth, RepoTagRow } from "../services/repo-state";
import type { RepoVulnerabilityPage, RepositoryDetail } from "../services/repo-page-types";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { TagGroupStatus } from "../services/tag-group-health";

function parseRepositoryId(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const id = Number.parseInt(value, 10);
  return Number.isFinite(id) ? id : null;
}

// ---------------------------------------------------------------------------
// Ignore rule summary (read-only; editing lives on /trivy-ignore)
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRY_WARNING_DAYS = 7;

export interface IgnoreRuleSummary {
  active: Array<TrivyIgnoreRow & { expiryLabel: string; expiringSoon: boolean }>;
  expiredCount: number;
}

export function summarizeIgnoreRules(rows: TrivyIgnoreRow[], now = Date.now()): IgnoreRuleSummary {
  const active: IgnoreRuleSummary["active"] = [];
  let expiredCount = 0;

  for (const row of rows) {
    if (!row.expires_at) {
      active.push({ ...row, expiryLabel: "no expiry", expiringSoon: false });
      continue;
    }
    const expires = Date.parse(row.expires_at);
    if (!Number.isFinite(expires)) {
      active.push({ ...row, expiryLabel: "no expiry", expiringSoon: false });
    } else if (expires <= now) {
      expiredCount += 1;
    } else {
      const days = Math.ceil((expires - now) / DAY_MS);
      active.push({ ...row, expiryLabel: `expires in ${days} ${days === 1 ? "day" : "days"}`, expiringSoon: days <= EXPIRY_WARNING_DAYS });
    }
  }

  active.sort((a, b) => Number(b.expiringSoon) - Number(a.expiringSoon));
  return { active, expiredCount };
}

// ---------------------------------------------------------------------------
// Presentational pieces
// ---------------------------------------------------------------------------

const TILE_ORDER: Array<{ key: SeverityKey; api: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" }> = [
  { key: "critical", api: "CRITICAL" },
  { key: "high", api: "HIGH" },
  { key: "medium", api: "MEDIUM" },
  { key: "low", api: "LOW" },
  { key: "unknown", api: "UNKNOWN" },
];

function SeverityTiles({ data }: { data: RepositoryDetail }) {
  return (
    <section aria-label="Severity summary" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {TILE_ORDER.map(({ key, api }) => (
        <Card key={key} className="flex items-center gap-3 !p-3">
          <SeverityChip severity={key} className="!h-8 !w-8 !text-sm" />
          <div className="min-w-0">
            <p className="text-2xl font-semibold leading-none tabular-nums">{data.by_severity[api]}</p>
            <p className="mt-1 truncate text-xs text-muted">
              {SEVERITY[key].label}
              {data.severity_change[api] !== null && (
                <>
                  {" · "}
                  <Delta value={data.severity_change[api]} />
                </>
              )}
            </p>
          </div>
        </Card>
      ))}
    </section>
  );
}

const STATUS_LABEL: Record<TagGroupStatus, string> = { improving: "Improving", at_risk: "At risk", critical: "Critical" };

export function StatusBadge({ status }: { status: TagGroupStatus }) {
  const style = status === "critical" ? { background: SEVERITY.critical.bg, color: SEVERITY.critical.fg } : undefined;
  const cls = status === "improving" ? "bg-success/15 text-success" : status === "at_risk" ? "bg-warning/15 text-warning" : "";
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cls}`} style={style}>
      {STATUS_LABEL[status]}
    </span>
  );
}

function GroupCard({ group, selected, onSelect }: { group: RepoGroupHealth; selected: boolean; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`min-h-11 rounded-xl border bg-card p-4 text-left transition ${FOCUS} ${selected ? "border-accent" : "border-line hover:border-accent/60"}`}
    >
      <span className="flex items-start justify-between gap-2">
        <span className="truncate text-base font-semibold">{group.group_name}</span>
        <StatusBadge status={group.status} />
      </span>
      <span className="mt-1 block text-xs text-fg2">
        Latest <Mono className="text-fg">{group.latest_tag ?? "-"}</Mono> {"·"} {group.tag_count} {group.tag_count === 1 ? "tag" : "tags"}
      </span>
      <SeverityBar counts={toBarCounts(group.by_severity)} className="my-3" />
      <span className="flex flex-wrap items-baseline justify-between gap-x-3 text-sm">
        <span>
          <strong className="tabular-nums">{group.open}</strong> open {"·"}{" "}
          <span style={{ color: SEVERITY.critical.fg }}>{group.critical} critical</span>
        </span>
        {group.change !== null && group.previous_tag && (
          <span className="text-xs">
            <Delta value={group.change} /> <span className="text-muted">vs <Mono>{group.previous_tag}</Mono></span>
          </span>
        )}
      </span>
    </button>
  );
}

export function filterTagsByGroup(tags: RepoTagRow[], group: string | null): RepoTagRow[] {
  return group ? tags.filter((tag) => tag.tag_group === group) : tags;
}

function TagsTable({ tags, group }: { tags: RepoTagRow[]; group: string | null }) {
  const rows = filterTagsByGroup(tags, group);
  return (
    <Card className="overflow-x-auto !p-0">
      <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 pt-4">
        <h3 className="text-base font-semibold">
          Tags <span className="font-normal text-fg2">{"·"} {group ?? "all groups"}</span>
        </h3>
        <p className="text-xs text-muted">Newest first {"·"} change vs previous tag in the same group</p>
      </div>
      <table className="mt-3 w-full min-w-[680px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-line text-left text-xs font-medium text-muted">
            <th scope="col" className="px-4 py-2">Tag</th>
            <th scope="col" className="px-4 py-2">Group</th>
            <th scope="col" className="px-4 py-2">Severity mix</th>
            <th scope="col" className="px-4 py-2 text-right">Open</th>
            <th scope="col" className="px-4 py-2 text-right">Change</th>
            <th scope="col" className="px-4 py-2 text-right">Fixable</th>
            <th scope="col" className="px-4 py-2 text-right">Scanned</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((tag) => (
            <tr key={tag.image_id} className="border-b border-rowline last:border-0">
              <td className="px-4 py-2">
                <AppLink href={`/images/${tag.image_id}`} className="inline-flex min-h-11 items-center gap-2 text-link hover:underline sm:min-h-9">
                  <Mono>{tag.tag ?? tag.name}</Mono>
                  {tag.is_latest && <LatestBadge />}
                </AppLink>
              </td>
              <td className="px-4 py-2 text-fg2">{tag.tag_group}</td>
              <td className="w-[220px] px-4 py-2">
                <SeverityBar counts={toBarCounts(tag.by_severity)} />
              </td>
              <td className="px-4 py-2 text-right font-semibold tabular-nums">{tag.open}</td>
              <td className="px-4 py-2 text-right">
                <Delta value={tag.change} />
              </td>
              <td className="px-4 py-2 text-right tabular-nums text-success">{tag.fixable}</td>
              <td className="px-4 py-2 text-right text-xs text-fg2" title={formatDateTime(tag.last_scanned_at)}>
                {timeAgo(tag.last_scanned_at)}
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={7} className="px-4 py-6 text-center text-muted">
                No tags in this group.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  );
}

function TopPackages({ data }: { data: RepositoryDetail }) {
  return (
    <Card>
      <h3 className="text-base font-semibold">Top packages{data.latest_tag ? ` in ${data.latest_tag.name}` : ""}</h3>
      {data.top_packages.length === 0 ? (
        <p className="mt-3 text-sm text-muted">No open vulnerabilities in the latest tag.</p>
      ) : (
        <ul className="mt-2">
          {data.top_packages.map((pkg) => (
            <li key={`${pkg.package_name}@${pkg.installed_version}`} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 border-b border-rowline py-2 text-sm last:border-0">
              <span>
                <strong>{pkg.package_name}</strong> <Mono className="text-xs text-muted">{pkg.installed_version ?? ""}</Mono>
              </span>
              <span className="text-xs text-fg2">
                {pkg.cve_count} {pkg.cve_count === 1 ? "CVE" : "CVEs"}
                {pkg.critical_count > 0 && ` · ${pkg.critical_count} critical`}
                {" → "}
                {pkg.fixed_version ? <Mono className="text-success">{pkg.fixed_version}</Mono> : <span className="text-muted">no fix yet</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function IgnoreRulesCard({ rules, failed }: { rules: TrivyIgnoreRow[] | null; failed: boolean }) {
  const summary = useMemo(() => summarizeIgnoreRules(rules ?? []), [rules]);
  return (
    <Card>
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-base font-semibold">Active ignore rules</h3>
        <AppLink href="/trivy-ignore" className="inline-flex min-h-11 items-center text-sm text-link hover:underline sm:min-h-0">
          Manage {"→"}
        </AppLink>
      </div>
      {failed ? (
        <p className="mt-3 text-sm text-muted">Ignore rules could not be loaded.</p>
      ) : rules === null ? (
        <p className="mt-3 text-sm text-muted">Loading rules...</p>
      ) : summary.active.length === 0 ? (
        <p className="mt-3 text-sm text-muted">No active ignore rules for this repository.</p>
      ) : (
        <ul className="mt-2 grid gap-2">
          {summary.active.slice(0, 4).map((rule) => (
            <li key={rule.id} className="rounded-lg border border-line p-3 text-sm">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <Mono className="font-semibold">{rule.cve_id}</Mono>
                <span className={`text-xs ${rule.expiringSoon ? "text-warning" : "text-muted"}`}>{rule.expiryLabel}</span>
              </div>
              <p className="mt-1 truncate text-xs text-fg2">
                {rule.scope === "all_tags" ? "All tags" : rule.tag_groups.join(", ") || "Selected tags"}
                {rule.reason ? ` · "${rule.reason}"` : ""}
              </p>
            </li>
          ))}
        </ul>
      )}
      {(summary.active.length > 4 || summary.expiredCount > 0) && (
        <p className="mt-2 text-xs text-muted">
          {summary.active.length > 4 ? `+${summary.active.length - 4} more active` : ""}
          {summary.active.length > 4 && summary.expiredCount > 0 ? " · " : ""}
          {summary.expiredCount > 0 ? `${summary.expiredCount} expired` : ""}
        </p>
      )}
    </Card>
  );
}

function VulnerabilityList({
  vulns,
  loading,
  error,
  group,
  page,
  limit,
  onPage,
  onLimit,
  repositoryName,
}: {
  vulns: RepoVulnerabilityPage | null;
  loading: boolean;
  error: string | null;
  group: string | null;
  page: number;
  limit: number;
  onPage: (page: number) => void;
  onLimit: (limit: number) => void;
  repositoryName: string;
}) {
  return (
    <section aria-label="Open vulnerabilities">
      <Card className="overflow-x-auto !p-0">
        <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 pt-4">
          <h3 className="text-base font-semibold">
            Open vulnerabilities <span className="font-normal text-fg2">{"·"} {group ?? "all groups"}</span>
          </h3>
          <p className="text-xs text-muted">Latest scan of each tag group</p>
        </div>
        {error ? (
          <p role="alert" className="px-4 py-6 text-sm text-fg2">{error}</p>
        ) : (
          <table className={`mt-3 w-full min-w-[720px] border-collapse text-sm ${loading ? "opacity-60" : ""}`}>
            <thead>
              <tr className="border-b border-line text-left text-xs font-medium text-muted">
                <th scope="col" className="px-4 py-2">CVE</th>
                <th scope="col" className="px-4 py-2">Package</th>
                <th scope="col" className="px-4 py-2">Installed {"→"} fixed</th>
                <th scope="col" className="px-4 py-2">Tag</th>
                <th scope="col" className="px-4 py-2 text-right">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {(vulns?.items ?? []).map((item) => (
                <tr key={item.id} className="border-b border-rowline last:border-0">
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-2">
                      <SeverityChip severity={item.severity} />
                      <a
                        href={`/vulnerabilities?search=${encodeURIComponent(item.cve_id)}&repository=${encodeURIComponent(repositoryName)}`}
                        className={`inline-flex min-h-11 items-center font-mono text-link hover:underline sm:min-h-9 ${FOCUS}`}
                      >
                        {item.cve_id}
                      </a>
                    </span>
                  </td>
                  <td className="px-4 py-2">{item.package_name}</td>
                  <td className="px-4 py-2">
                    <Mono className="text-fg2">{item.installed_version ?? "-"}</Mono> {"→"}{" "}
                    {item.fixed_version ? <Mono className="text-success">{item.fixed_version}</Mono> : <span className="text-muted">none</span>}
                  </td>
                  <td className="px-4 py-2 text-fg2">{item.tag_group}</td>
                  <td className="px-4 py-2 text-right text-xs text-fg2">{timeAgo(item.scanned_at)}</td>
                </tr>
              ))}
              {vulns && vulns.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-muted">
                    No open vulnerabilities.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </Card>
      {vulns && (
        <Pagination
          page={vulns.pagination.page}
          totalPages={vulns.pagination.total_pages}
          totalItems={vulns.pagination.total_items}
          limit={limit}
          onPageChange={onPage}
          onLimitChange={onLimit}
        />
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// View + container
// ---------------------------------------------------------------------------

export interface RepositoryDetailViewProps {
  data: RepositoryDetail;
  group: string | null;
  onGroupChange: (group: string | null) => void;
  rules: TrivyIgnoreRow[] | null;
  rulesFailed: boolean;
  vulns: RepoVulnerabilityPage | null;
  vulnsLoading: boolean;
  vulnsError: string | null;
  page: number;
  limit: number;
  onPage: (page: number) => void;
  onLimit: (limit: number) => void;
}

export function RepositoryDetailView(props: RepositoryDetailViewProps) {
  const { data, group, onGroupChange } = props;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-5">
      <SeverityTiles data={data} />

      <section aria-label="Tag group health" className="grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-base font-semibold">Tag group health</h2>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by tag group">
            <ChipButton active={group === null} onClick={() => onGroupChange(null)}>
              All groups
            </ChipButton>
            {data.tag_groups.map((g) => (
              <ChipButton key={g.group_name} active={group === g.group_name} onClick={() => onGroupChange(group === g.group_name ? null : g.group_name)}>
                {g.group_name} {"·"} {g.open}
              </ChipButton>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {data.tag_groups.map((g) => (
            <GroupCard key={g.group_name} group={g} selected={group === g.group_name} onSelect={() => onGroupChange(group === g.group_name ? null : g.group_name)} />
          ))}
        </div>
        {data.tag_groups.length === 0 && <Card className="text-sm text-muted">No scans yet for this repository.</Card>}
      </section>

      <TagsTable tags={data.tags} group={group} />

      <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-4 lg:grid-cols-[repeat(2,minmax(0,1fr))]">
        <TopPackages data={data} />
        <IgnoreRulesCard rules={props.rules} failed={props.rulesFailed} />
      </div>

      <VulnerabilityList
        vulns={props.vulns}
        loading={props.vulnsLoading}
        error={props.vulnsError}
        group={group}
        page={props.page}
        limit={props.limit}
        onPage={props.onPage}
        onLimit={props.onLimit}
        repositoryName={data.name}
      />
    </div>
  );
}

interface RepositoryDetailContentProps extends Partial<Omit<RepositoryDetailViewProps, "data">> {
  data: RepositoryDetail | null;
  loading: boolean;
  error: string | null;
  retry: () => void | Promise<void>;
}

export function RepositoryDetailContent({ data, loading, error, retry, ...rest }: RepositoryDetailContentProps) {
  if (loading && !data) {
    return <PageSkeleton />;
  }
  if (error) {
    return <PageError message={error} onRetry={retry} />;
  }
  if (!data) {
    return <NotFoundCard title="Repository not found" backTo="/repositories" backLabel="Back to Repositories" />;
  }

  return (
    <RepositoryDetailView
      data={data}
      group={rest.group ?? null}
      onGroupChange={rest.onGroupChange ?? (() => {})}
      rules={rest.rules ?? null}
      rulesFailed={rest.rulesFailed ?? false}
      vulns={rest.vulns ?? null}
      vulnsLoading={rest.vulnsLoading ?? false}
      vulnsError={rest.vulnsError ?? null}
      page={rest.page ?? 1}
      limit={rest.limit ?? 25}
      onPage={rest.onPage ?? (() => {})}
      onLimit={rest.onLimit ?? (() => {})}
    />
  );
}

export function RepositoryDetailPage() {
  const params = useParams({ strict: false }) as { id?: string; repoName?: string };
  const id = parseRepositoryId(params.id);
  const identifier = useMemo(() => {
    if (params.repoName) {
      return { type: "name" as const, value: params.repoName };
    }
    return id === null ? null : { type: "id" as const, value: id };
  }, [params.repoName, id]);

  const { data, loading, error, retry } = useRepoDetail(identifier);
  const [group, setGroup] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [rules, setRules] = useState<TrivyIgnoreRow[] | null>(null);
  const [rulesFailed, setRulesFailed] = useState(false);

  const repositoryId = data?.id ?? null;
  const vulns = useRepoVulnerabilities(repositoryId, group, page, limit);

  useEffect(() => {
    setGroup(null);
    setPage(1);
  }, [repositoryId]);

  useEffect(() => {
    if (repositoryId === null) {
      return;
    }
    let cancelled = false;
    setRules(null);
    setRulesFailed(false);
    fetchTrivyIgnores(fetch, repositoryId)
      .then((rows) => !cancelled && setRules(rows))
      .catch(() => !cancelled && setRulesFailed(true));
    return () => {
      cancelled = true;
    };
  }, [repositoryId]);

  const activeRules = summarizeIgnoreRules(rules ?? []).active.length;
  const name = data ? displayRepoName(data.name, data.registry) : "Repository";
  const meta = data
    ? [
        `${data.tag_groups.length} tag ${data.tag_groups.length === 1 ? "group" : "groups"}`,
        `${data.tag_count} ${data.tag_count === 1 ? "tag" : "tags"} scanned`,
        data.latest_tag ? `latest ${data.latest_tag.name}` : null,
        data.last_scanned_at ? timeAgo(data.last_scanned_at) : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : undefined;

  return (
    <AppShell
      activeRoute="/repositories/:id"
      title={name}
      meta={meta}
      breadcrumbs={[{ label: "Repositories", to: "/repositories" }, { label: name }]}
      actions={
        data && (
          <>
            <LinkButton href="/trivy-ignore">{`Ignore rules${rules ? ` (${activeRules})` : ""}`}</LinkButton>
            <a
              href={`/vulnerabilities?repository=${encodeURIComponent(data.name)}`}
              className={`inline-flex min-h-11 items-center justify-center rounded-lg bg-accent px-3 text-sm font-medium text-white hover:brightness-110 sm:min-h-9 ${FOCUS}`}
            >
              Open in explorer
            </a>
          </>
        )
      }
    >
      <RepositoryDetailContent
        data={data}
        loading={loading}
        error={error}
        retry={retry}
        group={group}
        onGroupChange={(next) => {
          setGroup(next);
          setPage(1);
        }}
        rules={rules}
        rulesFailed={rulesFailed}
        vulns={vulns.data}
        vulnsLoading={vulns.loading}
        vulnsError={vulns.error}
        page={page}
        limit={limit}
        onPage={setPage}
        onLimit={(next) => {
          setLimit(next);
          setPage(1);
        }}
      />
    </AppShell>
  );
}

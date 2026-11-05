import { useCallback, useMemo, useState } from "react";
import { useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { CveQuickPanel } from "../components/cve-quick-panel";
import { IgnoreVulnerabilityModal } from "../components/ignore-vulnerability-modal";
import { RepoIgnoreRules, RULE_PAGE_SIZE, type RepoIgnoreRulesProps } from "../components/repo-ignore-rules";
import { RepoTagsSection, TAG_PAGE_SIZE, type RepoTagsSectionProps } from "../components/repo-tags-section";
import { RepoVulnsSection, VULN_PAGE_SIZE, type RepoVulnsSectionProps } from "../components/repo-vulns-section";
import {
  Delta,
  FOCUS,
  LinkButton,
  NotFoundCard,
  PageError,
  PageSkeleton,
  displayRepoName,
  timeAgo,
  toBarCounts,
} from "../components/repo-ui";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";
import { SEVERITY, type SeverityKey } from "../components/ui/severity";
import { SeverityBar } from "../components/ui/severity-bar";
import { SeverityChip } from "../components/ui/severity-chip";
import { useCveSummary } from "../hooks/use-cve-detail";
import { useCveIgnore } from "../hooks/use-cve-ignore";
import { buildTrivyIgnoreAuthHeaders } from "../hooks/use-trivy-ignores";
import { useRepoCveStates, useRepoDetail, useRepoRules, useRepoTags, useRepoVulnerabilities } from "../hooks/use-repo-detail";
import { useUrlSearch } from "../hooks/use-url-search";
import type { RepoGroupHealth } from "../services/repo-state";
import type { RepositoryDetail } from "../services/repo-page-types";
import type { RepoRuleScopeFilter } from "../services/trivy-ignore-status";
import type { TagGroupStatus } from "../services/tag-group-health";

function parseRepositoryId(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const id = Number.parseInt(value, 10);
  return Number.isFinite(id) ? id : null;
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


// ---------------------------------------------------------------------------
// View + container
// ---------------------------------------------------------------------------

export interface RepositoryDetailViewProps {
  data: RepositoryDetail;
  group: string | null;
  onGroupChange: (group: string | null) => void;
  tags: Pick<RepoTagsSectionProps, "page" | "onPage" | "groupTags" | "onResetTag">;
  vulns: Omit<RepoVulnsSectionProps, "groups" | "group" | "onGroupChange">;
  rules: Omit<RepoIgnoreRulesProps, "repositoryId" | "repositoryName">;
}

export function RepositoryDetailView({ data, group, onGroupChange, tags, vulns, rules }: RepositoryDetailViewProps) {
  const toggleGroup = (name: string) => onGroupChange(group === name ? null : name);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-5">
      <SeverityTiles data={data} />

      <section aria-label="Tag group health" className="grid gap-3">
        <h2 className="text-base font-semibold">Tag group health</h2>
        <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {data.tag_groups.map((g) => (
            <GroupCard key={g.group_name} group={g} selected={group === g.group_name} onSelect={() => toggleGroup(g.group_name)} />
          ))}
        </div>
        {data.tag_groups.length === 0 && <Card className="text-sm text-muted">No scans yet for this repository.</Card>}
      </section>

      <RepoTagsSection tagGroups={data.tag_groups} latestTags={data.tags} group={group} onGroupChange={onGroupChange} {...tags} />

      <RepoVulnsSection {...vulns} groups={data.tag_groups.map((g) => g.group_name)} group={group} onGroupChange={onGroupChange} />

      <RepoIgnoreRules {...rules} repositoryId={data.id} repositoryName={data.name} />
    </div>
  );
}

interface RepositoryDetailContentProps {
  data: RepositoryDetail | null;
  loading: boolean;
  error: string | null;
  retry: () => void | Promise<void>;
  view: Omit<RepositoryDetailViewProps, "data">;
}

export function RepositoryDetailContent({ data, loading, error, retry, view }: RepositoryDetailContentProps) {
  if (loading && !data) {
    return <PageSkeleton />;
  }
  if (error) {
    return <PageError message={error} onRetry={retry} />;
  }
  if (!data) {
    return <NotFoundCard title="Repository not found" backTo="/repositories" backLabel="Back to Repositories" />;
  }

  return <RepositoryDetailView data={data} {...view} />;
}

const RULE_SCOPES: RepoRuleScopeFilter[] = ["all", "global", "repo"];

function positiveInt(value: string | null): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : 1;
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
  const { params: search, update } = useUrlSearch();
  const [reloadKey, setReloadKey] = useState(0);

  const repositoryId = data?.id ?? null;
  const groupParam = search.get("group");
  const group = data && groupParam && data.tag_groups.some((g) => g.group_name === groupParam) ? groupParam : null;
  const tagPage = positiveInt(search.get("tagPage"));
  const vulnPage = positiveInt(search.get("page"));
  const criticalHigh = search.get("crit") === "1";
  const fixable = search.get("fix") === "1";
  const rulesParam = search.get("rules") as RepoRuleScopeFilter | null;
  const ruleScope: RepoRuleScopeFilter = rulesParam && RULE_SCOPES.includes(rulesParam) ? rulesParam : "all";
  const rulePage = positiveInt(search.get("rulesPage"));
  const cve = search.get("cve");

  const groupTags = useRepoTags(repositoryId, group, tagPage, TAG_PAGE_SIZE, reloadKey);
  const vulns = useRepoVulnerabilities(repositoryId, { group, page: vulnPage, limit: VULN_PAGE_SIZE, criticalHigh, fixable }, reloadKey);
  const rules = useRepoRules(repositoryId, ruleScope, rulePage, RULE_PAGE_SIZE, reloadKey);

  const summary = useCveSummary(cve);
  const cveStates = useRepoCveStates(data?.name ?? null, cve, reloadKey);
  const ignore = useCveIgnore(() => setReloadKey((n) => n + 1));

  async function resetScans(path: string, message: string) {
    if (!window.confirm(message)) {
      return;
    }
    const response = await fetch(path, { method: "DELETE", headers: buildTrivyIgnoreAuthHeaders() });
    if (!response.ok) {
      window.alert(response.status === 401 ? "Reset failed: a valid API key is required." : "Reset failed.");
      return;
    }
    setReloadKey((n) => n + 1);
    retry();
  }

  const closePanel = useCallback(() => update({ cve: null }), [update]);

  const name = data ? displayRepoName(data.name, data.registry) : "Repository";
  const ruleCount = rules.data?.summary.total;
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

  const view: Omit<RepositoryDetailViewProps, "data"> = {
    group,
    onGroupChange: (next) => update({ group: next, tagPage: null, page: null }),
    tags: {
      page: tagPage,
      onPage: (page) => update({ tagPage: page > 1 ? page : null }),
      groupTags,
      onResetTag: (tag) => void resetScans(`/api/images/${tag.image_id}`, `Delete all scan data for ${tag.tag ?? tag.name}? Ignore rules are kept.`),
    },
    vulns: {
      vulns: vulns.data,
      loading: vulns.loading,
      error: vulns.error,
      criticalHigh,
      onCriticalHigh: (value) => update({ crit: value ? "1" : null, page: null }),
      fixable,
      onFixable: (value) => update({ fix: value ? "1" : null, page: null }),
      page: vulnPage,
      onPage: (page) => update({ page: page > 1 ? page : null }),
      selectedCve: cve,
      onOpenCve: (cveId) => update({ cve: cveId }, "push"),
    },
    rules: {
      data: rules.data,
      loading: rules.loading,
      error: rules.error,
      scope: ruleScope,
      onScope: (scope) => update({ rules: scope === "all" ? null : scope, rulesPage: null }),
      page: rulePage,
      onPage: (page) => update({ rulesPage: page > 1 ? page : null }),
      onChanged: () => setReloadKey((n) => n + 1),
    },
  };

  return (
    <AppShell
      activeRoute="/repositories/:id"
      title={name}
      meta={meta}
      breadcrumbs={[{ label: "Repositories", to: "/repositories" }, { label: name }]}
      actions={
        data && (
          <>
            <LinkButton href={`/trivy-ignore?repository=${encodeURIComponent(data.name)}`}>{`Ignore rules${ruleCount === undefined ? "" : ` (${ruleCount})`}`}</LinkButton>
            <button
              type="button"
              onClick={() => void resetScans(`/api/repositories/${data.id}/scans`, `Reset ${name}? All scans and findings for every tag are deleted. Ignore rules are kept.`)}
              className={`inline-flex min-h-11 items-center justify-center rounded-lg border border-line px-3 text-sm font-medium text-red-300 hover:bg-bg sm:min-h-9 ${FOCUS}`}
            >
              Reset
            </button>
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
      {ignore.notice && (
        <p role="status" className="mb-3 rounded-lg border border-success/40 bg-success/10 px-3 py-2 text-sm text-success">
          {ignore.notice}
        </p>
      )}
      <RepositoryDetailContent data={data} loading={loading} error={error} retry={retry} view={view} />

      {data && cve && (
        <CveQuickPanel
          cveId={cve}
          data={summary.data}
          loading={summary.loading}
          error={summary.error}
          onClose={closePanel}
          onIgnore={(cveId) =>
            ignore.open({
              cveIds: [cveId],
              repositories: [{ id: data.id, name: data.name }],
              tagGroup: group ?? undefined,
              tagGroupOptions: data.tag_groups.map((g) => g.group_name),
            })
          }
          repoScope={{
            name,
            states: cveStates.data?.cve_id === cve ? (cveStates.data.items[0]?.tags ?? []) : null,
            loading: cveStates.data?.cve_id !== cve && !cveStates.error,
            error: cveStates.error,
          }}
        />
      )}
      <IgnoreVulnerabilityModal {...ignore.modalProps} />
    </AppShell>
  );
}

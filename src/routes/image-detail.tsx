import { useCallback, useState } from "react";
import { useParams } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { Pagination } from "../components/pagination";
import {
  AppLink,
  ChipButton,
  FOCUS,
  LinkButton,
  NotFoundCard,
  PageError,
  PageSkeleton,
  SearchBox,
  displayRepoName,
  formatDateTime,
  repoHref,
  timeAgo,
  toBarCounts,
} from "../components/repo-ui";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";
import { SEVERITY, type SeverityKey } from "../components/ui/severity";
import { SeverityBar } from "../components/ui/severity-bar";
import { SeverityChip } from "../components/ui/severity-chip";
import { DEFAULT_IMAGE_DETAIL_QUERY, useImageDetail, type ImageDetailQuery } from "../hooks/use-image-detail";
import type { ImageDetailData, ImageDetailVulnerability } from "../services/repo-page-types";

function parseImageId(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const id = Number.parseInt(value, 10);
  return Number.isFinite(id) ? id : null;
}

export interface PackageGroup {
  key: string;
  package_name: string;
  installed_version: string | null;
  fix: string | null;
  items: ImageDetailVulnerability[];
}

/** Groups consecutive rows of the same package+version (the API already orders them that way). */
export function groupByPackage(items: ImageDetailVulnerability[]): PackageGroup[] {
  const groups: PackageGroup[] = [];
  for (const item of items) {
    const key = `${item.package_name}\u0000${item.installed_version ?? ""}`;
    let group = groups[groups.length - 1];
    if (!group || group.key !== key) {
      group = { key, package_name: item.package_name, installed_version: item.installed_version, fix: null, items: [] };
      groups.push(group);
    }
    group.items.push(item);
  }

  for (const group of groups) {
    const fixes = group.items.flatMap((item) => (item.fixed_version ?? "").split(",").map((part) => part.trim()).filter(Boolean));
    group.fix = fixes.sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).pop() ?? null;
  }
  return groups;
}

const SEVERITY_FILTERS: Array<{ key: SeverityKey; api: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }> = [
  { key: "critical", api: "CRITICAL" },
  { key: "high", api: "HIGH" },
  { key: "medium", api: "MEDIUM" },
  { key: "low", api: "LOW" },
];

function Summary({ data }: { data: ImageDetailData }) {
  return (
    <Card>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        <div className="rounded-lg bg-bg p-3">
          <p className="text-xs text-muted">Total</p>
          <p className="text-2xl font-semibold tabular-nums">{data.open}</p>
        </div>
        {SEVERITY_FILTERS.map(({ key, api }) => (
          <div key={key} className="rounded-lg p-3" style={{ background: SEVERITY[key].bg, color: SEVERITY[key].fg }}>
            <p className="text-xs">{SEVERITY[key].label}</p>
            <p className="text-2xl font-semibold tabular-nums">{data.by_severity[api]}</p>
          </div>
        ))}
      </div>
      <SeverityBar counts={toBarCounts(data.by_severity)} className="mt-3" />
      <p className="mt-2 text-xs text-muted">Unknown severity: {data.by_severity.UNKNOWN}</p>
    </Card>
  );
}

function Metadata({ data }: { data: ImageDetailData }) {
  const rows: Array<[string, React.ReactNode]> = [
    ["OS", data.os ?? "—"],
    ["Digest", data.digest ? <Mono className="whitespace-normal break-all">{data.digest}</Mono> : "—"],
    ["Scanned", formatDateTime(data.last_scanned_at)],
    ["Created", formatDateTime(data.created_at)],
    [
      "Repository",
      <AppLink key="repo" href={repoHref(data.repository.name)} className="inline-flex min-h-11 items-center break-all text-link hover:underline sm:min-h-0">
        {data.repository.name}
      </AppLink>,
    ],
  ];
  return (
    <Card>
      <h2 className="text-xs font-semibold uppercase tracking-wider text-muted">Metadata</h2>
      <dl className="mt-2 grid grid-cols-[84px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-fg2">{label}</dt>
            <dd className="min-w-0 break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

export interface ImageDetailExtras {
  query: ImageDetailQuery;
  onQueryChange: (patch: Partial<ImageDetailQuery>) => void;
}

function VulnerabilityGroups({ data, query, onQueryChange, loading }: ImageDetailExtras & { data: ImageDetailData; loading: boolean }) {
  const groups = groupByPackage(data.items);
  const { pagination } = data;
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox label="image-vulns" value={query.search} onSearch={(search) => onQueryChange({ search, page: 1 })} placeholder="CVE or package" />
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by severity">
          {SEVERITY_FILTERS.map(({ key, api }) => (
            <ChipButton key={key} active={query.severity === api} onClick={() => onQueryChange({ severity: query.severity === api ? null : api, page: 1 })}>
              {SEVERITY[key].label} {data.by_severity[api]}
            </ChipButton>
          ))}
          <label className={`inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border border-line bg-card px-3 text-sm text-fg2 sm:min-h-9 ${FOCUS}`}>
            <input type="checkbox" checked={query.fixable} onChange={(event) => onQueryChange({ fixable: event.target.checked, page: 1 })} className="h-4 w-4 accent-[#4c8dff]" />
            Fix available
          </label>
        </div>
      </div>

      <Card className={`!p-0 ${loading ? "opacity-60" : ""}`}>
        <p className="border-b border-line px-4 py-3 text-xs text-fg2">
          {data.items.length} of {pagination.total_items} vulnerabilities in {groups.length} {groups.length === 1 ? "package" : "packages"} on this page, grouped by package, worst first
        </p>
        {groups.length === 0 && <p className="px-4 py-6 text-center text-sm text-muted">No vulnerabilities match.</p>}
        {groups.map((group) => (
          <section key={group.key} aria-label={`${group.package_name} ${group.installed_version ?? ""}`} className="border-b border-rowline last:border-0">
            <header className="flex flex-wrap items-baseline justify-between gap-x-4 bg-bg/40 px-4 py-2 text-sm">
              <span>
                <strong>{group.package_name}</strong> <Mono className="text-xs text-muted">{group.installed_version ?? ""}</Mono>
              </span>
              {group.fix ? <Mono className="text-xs text-success">fix: {group.fix}</Mono> : <Mono className="text-xs text-muted">no fix available</Mono>}
            </header>
            <ul>
              {group.items.map((item) => (
                <li key={item.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-rowline px-4 py-2 text-sm">
                  <SeverityChip severity={item.severity} />
                  <a
                    href={`/vulnerabilities/${encodeURIComponent(item.cve_id)}`}
                    className={`inline-flex min-h-11 min-w-[9.5rem] items-center font-mono text-link hover:underline sm:min-h-9 ${FOCUS}`}
                  >
                    {item.cve_id}
                  </a>
                  <span className="text-xs">
                    <Mono className="text-fg2">{item.installed_version ?? "-"}</Mono> {"→"}{" "}
                    {item.fixed_version ? <Mono className="text-success">{item.fixed_version}</Mono> : <Mono className="text-muted">none</Mono>}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </Card>

      <Pagination
        page={pagination.page}
        totalPages={pagination.total_pages}
        totalItems={pagination.total_items}
        limit={pagination.limit}
        onPageChange={(page) => onQueryChange({ page })}
        onLimitChange={(limit) => onQueryChange({ limit, page: 1 })}
      />
    </div>
  );
}

interface ImageDetailContentProps extends Partial<ImageDetailExtras> {
  data: ImageDetailData | null;
  loading: boolean;
  error: string | null;
  retry: () => void | Promise<void>;
}

export function ImageDetailContent({ data, loading, error, retry, query = DEFAULT_IMAGE_DETAIL_QUERY, onQueryChange = () => {} }: ImageDetailContentProps) {
  if (loading && !data) {
    return <PageSkeleton />;
  }
  if (error) {
    return <PageError message={error} onRetry={retry} />;
  }
  if (!data) {
    return <NotFoundCard title="Image not found" backTo="/images" backLabel="Back to Images" />;
  }

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-4">
      <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Summary data={data} />
        <Metadata data={data} />
      </div>
      <VulnerabilityGroups data={data} query={query} onQueryChange={onQueryChange} loading={loading} />
    </div>
  );
}

export function ImageDetailPage() {
  const { id: rawId } = useParams({ strict: false }) as { id?: string };
  const id = parseImageId(rawId);
  const [query, setQuery] = useState<ImageDetailQuery>(DEFAULT_IMAGE_DETAIL_QUERY);
  const { data, loading, error, retry } = useImageDetail(id, query);
  const onQueryChange = useCallback((patch: Partial<ImageDetailQuery>) => setQuery((prev) => ({ ...prev, ...patch })), []);

  const tag = data ? (data.tag ?? data.name) : "Image";
  const repoLabel = data ? displayRepoName(data.repository.name, data.repository.registry) : "";
  const meta = data
    ? [
        `${data.open} open`,
        `${data.fixable} fixable`,
        data.change ? `${data.change.open > 0 ? "+" : data.change.open < 0 ? "−" : ""}${Math.abs(data.change.open)} vs ${data.change.previous_tag ?? "previous tag"}` : null,
        timeAgo(data.last_scanned_at),
      ]
        .filter(Boolean)
        .join(" · ")
    : undefined;

  return (
    <AppShell
      activeRoute="/images/:id"
      title={data?.name ?? "Image detail"}
      meta={meta}
      breadcrumbs={data ? [{ label: "Repositories", to: "/repositories" }, { label: repoLabel, to: repoHref(data.repository.name) }, { label: tag }] : undefined}
      actions={
        <>
          <LinkButton href="/images">Back to images</LinkButton>
          {data && <LinkButton href={repoHref(data.repository.name)}>Open repository</LinkButton>}
        </>
      }
    >
      <ImageDetailContent data={data} loading={loading} error={error} retry={retry} query={query} onQueryChange={onQueryChange} />
    </AppShell>
  );
}

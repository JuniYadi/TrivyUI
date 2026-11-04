import { ChipButton, FOCUS } from "./repo-ui";
import { Pagination } from "./pagination";
import { Card } from "./ui/card";
import { Mono } from "./ui/mono";
import { SEVERITY, toSeverityKey } from "./ui/severity";
import { SeverityChip } from "./ui/severity-chip";
import type { RepoVulnerabilityPage } from "../services/repo-page-types";

export const VULN_PAGE_SIZE = 10;

export interface RepoVulnsSectionProps {
  vulns: RepoVulnerabilityPage | null;
  loading: boolean;
  error: string | null;
  groups: string[];
  group: string | null;
  onGroupChange: (group: string | null) => void;
  criticalHigh: boolean;
  onCriticalHigh: (value: boolean) => void;
  fixable: boolean;
  onFixable: (value: boolean) => void;
  page: number;
  onPage: (page: number) => void;
  /** CVE id of the open side panel, highlighted in the list. */
  selectedCve: string | null;
  onOpenCve: (cveId: string) => void;
}

export function RepoVulnsSection(props: RepoVulnsSectionProps) {
  const { vulns, loading, error, groups, group, selectedCve } = props;

  return (
    <section aria-label="Open vulnerabilities">
      <Card className="!p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
          <h3 className="text-base font-semibold">
            Vulnerabilities in latest tags <span className="font-normal text-fg2">{"·"} click a row for details here</span>
          </h3>
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Vulnerability filters">
            <select
              aria-label="Tag group"
              value={group ?? ""}
              onChange={(event) => props.onGroupChange(event.target.value || null)}
              className={`min-h-11 rounded-lg border border-line bg-card px-2 text-sm text-fg sm:min-h-9 ${FOCUS}`}
            >
              <option value="">All groups</option>
              {groups.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <ChipButton active={props.criticalHigh} onClick={() => props.onCriticalHigh(!props.criticalHigh)}>
              Critical + High
            </ChipButton>
            <ChipButton active={props.fixable} onClick={() => props.onFixable(!props.fixable)}>
              Fix available
            </ChipButton>
          </div>
        </div>

        {error ? (
          <p role="alert" className="border-t border-rowline px-4 py-6 text-sm text-fg2">{error}</p>
        ) : (
          <ul className={`m-0 list-none p-0 ${loading ? "opacity-60" : ""}`} aria-busy={loading}>
            {(vulns?.items ?? []).map((item) => {
              const selected = selectedCve === item.cve_id;
              return (
                <li key={item.id} className="border-t border-rowline">
                  <button
                    type="button"
                    aria-haspopup="dialog"
                    aria-current={selected ? "true" : undefined}
                    onClick={() => props.onOpenCve(item.cve_id)}
                    className={`grid min-h-14 w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 px-4 py-2 text-left hover:bg-bg sm:grid-cols-[auto_minmax(0,1fr)_8rem_13rem_3rem] ${FOCUS} ${selected ? "bg-accent/10" : ""}`}
                  >
                    <SeverityChip severity={item.severity} />
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-sm text-link">{item.cve_id}</span>
                      <span className="block truncate text-sm font-medium">{item.package_name}</span>
                    </span>
                    <span className="hidden truncate text-sm text-fg2 sm:block">{item.tag_group}</span>
                    <span className="hidden text-xs sm:block">
                      <Mono className="text-fg2">{item.installed_version ?? "-"}</Mono> {"→"}{" "}
                      {item.fixed_version ? <Mono className="text-success">{item.fixed_version}</Mono> : <span className="text-muted">no fix</span>}
                    </span>
                    <span className="text-right text-sm font-semibold tabular-nums" style={{ color: SEVERITY[toSeverityKey(item.severity)].fg }}>
                      {item.score === null ? "-" : item.score.toFixed(1)}
                    </span>
                  </button>
                </li>
              );
            })}
            {vulns && vulns.items.length === 0 && <li className="border-t border-rowline px-4 py-6 text-center text-sm text-muted">No open vulnerabilities match.</li>}
          </ul>
        )}

        {vulns && (
          <Pagination
            embedded
            noun="vulnerabilities"
            page={vulns.pagination.page}
            totalPages={vulns.pagination.total_pages}
            totalItems={vulns.pagination.total_items}
            limit={VULN_PAGE_SIZE}
            onPageChange={props.onPage}
          />
        )}
        <p className="m-0 border-t border-rowline px-4 py-2 text-xs text-muted">Latest scan of each tag group {"·"} sorted by CVSS</p>
      </Card>
    </section>
  );
}

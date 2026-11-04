import { useState } from "react";
import { AppLink, FOCUS } from "./repo-ui";
import { Pagination } from "./pagination";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Mono } from "./ui/mono";
import { deleteTrivyIgnoreRecord, stopIgnoringRecords } from "../hooks/use-trivy-ignores";
import type { RepoRuleRow, RepoRuleScopeFilter, RepoRulesResult, RepoRulesSummary } from "../services/trivy-ignore-status";

export const RULE_PAGE_SIZE = 5;
const DAY_MS = 24 * 60 * 60 * 1000;

export function ruleStatusLabel(rule: Pick<RepoRuleRow, "status" | "suppressed" | "fixed_from_tag">): { label: string; className: string } {
  switch (rule.status) {
    case "still_present":
      return { label: rule.suppressed ? "Still present (suppressed)" : "Still present", className: "text-warning" };
    case "fixed":
      return { label: `Fixed here: gone from ${rule.fixed_from_tag ?? "latest tag"}`, className: "text-success" };
    case "unknown":
      return { label: "Unknown: scan without --show-suppressed", className: "text-fg2" };
    case "not_found":
      return { label: "Not found in this repo", className: "text-muted" };
    default:
      return { label: "No scan since rule was created", className: "text-muted" };
  }
}

export function ruleExpiryLabel(expiresAt: string | null, now = Date.now()): { label: string; soon: boolean } {
  const expires = expiresAt ? Date.parse(expiresAt) : Number.NaN;
  if (!Number.isFinite(expires)) return { label: "no expiry", soon: false };
  if (expires <= now) return { label: "expired", soon: false };
  const days = Math.ceil((expires - now) / DAY_MS);
  return { label: `in ${days} ${days === 1 ? "day" : "days"}`, soon: days <= 7 };
}

export function summaryLine(summary: RepoRulesSummary): string {
  return `${summary.total} ${summary.total === 1 ? "rule applies" : "rules apply"} here: ${summary.global} global + ${summary.repo} for this repository · ${summary.fixed} fixed here · ${summary.unknown} unknown`;
}

const TABS: Array<{ key: RepoRuleScopeFilter; label: string; count: (s: RepoRulesSummary) => number }> = [
  { key: "all", label: "All", count: (s) => s.total },
  { key: "global", label: "Global", count: (s) => s.global },
  { key: "repo", label: "This repo", count: (s) => s.repo },
];

const ROW_GRID = "grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 md:grid-cols-[minmax(0,1.6fr)_5rem_minmax(0,1.4fr)_6rem_9.5rem] md:items-center";

export interface RepoIgnoreRulesProps {
  repositoryId: number;
  repositoryName: string;
  data: RepoRulesResult | null;
  loading: boolean;
  error: string | null;
  scope: RepoRuleScopeFilter;
  onScope: (scope: RepoRuleScopeFilter) => void;
  page: number;
  onPage: (page: number) => void;
  /** Called after a rule was changed so the list (and counts) reload. */
  onChanged: () => void;
}

export function RepoIgnoreRules({ repositoryId, repositoryName, data, loading, error, scope, onScope, page, onPage, onChanged }: RepoIgnoreRulesProps) {
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const act = async (rule: RepoRuleRow) => {
    const global = rule.repository_id === null;
    const question = global
      ? `Stop ignoring ${rule.cve_id} in ${repositoryName}? The rule stays for all other repositories.`
      : `Delete the ${rule.cve_id} rule for ${repositoryName}?`;
    if (!window.confirm(question)) return;
    setBusyId(rule.id);
    setActionError(null);
    try {
      if (global) await stopIgnoringRecords(fetch, [rule.id], [repositoryId]);
      else await deleteTrivyIgnoreRecord(fetch, rule.id);
      onChanged();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to update the rule");
    } finally {
      setBusyId(null);
    }
  };

  const summary = data?.summary;

  return (
    <section aria-label="Ignore rules for this repository">
      <Card className="!p-0">
        <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
          <div className="min-w-0">
            <h3 className="m-0 truncate text-base font-semibold" title={repositoryName}>
              Ignore rules for {repositoryName}
            </h3>
            <p className="m-0 mt-0.5 text-xs text-fg2">{summary ? summaryLine(summary) : loading ? "Loading rules..." : ""}</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div role="tablist" aria-label="Rule scope" className="inline-flex rounded-lg border border-line bg-bg p-0.5">
              {TABS.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  role="tab"
                  aria-selected={scope === tab.key}
                  onClick={() => onScope(tab.key)}
                  className={`min-h-11 rounded-md px-3 text-sm font-medium sm:min-h-8 ${FOCUS} ${scope === tab.key ? "bg-card text-fg" : "text-fg2 hover:text-fg"}`}
                >
                  {tab.label}
                  {summary ? ` ${tab.count(summary)}` : ""}
                </button>
              ))}
            </div>
            <AppLink href={`/trivy-ignore?repository=${encodeURIComponent(repositoryName)}`} className="inline-flex min-h-11 items-center text-sm text-link hover:underline sm:min-h-9">
              Open in Ignore rules {"→"}
            </AppLink>
          </div>
        </div>

        {error && <p role="alert" className="border-t border-rowline px-4 py-6 text-sm text-fg2">{error}</p>}
        {actionError && <p role="alert" className="border-t border-rowline px-4 py-2 text-sm text-warning">{actionError}</p>}

        {!error && data && data.items.length === 0 && (
          <p className="border-t border-rowline px-4 py-6 text-center text-sm text-muted">
            {summary && summary.total > 0 ? "No rules in this tab." : "No ignore rules apply to this repository."}
          </p>
        )}

        {!error && data && data.items.length > 0 && (
          <div className={loading ? "opacity-60" : ""}>
            <div className={`${ROW_GRID} hidden border-t border-line px-4 py-2 text-xs font-medium text-muted md:grid`}>
              <span>Rule</span>
              <span>Scope</span>
              <span>Status in this repo</span>
              <span>Expires</span>
              <span />
            </div>
            <ul className="m-0 list-none p-0">
              {data.items.map((rule) => {
                const status = ruleStatusLabel(rule);
                const expiry = ruleExpiryLabel(rule.expires_at);
                const global = rule.repository_id === null;
                return (
                  <li key={rule.id} className={`${ROW_GRID} border-t border-rowline px-4 py-3`}>
                    <span className="min-w-0">
                      <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                        <Mono className="font-semibold">{rule.cve_id}</Mono>
                        {rule.package_name && <strong className="truncate text-sm">{rule.package_name}</strong>}
                      </span>
                      {rule.reason && <span className="block truncate text-xs text-fg2" title={rule.reason}>{`"${rule.reason}"`}</span>}
                    </span>
                    <span className="row-start-1 col-start-2 justify-self-end md:col-start-auto md:row-start-auto md:justify-self-start">
                      <span className={`rounded px-1.5 py-0.5 text-[11px] font-bold uppercase tracking-wide ${global ? "bg-purple-500/15 text-purple-400" : "bg-accent/15 text-link"}`}>
                        {global ? "Global" : "This repo"}
                      </span>
                    </span>
                    <span className={`text-sm ${status.className}`}>{status.label}</span>
                    <span className={`text-sm ${expiry.soon ? "text-warning" : "text-fg2"}`}>{expiry.label}</span>
                    <span className="md:justify-self-end">
                      <Button className="min-h-11 md:min-h-9" disabled={busyId === rule.id} onClick={() => void act(rule)}>
                        {global ? "Stop ignoring here" : "Delete rule"}
                      </Button>
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {data && (
          <Pagination
            embedded
            noun="rules"
            page={data.pagination.page}
            totalPages={data.pagination.total_pages}
            totalItems={data.pagination.total_items}
            limit={RULE_PAGE_SIZE}
            onPageChange={onPage}
          />
        )}
      </Card>
    </section>
  );
}

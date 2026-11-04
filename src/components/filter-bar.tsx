import { useEffect, useState } from "react";
import type { Severity } from "../services/types";
import type { VulnerabilityQueryParams } from "../hooks/use-vulnerabilities";
import { SEVERITY, toSeverityKey } from "./ui/severity";

interface FilterBarProps {
  query: VulnerabilityQueryParams;
  repositories: string[];
  images: string[];
  /** Unique-CVE counts per severity (grouped mode). Omitted in per-finding mode. */
  severityCounts?: Partial<Record<Severity, number>>;
  onChange: (patch: Partial<VulnerabilityQueryParams>) => void;
  onClear: () => void;
}

const SEVERITY_OPTIONS: Array<Severity> = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const FIELD =
  "min-h-11 rounded-lg border border-line bg-card px-3 text-sm text-fg placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent md:min-h-9";

export function FilterBar({ query, repositories, images, severityCounts, onChange, onClear }: FilterBarProps) {
  const [searchInput, setSearchInput] = useState(query.search || "");
  const [moreOpen, setMoreOpen] = useState(false);

  useEffect(() => {
    setSearchInput(query.search || "");
  }, [query.search]);

  useEffect(() => {
    if ((query.search || "") === searchInput) return;
    const timer = window.setTimeout(() => {
      onChange({ search: searchInput || undefined, page: 1 });
    }, 300);

    return () => window.clearTimeout(timer);
  }, [searchInput, query.search, onChange]);

  const toggleSeverity = (severity: Severity) => onChange({ severity: query.severity === severity ? undefined : severity, page: 1 });
  const fixOn = Boolean(query.fixAvailable);

  const selects = (
    <>
      <label className="flex items-center gap-2 text-sm text-muted">
        <span className="sr-only md:not-sr-only">Repository</span>
        <select
          aria-label="Repository"
          className={`${FIELD} max-w-full md:max-w-[200px]`}
          value={query.repository || ""}
          onChange={(event) => onChange({ repository: event.target.value || undefined, image: undefined, page: 1 })}
        >
          <option value="">All repositories</option>
          {repositories.map((repo) => (
            <option key={repo} value={repo}>
              {repo}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-2 text-sm text-muted">
        <span className="sr-only md:not-sr-only">Image</span>
        <select
          aria-label="Image"
          className={`${FIELD} max-w-full md:max-w-[200px]`}
          value={query.image || ""}
          onChange={(event) => onChange({ image: event.target.value || undefined, page: 1 })}
          disabled={images.length === 0 && !query.image}
        >
          <option value="">{images.length === 0 && !query.repository && query.group !== "finding" ? "Pick a repository first" : "All images"}</option>
          {images.map((image) => (
            <option key={image} value={image}>
              {image}
            </option>
          ))}
        </select>
      </label>
      {(query.state === "done" || query.state === "all" || query.group === "finding") && (
        <label className="flex items-center gap-2 text-sm text-muted">
          <span className="sr-only md:not-sr-only">State</span>
          <select
            aria-label="State"
            className={FIELD}
            value={query.state || "open"}
            onChange={(event) => onChange({ state: event.target.value as "open" | "done" | "all", page: 1 })}
          >
            <option value="open">Open</option>
            <option value="done">Fixed</option>
            <option value="all">All</option>
          </select>
        </label>
      )}
    </>
  );

  return (
    <section className="mb-4 flex flex-wrap items-center gap-2" aria-label="Vulnerability filters">
      <input
        type="search"
        aria-label="Search CVE, GHSA or package"
        placeholder="CVE, GHSA or package"
        value={searchInput}
        onChange={(event) => setSearchInput(event.target.value)}
        className={`${FIELD} w-full sm:w-64 sm:flex-none`}
      />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Severity">
        {SEVERITY_OPTIONS.map((severity) => {
          const key = toSeverityKey(severity);
          const active = query.severity === severity;
          const count = severityCounts?.[severity];
          return (
            <button
              key={severity}
              type="button"
              aria-pressed={active}
              onClick={() => toggleSeverity(severity)}
              className="inline-flex min-h-11 items-center gap-1.5 rounded-lg border px-3 text-sm font-semibold transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent md:min-h-9"
              style={{
                color: SEVERITY[key].fg,
                borderColor: active ? SEVERITY[key].bar : "var(--color-line)",
                background: active ? SEVERITY[key].bg : "transparent",
              }}
            >
              {SEVERITY[key].label}
              {count !== undefined && <span className="font-mono text-xs">{count}</span>}
            </button>
          );
        })}
      </div>

      <button
        type="button"
        aria-pressed={fixOn}
        onClick={() => onChange({ fixAvailable: fixOn ? undefined : true, page: 1 })}
        className={`inline-flex min-h-11 items-center gap-2 rounded-lg border px-3 text-sm font-semibold transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent md:min-h-9 ${
          fixOn ? "border-success bg-success/15 text-success" : "border-line text-fg2 hover:border-accent"
        }`}
      >
        <span aria-hidden="true">{fixOn ? "☑" : "☐"}</span>
        Fix available
      </button>

      <button
        type="button"
        aria-expanded={moreOpen}
        onClick={() => setMoreOpen((v) => !v)}
        className="inline-flex min-h-11 items-center rounded-lg border border-line px-3 text-sm font-medium text-fg2 hover:border-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent md:hidden"
      >
        More filters
      </button>
      <div className={`${moreOpen ? "flex" : "hidden"} w-full flex-col gap-2 md:contents`}>{selects}</div>

      {(query.search || query.severity || query.repository || query.image || query.package || query.fixAvailable || query.state) && (
        <button type="button" className="min-h-11 px-2 text-sm font-medium text-link hover:underline md:min-h-9" onClick={onClear}>
          Clear filters
        </button>
      )}
    </section>
  );
}

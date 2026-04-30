import { useEffect, useState } from "react";
import type { Severity } from "../services/types";
import type { VulnerabilityQueryParams } from "../hooks/use-vulnerabilities";

interface FilterBarProps {
  query: VulnerabilityQueryParams;
  repositories: string[];
  images: string[];
  onChange: (patch: Partial<VulnerabilityQueryParams>) => void;
  onClear: () => void;
}

const SEVERITY_OPTIONS: Array<Severity> = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export function FilterBar({ query, repositories, images, onChange, onClear }: FilterBarProps) {
  const [searchInput, setSearchInput] = useState(query.search || "");

  useEffect(() => {
    setSearchInput(query.search || "");
  }, [query.search]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      onChange({ search: searchInput || undefined, page: 1 });
    }, 300);

    return () => window.clearTimeout(timer);
  }, [searchInput, onChange]);

  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner" aria-label="Vulnerability filters">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5">
        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Search</span>
          <input
            type="search"
            placeholder="Search CVE, package, description"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Severity</span>
          <select
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={query.severity || ""}
            onChange={(event) =>
              onChange({
                severity: event.target.value ? (event.target.value as Severity) : undefined,
                page: 1,
              })
            }
          >
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Repository</span>
          <select
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={query.repository || ""}
            onChange={(event) =>
              onChange({
                repository: event.target.value || undefined,
                page: 1,
              })
            }
          >
            <option value="">All repositories</option>
            {repositories.map((repo) => (
              <option key={repo} value={repo}>
                {repo}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Image</span>
          <select
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={query.image || ""}
            onChange={(event) =>
              onChange({
                image: event.target.value || undefined,
                page: 1,
              })
            }
          >
            <option value="">All images</option>
            {images.map((image) => (
              <option key={image} value={image}>
                {image}
              </option>
            ))}
          </select>
        </label>

        <div className="flex items-end">
          <button type="button" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500" onClick={onClear}>
            Clear Filters
          </button>
        </div>
      </div>
    </section>
  );
}

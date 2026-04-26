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
    <section className="card vulnerability-filters" aria-label="Vulnerability filters">
      <label className="filter-control">
        <span className="filter-label">Search</span>
        <input
          type="search"
          placeholder="Search CVE, package, description"
          value={searchInput}
          onChange={(event) => setSearchInput(event.target.value)}
          className="filter-input"
        />
      </label>

      <label className="filter-control">
        <span className="filter-label">Severity</span>
        <select
          className="filter-select"
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

      <label className="filter-control">
        <span className="filter-label">Repository</span>
        <select
          className="filter-select"
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

      <label className="filter-control">
        <span className="filter-label">Image</span>
        <select
          className="filter-select"
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

      <button type="button" className="secondary-button" onClick={onClear}>
        Clear Filters
      </button>
    </section>
  );
}

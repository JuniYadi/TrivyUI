import { useEffect, useState, type AnchorHTMLAttributes, type ReactNode } from "react";
import { navigate } from "../lib/navigation";
import { SEVERITY, type SeverityKey } from "./ui/severity";
import type { SeverityCounts } from "../services/repo-page-types";

/** Shared bits for the repositories / repository detail / images / image detail pages. */

export const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent";

export const SEVERITY_KEYS_LOWER: SeverityKey[] = ["critical", "high", "medium", "low", "unknown"];

/** API severity counts (UPPERCASE keys) -> SeverityBar/SEVERITY keys. */
export function toBarCounts(counts: SeverityCounts): Record<SeverityKey, number> {
  return {
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    unknown: counts.UNKNOWN,
  };
}

/** In-app link: real href (open in new tab works) with client-side navigation on plain click. */
export function AppLink({ href, className = "", children, ...rest }: { href: string; className?: string; children: ReactNode } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href">) {
  return (
    <a
      href={href}
      className={`${FOCUS} ${className}`}
      onClick={(event) => {
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
          return;
        }
        event.preventDefault();
        navigate(href);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}

/** Link styled like Button (secondary / primary), 44px tall on touch screens. */
export function LinkButton({ href, primary = false, children }: { href: string; primary?: boolean; children: ReactNode }) {
  return (
    <AppLink
      href={href}
      className={`inline-flex min-h-11 items-center justify-center rounded-lg border px-3 text-sm font-medium transition sm:min-h-9 ${
        primary ? "border-transparent bg-accent text-white hover:brightness-110" : "border-line bg-card text-fg hover:border-accent"
      }`}
    >
      {children}
    </AppLink>
  );
}

export function repoHref(name: string): string {
  return `/repositories/by-name/${encodeURIComponent(name)}`;
}

export function displayRepoName(name: string, registry: string | null): string {
  return registry && name.startsWith(`${registry}/`) ? name.slice(registry.length + 1) : name;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const time = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value.replace(" ", "T")}Z`);
  return Number.isFinite(time) ? new Date(time).toLocaleString() : "-";
}

export function timeAgo(value: string | null | undefined, now = Date.now()): string {
  if (!value) {
    return "never";
  }
  const time = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value.replace(" ", "T")}Z`);
  if (!Number.isFinite(time)) {
    return "-";
  }
  const seconds = Math.max(0, Math.round((now - time) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 60) return `${days} d ago`;
  return new Date(time).toLocaleDateString();
}

/** +N (worse, red) / -N (better, green) / dash. */
export function Delta({ value, className = "" }: { value: number | null | undefined; className?: string }) {
  if (value === null || value === undefined || value === 0) {
    return (
      <span className={`font-mono text-muted ${className}`} aria-label="no change">
        {value === 0 ? "0" : "—"}
      </span>
    );
  }
  const worse = value > 0;
  return (
    <span
      className={`font-mono ${worse ? "" : "text-success"} ${className}`}
      style={worse ? { color: SEVERITY.critical.fg } : undefined}
      aria-label={`${worse ? "up" : "down"} ${Math.abs(value)}`}
    >
      {worse ? "+" : "−"}
      {Math.abs(value)}
    </span>
  );
}

/** Compact "9C 10H 11M 7L" line. */
export function SeverityLetters({ counts }: { counts: SeverityCounts }) {
  const parts = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((key) => `${counts[key]}${key[0]}`);
  return <span className="font-mono text-[11px] text-muted">{parts.join(" ")}</span>;
}

/** Letter + count pills (C 6, H 4 ...). Zero counts are dimmed. */
export function SeverityCountChips({ counts }: { counts: SeverityCounts }) {
  return (
    <span className="inline-flex flex-wrap gap-1" role="group" aria-label="Severity counts">
      {(["critical", "high", "medium", "low"] as const).map((key) => {
        const s = SEVERITY[key];
        const count = counts[key.toUpperCase() as keyof SeverityCounts];
        return (
          <span
            key={key}
            title={`${s.label} ${count}`}
            className={`inline-flex h-5 items-center gap-1 rounded px-1.5 font-mono text-[11px] font-bold leading-none ${count === 0 ? "opacity-40" : ""}`}
            style={{ background: s.bg, color: s.fg }}
          >
            {s.letter}
            <span>{count}</span>
          </span>
        );
      })}
    </span>
  );
}

export function LatestBadge() {
  return <span className="rounded bg-success/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-success">latest</span>;
}

/** Debounced controlled search box. Calls onSearch(trimmed) after `delay` ms of inactivity. */
export function SearchBox({
  value,
  onSearch,
  label,
  placeholder,
  delay = 300,
}: {
  value: string;
  onSearch: (value: string) => void;
  label: string;
  placeholder: string;
  delay?: number;
}) {
  const [input, setInput] = useState(value);

  useEffect(() => {
    setInput(value);
  }, [value]);

  useEffect(() => {
    const next = input.trim();
    if (next === value) {
      return;
    }
    const timer = window.setTimeout(() => onSearch(next), delay);
    return () => window.clearTimeout(timer);
  }, [input, value, delay, onSearch]);

  return (
    <div className="min-w-0 flex-1 basis-56">
      <label htmlFor={`search-${label}`} className="sr-only">
        {label}
      </label>
      <input
        id={`search-${label}`}
        type="search"
        value={input}
        placeholder={placeholder}
        onChange={(event) => setInput(event.target.value)}
        className={`h-11 w-full rounded-lg border border-line bg-card px-3 text-sm text-fg placeholder:text-muted sm:h-10 ${FOCUS}`}
      />
    </div>
  );
}

/** Row of small toggle buttons (sort chips, filter chips). Touch target >= 44px on mobile. */
export function ChipButton({ active, onClick, children, label }: { active: boolean; onClick: () => void; children: ReactNode; label?: string }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      aria-label={label}
      onClick={onClick}
      className={`inline-flex min-h-11 items-center gap-1 rounded-lg border px-3 text-sm font-medium transition sm:min-h-9 ${FOCUS} ${
        active ? "border-accent bg-accent/15 text-fg" : "border-line bg-card text-fg2 hover:border-accent"
      }`}
    >
      {children}
    </button>
  );
}

export function PageSkeleton() {
  return (
    <div className="grid gap-4" aria-busy="true" aria-label="Loading">
      <div className="h-12 animate-pulse rounded-xl border border-line bg-card" />
      <div className="h-64 animate-pulse rounded-xl border border-line bg-card" />
    </div>
  );
}

export function PageError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-line bg-card p-4">
      <p className="text-sm text-fg">
        <strong>Something went wrong.</strong> <span className="text-fg2">{message}</span>
      </p>
      <button
        type="button"
        onClick={onRetry}
        className={`mt-3 inline-flex min-h-11 items-center rounded-lg bg-accent px-4 text-sm font-semibold text-white hover:brightness-110 sm:min-h-9 ${FOCUS}`}
      >
        Retry
      </button>
    </div>
  );
}

export function NotFoundCard({ title, backTo, backLabel }: { title: string; backTo: string; backLabel: string }) {
  return (
    <div className="rounded-xl border border-dashed border-line p-8 text-center">
      <h2 className="text-lg font-semibold">{title}</h2>
      <a href={backTo} className={`mt-3 inline-flex min-h-11 items-center text-link hover:underline ${FOCUS}`}>
        {backLabel}
      </a>
    </div>
  );
}

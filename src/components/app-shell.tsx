import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";

export type ActiveRoute =
  | "/dashboard"
  | "/upload"
  | "/vulnerabilities"
  | "/repositories"
  | "/repositories/:id"
  | "/images"
  | "/images/:id"
  | "/settings"
  | "/api-keys"
  | "/email-templates"
  | "/trivy-ignore";

export interface Breadcrumb {
  label: string;
  /** Omit for the current (last) item. */
  to?: string;
}

interface AppShellProps {
  title: string;
  /** One-line meta under the title. */
  meta?: ReactNode;
  /** @deprecated alias of `meta`, kept for existing call sites. */
  subtitle?: ReactNode;
  actions?: ReactNode;
  breadcrumbs?: Breadcrumb[];
  activeRoute: ActiveRoute;
  children: ReactNode;
}

type NavItem = { to: string; label: string; icon: ReactNode; match: (r: ActiveRoute) => boolean };

const icon = (children: ReactNode) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0">
    {children}
  </svg>
);

const ICONS = {
  dashboard: icon(<><rect x="3" y="3" width="7" height="9" /><rect x="14" y="3" width="7" height="5" /><rect x="14" y="12" width="7" height="9" /><rect x="3" y="16" width="7" height="5" /></>),
  vulns: icon(<><path d="M12 3l10 18H2z" /><path d="M12 10v5M12 18h.01" /></>),
  repos: icon(<><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" /></>),
  images: icon(<><path d="M12 2l9 5v10l-9 5-9-5V7z" /><path d="M3 7l9 5 9-5M12 12v10" /></>),
  ignore: icon(<><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></>),
  upload: icon(<path d="M12 16V4M6 10l6-6 6 6M4 20h16" />),
  settings: icon(<><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" /></>),
  key: icon(<><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M16 7l3 3" /></>),
  mail: icon(<><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 7l9 6 9-6" /></>),
};

const NAV: { heading?: string; items: NavItem[] }[] = [
  { items: [{ to: "/dashboard", label: "Dashboard", icon: ICONS.dashboard, match: (r) => r === "/dashboard" }] },
  {
    heading: "Explore",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ICONS.vulns, match: (r) => r === "/vulnerabilities" },
      { to: "/repositories", label: "Repositories", icon: ICONS.repos, match: (r) => r.startsWith("/repositories") },
      { to: "/images", label: "Images", icon: ICONS.images, match: (r) => r.startsWith("/images") },
    ],
  },
  {
    heading: "Remediate",
    items: [
      { to: "/trivy-ignore", label: "Ignore rules", icon: ICONS.ignore, match: (r) => r === "/trivy-ignore" },
      { to: "/upload", label: "Upload scan", icon: ICONS.upload, match: (r) => r === "/upload" },
    ],
  },
  {
    heading: "Admin",
    items: [
      { to: "/settings", label: "Settings", icon: ICONS.settings, match: (r) => r === "/settings" },
      { to: "/api-keys", label: "API keys", icon: ICONS.key, match: (r) => r === "/api-keys" },
      { to: "/email-templates", label: "Email templates", icon: ICONS.mail, match: (r) => r === "/email-templates" },
    ],
  },
];

const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent";

function SidebarNav({ activeRoute, onNavigate }: { activeRoute: ActiveRoute; onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="flex flex-col gap-4 overflow-y-auto px-3 pb-4">
      {NAV.map((group, i) => (
        <div key={group.heading ?? i} className="flex flex-col gap-0.5">
          {group.heading && (
            <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted">{group.heading}</p>
          )}
          {group.items.map((item) => {
            const active = item.match(activeRoute);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                className={`flex min-h-9 items-center gap-2.5 rounded-lg px-2 text-sm font-medium ${FOCUS} ${
                  active ? "bg-accent/15 text-link" : "text-fg2 hover:bg-line hover:text-fg"
                }`}
              >
                {item.icon}
                {item.label}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

export function AppShell({ title, meta, subtitle, actions, breadcrumbs, activeRoute, children }: AppShellProps) {
  const [open, setOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const metaLine = meta ?? subtitle;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      e.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const onSearch = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const q = searchRef.current?.value.trim() ?? "";
    // Full navigation: the vulnerabilities page parses window.location on load.
    window.location.assign(q ? `/vulnerabilities?search=${encodeURIComponent(q)}` : "/vulnerabilities");
  };

  return (
    <div className="min-h-screen bg-bg font-sans text-fg lg:grid lg:grid-cols-[232px_minmax(0,1fr)]">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-white"
      >
        Skip to content
      </a>

      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setOpen(false)} aria-hidden="true" />}
      <aside
        id="app-sidebar"
        className={`fixed inset-y-0 left-0 z-40 flex w-[260px] flex-col gap-3 border-r border-line bg-sidebar transition-transform lg:sticky lg:top-0 lg:h-screen lg:w-auto lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <Link to="/dashboard" onClick={() => setOpen(false)} className={`flex items-center gap-2.5 px-5 py-4 text-base font-bold tracking-tight text-fg ${FOCUS}`}>
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="text-accent">
            <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          TrivyUI
        </Link>
        <SidebarNav activeRoute={activeRoute} onNavigate={() => setOpen(false)} />
      </aside>

      <div className="min-w-0">
        <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line px-4 py-3 sm:px-6">
          <button
            type="button"
            className={`inline-flex h-11 w-11 items-center justify-center rounded-lg border border-line text-fg lg:hidden ${FOCUS}`}
            aria-label="Open navigation"
            aria-expanded={open}
            aria-controls="app-sidebar"
            onClick={() => setOpen((v) => !v)}
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M3 5h14M3 10h14M3 15h14" />
            </svg>
          </button>
          <div className="min-w-0 flex-1 basis-56">
            {breadcrumbs && breadcrumbs.length > 0 && (
              <nav aria-label="Breadcrumb" className="mb-0.5 text-xs text-muted">
                <ol className="flex flex-wrap items-center gap-1">
                  {breadcrumbs.map((b, i) => (
                    <li key={`${b.label}-${i}`} className="flex items-center gap-1">
                      {i > 0 && <span aria-hidden="true">/</span>}
                      {b.to ? (
                        <Link to={b.to} className={`text-link hover:underline ${FOCUS}`}>
                          {b.label}
                        </Link>
                      ) : (
                        <span aria-current="page">{b.label}</span>
                      )}
                    </li>
                  ))}
                </ol>
              </nav>
            )}
            <h1 className="truncate text-xl font-semibold leading-tight">{title}</h1>
            {metaLine && <p className="truncate text-xs text-muted">{metaLine}</p>}
          </div>
          <form role="search" onSubmit={onSearch} className="w-full sm:w-72">
            <label htmlFor="global-search" className="sr-only">
              Search CVE, package or image
            </label>
            <input
              id="global-search"
              ref={searchRef}
              type="search"
              name="search"
              placeholder="Search CVE, package, image  ( / )"
              className="h-9 w-full rounded-lg border border-line bg-card px-3 text-sm text-fg placeholder:text-muted focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent"
            />
          </form>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>

        <main id="main-content" tabIndex={-1} className="mx-auto w-full max-w-[1240px] px-4 py-5 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  );
}

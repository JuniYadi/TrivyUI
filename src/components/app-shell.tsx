import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";

interface AppShellProps {
  title: string;
  subtitle: string;
  activeRoute:
    | "/dashboard"
    | "/upload"
    | "/vulnerabilities"
    | "/repositories"
    | "/repositories/:id"
    | "/images"
    | "/images/:id"
    | "/settings"
    | "/api-keys"
    | "/email-templates";
  children: ReactNode;
}

export function AppShell({ title, subtitle, activeRoute, children }: AppShellProps) {
  return (
    <main className="page-shell" role="main">
      <div className="container">
        <header className="shell-header">
          <div className="shell-brand">
            <span className="shell-brand__badge">TrivyUI</span>
            <h1 className="page-title text-3xl font-bold leading-tight">{title}</h1>
            <p className="page-subtitle mt-2 text-sm text-slate-400">{subtitle}</p>
          </div>

          <nav className="shell-nav" aria-label="Primary">
            <Link
              to="/dashboard"
              className={`shell-nav__link ${activeRoute === "/dashboard" ? "shell-nav__link--active" : ""}`}
            >
              Dashboard
            </Link>
            <Link
              to="/vulnerabilities"
              className={`shell-nav__link ${activeRoute === "/vulnerabilities" ? "shell-nav__link--active" : ""}`}
            >
              Vulns
            </Link>
            <Link
              to="/repositories"
              className={`shell-nav__link ${activeRoute.startsWith("/repositories") ? "shell-nav__link--active" : ""}`}
            >
              Repos
            </Link>
            <Link
              to="/images"
              className={`shell-nav__link ${activeRoute.startsWith("/images") ? "shell-nav__link--active" : ""}`}
            >
              Images
            </Link>
            <Link
              to="/upload"
              className={`shell-nav__link ${activeRoute === "/upload" ? "shell-nav__link--active" : ""}`}
            >
              Upload
            </Link>
            <Link
              to="/settings"
              className={`shell-nav__link ${activeRoute === "/settings" ? "shell-nav__link--active" : ""}`}
            >
              Settings
            </Link>
            <Link
              to="/api-keys"
              className={`shell-nav__link ${activeRoute === "/api-keys" ? "shell-nav__link--active" : ""}`}
            >
              API Keys
            </Link>
            <Link
              to="/email-templates"
              className={`shell-nav__link ${activeRoute === "/email-templates" ? "shell-nav__link--active" : ""}`}
            >
              Email Templates
            </Link>
          </nav>
        </header>

        <section className="w-full">{children}</section>
      </div>
    </main>
  );
}

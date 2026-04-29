import type { ReactNode } from "react";

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

function navigate(
  path: "/dashboard" | "/upload" | "/vulnerabilities" | "/repositories" | "/images" | "/settings" | "/api-keys" | "/email-templates"
) {
  if (window.location.pathname === path) {
    return;
  }

  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function AppShell({ title, subtitle, activeRoute, children }: AppShellProps) {
  return (
    <main className="page-shell" role="main">
      <div className="container">
        <header className="shell-header">
          <div className="shell-brand">
            <span className="shell-brand__badge">TrivyUI</span>
            <h1 className="page-title">{title}</h1>
            <p className="page-subtitle">{subtitle}</p>
          </div>

          <nav className="shell-nav" aria-label="Primary">
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/dashboard" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/dashboard")}
            >
              Dashboard
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/vulnerabilities" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/vulnerabilities")}
            >
              Vulns
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute.startsWith("/repositories") ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/repositories")}
            >
              Repos
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute.startsWith("/images") ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/images")}
            >
              Images
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/upload" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/upload")}
            >
              Upload
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/settings" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/settings")}
            >
              Settings
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/api-keys" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/api-keys")}
            >
              API Keys
            </button>
            <button
              type="button"
              className={`shell-nav__link ${activeRoute === "/email-templates" ? "shell-nav__link--active" : ""}`}
              onClick={() => navigate("/email-templates")}
            >
              Email Templates
            </button>
          </nav>
        </header>

        {children}
      </div>
    </main>
  );
}

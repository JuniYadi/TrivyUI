import { useEffect, useState } from "react";
import { DashboardPage } from "./routes/dashboard";
import { ImageDetailPage } from "./routes/image-detail";
import { ImagesPage } from "./routes/images";
import { RepositoryDetailPage } from "./routes/repository-detail";
import { RepositoriesPage } from "./routes/repositories";
import { UploadPage } from "./routes/upload";
import { VulnerabilitiesPage } from "./routes/vulnerabilities";
import { SettingsPage } from "./routes/settings";
import { ApiKeysPage } from "./routes/api-keys";
import { EmailTemplatesPage } from "./routes/email-templates";

export type AppRoute =
  | "/dashboard"
  | "/upload"
  | "/vulnerabilities"
  | "/repositories"
  | "/repositories/:id"
  | "/repositories/by-name/:repo-name"
  | "/images"
  | "/images/:id"
  | "/settings"
  | "/api-keys"
  | "/email-templates"
  | "/not-found";

export function resolveRoute(pathname: string): AppRoute {
  if (pathname === "/" || pathname === "") {
    window.history.replaceState({}, "", "/dashboard");
    return "/dashboard";
  }

  if (pathname === "/dashboard") {
    return "/dashboard";
  }

  if (pathname === "/upload") {
    return "/upload";
  }

  if (pathname === "/vulnerabilities") {
    return "/vulnerabilities";
  }

  if (pathname === "/repositories") {
    return "/repositories";
  }

  if (/^\/repositories\/\d+$/.test(pathname)) {
    return "/repositories/:id";
  }

  if (/^\/repositories\/by-name\/.+$/.test(pathname)) {
    return "/repositories/by-name/:repo-name";
  }

  if (pathname === "/images") {
    return "/images";
  }

  if (/^\/images\/\d+$/.test(pathname)) {
    return "/images/:id";
  }

  if (pathname === "/settings") {
    return "/settings";
  }

  if (pathname === "/api-keys") {
    return "/api-keys";
  }

  if (pathname === "/email-templates") {
    return "/email-templates";
  }

  return "/not-found";
}

export default function App() {
  const [route, setRoute] = useState<AppRoute>(() => resolveRoute(window.location.pathname));

  useEffect(() => {
    const onPopState = () => setRoute(resolveRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (route === "/dashboard") {
    return <DashboardPage />;
  }

  if (route === "/upload") {
    return <UploadPage />;
  }

  if (route === "/vulnerabilities") {
    return <VulnerabilitiesPage />;
  }

  if (route === "/repositories") {
    return <RepositoriesPage />;
  }

  if (route === "/repositories/:id") {
    return <RepositoryDetailPage />;
  }

  if (route === "/repositories/by-name/:repo-name") {
    return <RepositoryDetailPage />;
  }

  if (route === "/images") {
    return <ImagesPage />;
  }

  if (route === "/images/:id") {
    return <ImageDetailPage />;
  }

  if (route === "/settings") {
    return <SettingsPage />;
  }

  if (route === "/api-keys") {
    return <ApiKeysPage />;
  }

  if (route === "/email-templates") {
    return <EmailTemplatesPage />;
  }

  return (
    <main className="not-found" role="main">
      <h1>404</h1>
      <p className="muted">Page not found.</p>
    </main>
  );
}

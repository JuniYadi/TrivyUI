import { createRootRoute, createRoute, createRouter, Navigate } from "@tanstack/react-router";
import { DashboardPage } from "./routes/dashboard";
import { VulnerabilitiesPage } from "./routes/vulnerabilities";
import { RepositoriesPage } from "./routes/repositories";
import { RepositoryDetailPage } from "./routes/repository-detail";
import { ImagesPage } from "./routes/images";
import { ImageDetailPage } from "./routes/image-detail";
import { UploadPage } from "./routes/upload";
import { SettingsPage } from "./routes/settings";
import { ApiKeysPage } from "./routes/api-keys";
import { EmailTemplatesPage } from "./routes/email-templates";

export const APP_ROUTE_PATHS = [
  "/dashboard",
  "/upload",
  "/vulnerabilities",
  "/repositories",
  "/repositories/$id",
  "/repositories/by-name/$repoName",
  "/images",
  "/images/$id",
  "/settings",
  "/api-keys",
  "/email-templates",
] as const;

const rootRoute = createRootRoute({
  notFoundComponent: () => (
    <main className="not-found" role="main">
      <h1>404</h1>
      <p className="muted">Page not found.</p>
    </main>
  ),
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => <Navigate to="/dashboard" />,
});

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/dashboard",
  component: DashboardPage,
});

const uploadRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/upload",
  component: UploadPage,
});

const vulnerabilitiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vulnerabilities",
  component: VulnerabilitiesPage,
});

const repositoriesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/repositories",
  component: RepositoriesPage,
});

const repositoryDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/repositories/$id",
  component: RepositoryDetailPage,
});

const repositoryByNameRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/repositories/by-name/$repoName",
  component: RepositoryDetailPage,
});

const imagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/images",
  component: ImagesPage,
});

const imageDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/images/$id",
  component: ImageDetailPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const apiKeysRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/api-keys",
  component: ApiKeysPage,
});

const emailTemplatesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/email-templates",
  component: EmailTemplatesPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  dashboardRoute,
  uploadRoute,
  vulnerabilitiesRoute,
  repositoriesRoute,
  repositoryDetailRoute,
  repositoryByNameRoute,
  imagesRoute,
  imageDetailRoute,
  settingsRoute,
  apiKeysRoute,
  emailTemplatesRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

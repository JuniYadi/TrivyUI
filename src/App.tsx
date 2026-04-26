import { useEffect, useState } from "react";
import { DashboardPage } from "./routes/dashboard";
import { UploadPage } from "./routes/upload";
import { VulnerabilitiesPage } from "./routes/vulnerabilities";

export type AppRoute = "/dashboard" | "/upload" | "/vulnerabilities" | "/not-found";

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

  return (
    <main className="not-found" role="main">
      <h1>404</h1>
      <p className="muted">Page not found.</p>
    </main>
  );
}

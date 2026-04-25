import { useEffect, useState } from "react";
import { DashboardPage } from "./routes/dashboard";

type AppRoute = "/dashboard" | "/not-found";

function resolveRoute(pathname: string): AppRoute {
  if (pathname === "/" || pathname === "") {
    window.history.replaceState({}, "", "/dashboard");
    return "/dashboard";
  }

  if (pathname === "/dashboard") {
    return "/dashboard";
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

  return (
    <main style={{ fontFamily: "system-ui", padding: "2rem" }}>
      <h1>404</h1>
      <p>Page not found.</p>
    </main>
  );
}

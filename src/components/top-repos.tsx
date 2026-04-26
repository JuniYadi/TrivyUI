import type { DashboardTopRepository } from "../services/types";

interface TopReposProps {
  repositories: DashboardTopRepository[];
}

export function TopRepos({ repositories }: TopReposProps) {
  const navigateToRepo = (repoId: number) => {
    window.history.pushState({}, "", `/repositories/${repoId}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  return (
    <section style={{ border: "1px solid #334155", borderRadius: 12, padding: "1rem" }}>
      <h3 style={{ marginTop: 0 }}>Top Vulnerable Repositories</h3>
      {repositories.length === 0 ? (
        <p style={{ marginBottom: 0, color: "#94a3b8" }}>No vulnerable repositories found yet.</p>
      ) : (
        <ol style={{ margin: 0, paddingLeft: "1.25rem", display: "grid", gap: 8 }}>
          {repositories.map((repo) => (
            <li key={repo.id}>
              <button
                type="button"
                onClick={() => navigateToRepo(repo.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#93c5fd",
                  padding: 0,
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                {repo.name}
              </button>{" "}
              — {repo.vulnerability_count} vulns ({repo.critical_count} critical)
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

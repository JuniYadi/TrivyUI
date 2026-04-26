import type { DashboardTopRepository } from "../services/types";

interface TopReposProps {
  repositories: DashboardTopRepository[];
}

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function TopRepos({ repositories }: TopReposProps) {
  return (
    <section className="card">
      <h3 className="card-title">Top Vulnerable Repositories</h3>
      {repositories.length === 0 ? (
        <p className="muted mb-0">No vulnerable repositories found yet.</p>
      ) : (
        <ol className="list">
          {repositories.map((repo) => (
            <li key={repo.id}>
              <button type="button" className="link-button" onClick={() => navigate(`/repositories/${repo.id}`)}>
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

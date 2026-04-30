import type { DashboardTopRepository } from "../services/types";
import { navigate } from "../lib/navigation";

interface TopReposProps {
  repositories: DashboardTopRepository[];
}

export function TopRepos({ repositories }: TopReposProps) {
  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
      <h3 className="mb-3 text-base font-semibold">Top Vulnerable Repositories</h3>
      {repositories.length === 0 ? (
        <p className="mb-0 text-slate-400">No vulnerable repositories found yet.</p>
      ) : (
        <ol className="m-0 list-none p-0 space-y-2">
          {repositories.map((repo) => (
            <li key={repo.id} className="rounded-lg border border-slate-700/80 bg-slate-950/60 p-2">
              <button type="button" className="text-blue-400 hover:text-blue-300 hover:underline" onClick={() => navigate(`/repositories/${repo.id}`)}>
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

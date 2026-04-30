import type { DashboardTopRepository } from "../services/types";
import { navigate } from "../lib/navigation";

interface TopReposProps {
  repositories: DashboardTopRepository[];
}

type ParsedRepositoryRef = {
  registry: string;
  owner: string;
  region: string;
  repository: string;
};

function parseRepositoryReference(repositoryName: string): ParsedRepositoryRef {
  const value = repositoryName.trim();
  if (!value) {
    return {
      registry: "Unknown",
      owner: "-",
      region: "-",
      repository: repositoryName,
    };
  }

  const ecrMatch = value.match(/^([^.]*)\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/(.+)$/i);
  if (ecrMatch) {
    const [, accountId, region, repository] = ecrMatch;
    return {
      registry: "ECR",
      owner: accountId || "-",
      region: region || "-",
      repository: repository || "-",
    };
  }

  const slash = value.indexOf("/");
  const repository = slash >= 0 ? value.slice(slash + 1) : value;

  return {
    registry: "Other",
    owner: "-",
    region: "-",
    repository,
  };
}

export function TopRepos({ repositories }: TopReposProps) {
  const visibleRepositories = repositories.slice(0, 10);

  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-3 shadow-inner">
      <h3 className="mb-2 text-sm font-semibold">Top Vulnerable Repositories</h3>
      {visibleRepositories.length === 0 ? (
        <p className="mb-0 text-sm text-slate-400">No vulnerable repositories found yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-left text-slate-300">
                <th className="py-2 pr-3 font-medium">Registry</th>
                <th className="py-2 pr-3 font-medium">Owner</th>
                <th className="py-2 pr-3 font-medium">Region</th>
                <th className="py-2 pr-3 font-medium">Repository</th>
                <th className="py-2 pr-3 font-medium">Vulnerabilities</th>
                <th className="py-2 font-medium">Critical</th>
              </tr>
            </thead>
            <tbody>
              {visibleRepositories.map((repo) => {
                const parsed = parseRepositoryReference(repo.name);

                return (
                  <tr key={repo.id} className="border-b border-slate-800/80 last:border-b-0">
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.registry}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.owner}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.region}</td>
                    <td className="py-2 pr-3">
                      <button
                        type="button"
                        className="block max-w-[320px] truncate text-blue-400 hover:text-blue-300 hover:underline"
                        title={repo.name}
                        onClick={() => navigate(`/repositories/${repo.id}`)}
                      >
                        {parsed.repository}
                      </button>
                    </td>
                    <td className="py-2 pr-3">{repo.vulnerability_count}</td>
                    <td className="py-2">{repo.critical_count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

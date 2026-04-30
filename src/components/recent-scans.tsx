import type { DashboardRecentScan } from "../services/types";
import { navigate } from "../lib/navigation";

interface RecentScansProps {
  scans: DashboardRecentScan[];
}

type ParsedImageRef = {
  registry: string;
  owner: string;
  region: string;
  repository: string;
};

function parseImageReference(image: string): ParsedImageRef {
  const value = image.trim();
  if (!value) {
    return {
      registry: "Unknown",
      owner: "-",
      region: "-",
      repository: image,
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

function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diffMs = Math.max(0, now - then);

  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;

  if (diffMs < hour) {
    const mins = Math.max(1, Math.floor(diffMs / minute));
    return `${mins}m ago`;
  }

  if (diffMs < day) {
    const hours = Math.max(1, Math.floor(diffMs / hour));
    return `${hours}h ago`;
  }

  const days = Math.max(1, Math.floor(diffMs / day));
  return `${days}d ago`;
}

export function RecentScans({ scans }: RecentScansProps) {
  const visibleScans = scans.slice(0, 10);

  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-3 shadow-inner">
      <h3 className="mb-2 text-sm font-semibold">Recent Scans</h3>
      {visibleScans.length === 0 ? (
        <p className="mb-0 text-sm text-slate-400">No scans available.</p>
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
                <th className="py-2 pr-3 font-medium">Packages</th>
                <th className="py-2 font-medium">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {visibleScans.map((scan) => {
                const parsed = parseImageReference(scan.image);

                return (
                  <tr key={scan.id} className="border-b border-slate-800/80 last:border-b-0">
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.registry}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.owner}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">{parsed.region}</td>
                    <td className="py-2 pr-3">
                      <button
                        type="button"
                        className="block max-w-[300px] truncate text-blue-400 hover:text-blue-300 hover:underline"
                        title={scan.image}
                        onClick={() => navigate(`/images/${scan.id}`)}
                      >
                        {parsed.repository}
                      </button>
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap">
                      {scan.vulnerability_count} total / {scan.critical_count} critical
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap">
                      {scan.package_count} total / {scan.clean_package_count} clean / {scan.vulnerable_package_count} vuln
                    </td>
                    <td className="py-2 whitespace-nowrap">{formatRelativeTime(scan.scanned_at)}</td>
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

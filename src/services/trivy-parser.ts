import type {
  NormalizedVulnerability,
  ParseResult,
  Severity,
  TrivyJson,
  TrivyPackage,
  TrivyResult,
  TrivyVulnerability,
} from "./types";

const ALLOWED_SEVERITIES: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
];

export function detectSchemaVersion(input: unknown): string {
  if (!isObject(input)) {
    return "unknown";
  }

  const payload = input as TrivyJson;

  if (payload.SchemaVersion !== undefined && payload.SchemaVersion !== null) {
    return String(payload.SchemaVersion);
  }

  const trivyVersion = payload.Metadata?.TrivyVersion;
  if (typeof trivyVersion === "string" && trivyVersion.trim().length > 0) {
    return trivyVersion;
  }

  return "unknown";
}

export function parseTrivyResult(input: unknown): ParseResult {
  if (!isObject(input)) {
    throw new Error("INVALID_TRIVY_FORMAT: expected JSON object");
  }

  const payload = input as TrivyJson;
  const results = extractResults(payload);

  if (results.length === 0) {
    throw new Error("EMPTY_RESULTS");
  }

  const artifactName = extractArtifactName(payload);
  const { repoName, imageName } = splitArtifact(artifactName);

  const vulnerabilities: NormalizedVulnerability[] = [];

  for (const result of results) {
    const packages = extractPackages(result);

    for (const pkg of packages) {
      const packageVulns = extractPackageVulnerabilities(result, pkg);
      if (packageVulns.length === 0) {
        continue;
      }

      for (const vuln of packageVulns) {
        const normalized = normalizeVulnerability(pkg, vuln);
        if (normalized) {
          vulnerabilities.push(normalized);
        }
      }
    }
  }

  return {
    repo_name: repoName,
    image_name: imageName,
    scan_date: extractScanDate(payload),
    source: extractSource(payload),
    schema_version: detectSchemaVersion(payload),
    vulnerabilities,
  };
}

function extractResults(payload: TrivyJson): TrivyResult[] {
  const resultsCandidate = payload.Results ?? payload.results;
  if (!Array.isArray(resultsCandidate)) {
    throw new Error("INVALID_TRIVY_FORMAT: missing Results/results");
  }

  return resultsCandidate.filter((entry): entry is TrivyResult => isObject(entry));
}

function extractPackages(result: TrivyResult): TrivyPackage[] {
  const packages = result.Packages;
  if (Array.isArray(packages) && packages.length > 0) {
    return packages.filter((entry): entry is TrivyPackage => isObject(entry));
  }

  return [{}];
}

function extractPackageVulnerabilities(
  result: TrivyResult,
  pkg: TrivyPackage
): TrivyVulnerability[] {
  const packageVulns = pkg.Vulnerabilities;
  if (Array.isArray(packageVulns)) {
    return packageVulns.filter((entry): entry is TrivyVulnerability => isObject(entry));
  }

  const resultVulns = result.Vulnerabilities ?? (result as Record<string, unknown>).vulnerabilities;
  if (Array.isArray(resultVulns)) {
    return resultVulns.filter((entry): entry is TrivyVulnerability => isObject(entry));
  }

  return [];
}

function normalizeVulnerability(
  pkg: TrivyPackage,
  vuln: TrivyVulnerability
): NormalizedVulnerability | null {
  const cveId = normalizedText(vuln.VulnerabilityID);
  const packageName =
    normalizedText(vuln.PkgName) ??
    normalizedText(pkg.PkgName) ??
    normalizedText(pkg.Name);

  if (!cveId || !packageName) {
    return null;
  }

  const installedVersion =
    normalizedText(vuln.InstalledVersion) ??
    normalizedText(pkg.InstalledVersion) ??
    normalizedText(pkg.Version) ??
    null;

  const fixedVersion = normalizedText(vuln.FixedVersion) ?? null;
  const title = normalizedText(vuln.Title) ?? null;
  const description = normalizedText(vuln.Description) ?? null;

  return {
    cve_id: cveId,
    severity: normalizeSeverity(vuln.Severity),
    package_name: packageName,
    installed_version: installedVersion,
    fixed_version: fixedVersion,
    title,
    description,
    score: extractScore(vuln),
  };
}

function normalizeSeverity(value: unknown): Severity {
  if (typeof value !== "string") {
    return "UNKNOWN";
  }

  const normalized = value.toUpperCase() as Severity;
  return ALLOWED_SEVERITIES.includes(normalized) ? normalized : "UNKNOWN";
}

function extractScore(vuln: TrivyVulnerability): number | null {
  const cvss = vuln.CVSS;
  if (!cvss || typeof cvss !== "object") {
    return null;
  }

  const preferredSources = ["nvd", "redhat", "ghsa"];

  for (const source of preferredSources) {
    const score = cvss[source]?.V3Score;
    if (typeof score === "number") {
      return score;
    }
  }

  for (const entry of Object.values(cvss)) {
    if (entry && typeof entry.V3Score === "number") {
      return entry.V3Score;
    }
  }

  return null;
}

function extractArtifactName(payload: TrivyJson): string {
  return (
    normalizedText(payload.ArtifactName) ??
    normalizedText(payload.artifactName) ??
    "unknown-image"
  );
}

function splitArtifact(artifactName: string): { repoName: string; imageName: string } {
  const imageName = artifactName;

  const digestIndex = artifactName.indexOf("@");
  const withoutDigest = digestIndex >= 0 ? artifactName.slice(0, digestIndex) : artifactName;

  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");

  const hasTag = lastColon > lastSlash;
  const repoName = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;

  return {
    repoName: repoName || "unknown-repository",
    imageName: imageName || "unknown-image",
  };
}

function extractSource(payload: TrivyJson): string {
  return normalizedText(payload.Metadata?.Source) ?? "manual";
}

function extractScanDate(payload: TrivyJson): string {
  return normalizedText(payload.Metadata?.CreatedAt) ?? new Date().toISOString();
}

function normalizedText(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

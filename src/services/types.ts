export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface TrivyVulnerability {
  VulnerabilityID?: string;
  Severity?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  CVSS?: Record<string, { V3Score?: number }>;
}

export interface TrivyPackage {
  Name?: string;
  Version?: string;
  PkgName?: string;
  InstalledVersion?: string;
  Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Packages?: TrivyPackage[];
  Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyJson {
  SchemaVersion?: number | string;
  ArtifactName?: string;
  artifactName?: string;
  Metadata?: {
    TrivyVersion?: string;
    Source?: string;
    CreatedAt?: string;
    [key: string]: unknown;
  };
  Results?: TrivyResult[];
  results?: TrivyResult[];
  [key: string]: unknown;
}

export interface NormalizedVulnerability {
  cve_id: string;
  severity: Severity;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  description: string | null;
  score: number | null;
}

export interface ParseResult {
  repo_name: string;
  image_name: string;
  scan_date: string;
  source: string;
  schema_version: string;
  vulnerabilities: NormalizedVulnerability[];
}

export interface Repository {
  id: number;
  name: string;
  created_at: string;
}

export interface Image {
  id: number;
  repository_id: number;
  name: string;
  last_scanned_at: string | null;
}

export interface ScanResult {
  id: number;
  image_id: number;
  scan_date: string;
  raw_json: string | null;
  source: string;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  scan_result_id: number;
  cve_id: string;
  severity: Severity;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  description: string | null;
  score: number | null;
  created_at: string;
}

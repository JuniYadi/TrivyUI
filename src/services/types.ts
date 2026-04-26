export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface SeverityBreakdown {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
}

export interface DashboardTopRepository {
  id: number;
  name: string;
  vulnerability_count: number;
  critical_count: number;
}

export interface DashboardRecentScan {
  id: number;
  repository: string;
  image: string;
  vulnerability_count: number;
  critical_count: number;
  scanned_at: string;
}

export interface DashboardStats {
  total_vulnerabilities: number;
  total_repositories: number;
  total_images: number;
  by_severity: SeverityBreakdown;
  top_repositories: DashboardTopRepository[];
  recent_scans: DashboardRecentScan[];
}

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

export type VulnerabilitySortField = "cve_id" | "severity" | "package_name" | "score" | "scanned_at";

export interface VulnerabilityWithRelations extends Vulnerability {
  repository: {
    id: number;
    name: string;
  };
  image: {
    id: number;
    name: string;
  };
  scanned_at: string;
}

export interface VulnerabilityListResponse {
  items: VulnerabilityWithRelations[];
  pagination: {
    page: number;
    limit: number;
    total_items: number;
    total_pages: number;
  };
}

export type VulnerabilityDetailResponse = VulnerabilityWithRelations;

export type RepositorySortField = "name" | "vulnerability_count" | "critical_count" | "last_scanned_at";

export interface RepositoryListItem {
  id: number;
  name: string;
  vulnerability_count: number;
  critical_count: number;
  last_scanned_at: string | null;
}

export interface RepositoryImageSummary {
  id: number;
  name: string;
  last_scanned_at: string | null;
  vulnerability_count: number;
  critical_count: number;
}

export interface RepositoryDetailResponse {
  id: number;
  name: string;
  created_at: string;
  by_severity: SeverityBreakdown;
  images: RepositoryImageSummary[];
  vulnerabilities: VulnerabilityWithRelations[];
}

export interface RepositoryListResponse {
  items: RepositoryListItem[];
  pagination: {
    page: number;
    limit: number;
    total_items: number;
    total_pages: number;
  };
}

export type ImageSortField = "name" | "repository" | "vulnerability_count" | "critical_count" | "last_scanned_at";

export interface ImageListItem {
  id: number;
  name: string;
  repository: {
    id: number;
    name: string;
  };
  vulnerability_count: number;
  critical_count: number;
  last_scanned_at: string | null;
}

export interface ImageListResponse {
  items: ImageListItem[];
  pagination: {
    page: number;
    limit: number;
    total_items: number;
    total_pages: number;
  };
}

export interface ImageDetailResponse {
  id: number;
  name: string;
  repository: {
    id: number;
    name: string;
  };
  created_at: string;
  last_scanned_at: string | null;
  by_severity: SeverityBreakdown;
  vulnerabilities: VulnerabilityWithRelations[];
}


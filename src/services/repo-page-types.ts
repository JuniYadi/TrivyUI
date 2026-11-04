import type { RepoVulnerabilityRow, RepositoryDetail, SeverityCounts } from "./repo-state";

/** Client-facing response shapes for the repository and image pages (type-only module). */
export type { RepositoryDetail, RepoVulnerabilityRow, SeverityCounts };

export interface PaginationMeta {
  page: number;
  limit: number;
  total_items: number;
  total_pages: number;
}

export interface RepoListItem {
  id: number;
  name: string;
  registry: string | null;
  tag_count: number;
  by_severity: SeverityCounts;
  vulnerability_count: number;
  critical_count: number;
  fixable_count: number;
  last_scanned_at: string | null;
}

export interface RepoListResponse {
  items: RepoListItem[];
  summary: { repositories: number; open: number; fixable: number };
  pagination: PaginationMeta;
}

export interface RepoVulnerabilityPage {
  items: RepoVulnerabilityRow[];
  pagination: PaginationMeta;
}

export interface ImageListRow {
  id: number;
  name: string;
  tag: string | null;
  tag_group: string;
  is_latest: boolean;
  by_severity: SeverityCounts;
  open: number;
  critical: number;
  change: { total: number; critical: number; previous_tag: string | null } | null;
  digest: string | null;
  last_scanned_at: string;
}

export interface ImageListGroup {
  repository: { id: number; name: string; registry: string | null };
  tag_count: number;
  open: number;
  critical: number;
  last_scanned_at: string | null;
  images: ImageListRow[];
}

export interface ImageListResponse {
  groups: ImageListGroup[];
  summary: { repositories: number; images: number };
  pagination: PaginationMeta;
}

export interface ImageDetailVulnerability {
  id: number;
  cve_id: string;
  severity: string;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  score: number | null;
}

export interface ImageDetailData {
  id: number;
  name: string;
  tag: string | null;
  tag_group: string;
  is_latest: boolean;
  repository: { id: number; name: string; registry: string | null };
  created_at: string | null;
  last_scanned_at: string | null;
  os: string | null;
  digest: string | null;
  by_severity: SeverityCounts;
  open: number;
  fixable: number;
  change: { open: number; critical: number; previous_tag: string | null } | null;
  total_packages: number;
  items: ImageDetailVulnerability[];
  pagination: PaginationMeta;
}

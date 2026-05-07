export const OPEN_VULNERABILITY_STATE_CTE = `
WITH ranked_group_scans AS (
  SELECT
    sr.id AS scan_result_id,
    i.repository_id AS repository_id,
    i.tag_group AS tag_group,
    ROW_NUMBER() OVER (
      PARTITION BY i.repository_id, i.tag_group
      ORDER BY datetime(sr.scan_date) DESC, sr.id DESC
    ) AS row_num
  FROM scan_results sr
  JOIN images i ON i.id = sr.image_id
),
latest_group_scans AS (
  SELECT scan_result_id, repository_id, tag_group
  FROM ranked_group_scans
  WHERE row_num = 1
),
open_vulnerabilities AS (
  SELECT
    v.id,
    v.scan_result_id,
    v.cve_id,
    v.severity,
    v.package_name,
    v.installed_version,
    lgs.repository_id,
    lgs.tag_group
  FROM latest_group_scans lgs
  JOIN vulnerabilities v ON v.scan_result_id = lgs.scan_result_id
)
`;

export function withOpenVulnerabilityState(sql: string): string {
  return `${OPEN_VULNERABILITY_STATE_CTE}${sql}`;
}

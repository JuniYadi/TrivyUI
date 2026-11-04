import type { Database } from "bun:sqlite";
import { ensureTrivyIgnoreSchema } from "./trivy-ignore-schema";
import type { NormalizedSuppressedFinding } from "./types";

export function insertSuppressedFindings(
  db: Database,
  scanResultId: number,
  findings: NormalizedSuppressedFinding[] | undefined,
): void {
  if (!findings || findings.length === 0) {
    return;
  }

  ensureTrivyIgnoreSchema(db);
  const insert = db.query(`
    INSERT INTO suppressed_findings
      (scan_result_id, cve_id, severity, package_name, installed_version, fixed_version, status, statement, source)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
  `);

  db.transaction(() => {
    for (const f of findings) {
      insert.run(
        scanResultId,
        f.cve_id,
        f.severity,
        f.package_name,
        f.installed_version,
        f.fixed_version,
        f.status,
        f.statement,
        f.source,
      );
    }
  })();
}

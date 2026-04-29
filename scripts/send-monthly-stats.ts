import { initDb } from "../src/db";
import { runMonthlyVulnerabilityStats } from "../src/services/scheduled-notifications";

const db = initDb(process.env.DB_PATH || "trivy.db");

try {
  const result = await runMonthlyVulnerabilityStats(db, {
    dryRun: process.argv.includes("--dry-run"),
  });
  console.log("[monthly-stats]", result.status, result.reason, `count=${result.totalCount}`);
} finally {
  db.close();
}

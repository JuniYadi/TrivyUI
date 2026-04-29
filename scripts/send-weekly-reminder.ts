import { initDb } from "../src/db";
import { runWeeklyExistingVulnerabilityReminder } from "../src/services/scheduled-notifications";

const db = initDb(process.env.DB_PATH || "trivy.db");

try {
  const result = await runWeeklyExistingVulnerabilityReminder(db, {
    dryRun: process.argv.includes("--dry-run"),
  });
  console.log("[weekly-reminder]", result.status, result.reason, `count=${result.totalCount}`);
} finally {
  db.close();
}

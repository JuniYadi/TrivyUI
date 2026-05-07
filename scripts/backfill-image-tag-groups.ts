import { Database } from "bun:sqlite";
import { parseImageTagGrouping } from "../src/services/image-tag-grouping";

type ImageRow = {
  id: number;
  name: string;
  repository_base: string | null;
  tag: string | null;
  tag_group: string | null;
};

const dbPath = process.env.TRIVYUI_DB_PATH || "trivy.db";
const db = new Database(dbPath, { create: true });

try {
  console.log("[DB] Checking DB and comparation for patch");

  const rows = db
    .query("SELECT id, name, repository_base, tag, tag_group FROM images")
    .all() as ImageRow[];

  let updated = 0;

  for (const row of rows) {
    const parsed = parseImageTagGrouping(row.name);

    const currentRepositoryBase = (row.repository_base || "").trim();
    const nextRepositoryBase = currentRepositoryBase || parsed.repository_base;

    const nextTag = row.tag ?? parsed.tag;

    const currentTagGroup = (row.tag_group || "").trim();
    const nextTagGroup = currentTagGroup && currentTagGroup !== "ungrouped" ? currentTagGroup : parsed.tag_group;

    const shouldUpdate =
      currentRepositoryBase !== nextRepositoryBase ||
      (row.tag || null) !== (nextTag || null) ||
      currentTagGroup !== nextTagGroup;

    if (!shouldUpdate) {
      continue;
    }

    db.query("UPDATE images SET repository_base = ?1, tag = ?2, tag_group = ?3 WHERE id = ?4").run(nextRepositoryBase, nextTag, nextTagGroup, row.id);
    updated += 1;
  }

  if (updated === 0) {
    console.log("[DB] ✅ all good");
  } else {
    console.log(`[DB] ❗ Patch ${updated} Data on images Table`);
  }
} finally {
  db.close();
}

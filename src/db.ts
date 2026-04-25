import { Database } from "bun:sqlite";

export type TrivyUiDb = Database;

export function initDb(path = "trivy.db"): TrivyUiDb {
  const db = new Database(path, { create: true });

  db.exec(`
    CREATE TABLE IF NOT EXISTS _health_check (
      id INTEGER PRIMARY KEY,
      msg TEXT NOT NULL DEFAULT 'ok'
    );

    INSERT OR IGNORE INTO _health_check (id, msg)
    VALUES (1, 'ok');
  `);

  return db;
}

export function getHealthMessage(db: TrivyUiDb): string {
  const row = db
    .query("SELECT msg FROM _health_check WHERE id = 1")
    .get() as { msg: string } | null;

  return row?.msg ?? "ok";
}

import { SQL } from "bun";
import type { DatabaseDriver, DbDialect, ExecuteResult } from "../driver";

function normalizeSql(sql: string, dialect: DbDialect): string {
  if (dialect !== "postgres") {
    return sql.replace(/\?(\d+)/g, "?");
  }

  const explicitMatches = [...sql.matchAll(/\?(\d+)/g)].map((m) => Number(m[1]));
  let nextIndex = explicitMatches.length > 0 ? Math.max(...explicitMatches) + 1 : 1;

  return sql
    .replace(/\?(\d+)/g, (_full, idx) => `$${idx}`)
    .replace(/\?(?!\d)/g, () => `$${nextIndex++}`);
}

async function resolveLastInsertId(client: SQL, dialect: DbDialect): Promise<number | null> {
  if (dialect === "sqlite") {
    const rows = (await client.unsafe("SELECT last_insert_rowid() AS id")) as Array<{ id: number }>;
    return rows[0]?.id ? Number(rows[0].id) : null;
  }

  if (dialect === "mysql") {
    const rows = (await client.unsafe("SELECT LAST_INSERT_ID() AS id")) as Array<{ id: number }>;
    return rows[0]?.id ? Number(rows[0].id) : null;
  }

  return null;
}

export class SqlDriver implements DatabaseDriver {
  constructor(
    public readonly dialect: DbDialect,
    private readonly client: SQL,
  ) {}

  async execute(sql: string, params: unknown[] = []): Promise<ExecuteResult> {
    const normalized = normalizeSql(sql, this.dialect);
    const rows = (await this.client.unsafe(normalized, params)) as unknown[];

    const isInsert = /^\s*insert\b/i.test(sql);
    const lastInsertId = isInsert ? await resolveLastInsertId(this.client, this.dialect) : null;

    return {
      rowCount: Array.isArray(rows) ? rows.length : 0,
      lastInsertId,
    };
  }

  async queryOne<T>(sql: string, params: unknown[] = []): Promise<T | null> {
    const normalized = normalizeSql(sql, this.dialect);
    const rows = (await this.client.unsafe(normalized, params)) as T[];
    return rows[0] ?? null;
  }

  async queryAll<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    const normalized = normalizeSql(sql, this.dialect);
    return (await this.client.unsafe(normalized, params)) as T[];
  }

  async transaction<T>(fn: (tx: DatabaseDriver) => Promise<T>): Promise<T> {
    return this.client.begin(async (txClient) => {
      const txDriver = new SqlDriver(this.dialect, txClient);
      return fn(txDriver);
    });
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

export function createSqlDriver(dialect: DbDialect, connectionString: string): DatabaseDriver {
  return new SqlDriver(dialect, new SQL(connectionString));
}

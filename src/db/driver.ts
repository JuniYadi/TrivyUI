export type DbDialect = "sqlite" | "mysql" | "postgres";

export interface ExecuteResult {
  rowCount: number;
  lastInsertId: number | null;
}

export interface DatabaseDriver {
  readonly dialect: DbDialect;
  execute(sql: string, params?: unknown[]): Promise<ExecuteResult>;
  queryOne<T>(sql: string, params?: unknown[]): Promise<T | null>;
  queryAll<T>(sql: string, params?: unknown[]): Promise<T[]>;
  transaction<T>(fn: (tx: DatabaseDriver) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

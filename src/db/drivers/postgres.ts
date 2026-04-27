import type { DatabaseDriver } from "../driver";
import { createSqlDriver } from "./sql-driver";

export function createPostgresDriver(connectionString: string): DatabaseDriver {
  return createSqlDriver("postgres", connectionString);
}

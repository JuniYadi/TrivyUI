import type { DatabaseDriver } from "../driver";
import { createSqlDriver } from "./sql-driver";

export function createMysqlDriver(connectionString: string): DatabaseDriver {
  return createSqlDriver("mysql", connectionString);
}

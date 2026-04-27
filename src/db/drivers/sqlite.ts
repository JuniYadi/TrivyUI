import type { DatabaseDriver } from "../driver";
import { createSqlDriver } from "./sql-driver";

export function createSqliteDriver(path = ":memory:"): DatabaseDriver {
  return createSqlDriver("sqlite", path);
}

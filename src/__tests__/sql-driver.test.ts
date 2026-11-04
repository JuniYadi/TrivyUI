import { describe, expect, test } from "bun:test";
import type { SQL } from "bun";
import { SqlDriver, createSqlDriver } from "../db/drivers/sql-driver";

function fakeClient(rowsByCall: unknown[][] = []) {
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  let closed = false;
  const client = {
    unsafe: async (sql: string, params: unknown[] = []) => {
      calls.push({ sql, params });
      return rowsByCall.shift() ?? [];
    },
    begin: async (fn: (tx: unknown) => Promise<unknown>) => fn(client),
    close: async () => {
      closed = true;
    },
  };
  return { client: client as unknown as SQL, calls, isClosed: () => closed };
}

describe("SqlDriver", () => {
  test("postgres rewrites explicit and positional placeholders", async () => {
    const { client, calls } = fakeClient();
    const db = new SqlDriver("postgres", client);
    await db.queryAll("SELECT * FROM t WHERE a = ?1 AND b = ?", [1, 2]);
    expect(calls[0]?.sql).toBe("SELECT * FROM t WHERE a = $1 AND b = $2");
    await db.queryAll("SELECT ? , ?", [1, 2]);
    expect(calls[1]?.sql).toBe("SELECT $1 , $2");
  });

  test("mysql and sqlite collapse numbered placeholders", async () => {
    const { client, calls } = fakeClient();
    await new SqlDriver("mysql", client).queryOne("SELECT ?1", [1]);
    expect(calls[0]?.sql).toBe("SELECT ?");
  });

  test("execute resolves lastInsertId for sqlite, mysql and not for postgres", async () => {
    const sqlite = fakeClient([[], [{ id: 5 }]]);
    expect((await new SqlDriver("sqlite", sqlite.client).execute("INSERT INTO t VALUES (1)")).lastInsertId).toBe(5);

    const mysql = fakeClient([[], [{ id: 9 }]]);
    expect((await new SqlDriver("mysql", mysql.client).execute(" insert into t values (1)")).lastInsertId).toBe(9);

    const mysqlEmpty = fakeClient([[], [{ id: 0 }]]);
    expect((await new SqlDriver("mysql", mysqlEmpty.client).execute("INSERT INTO t VALUES (1)")).lastInsertId).toBeNull();

    const pg = fakeClient([[{ id: 1 }]]);
    const result = await new SqlDriver("postgres", pg.client).execute("INSERT INTO t VALUES (1)");
    expect(result).toEqual({ rowCount: 1, lastInsertId: null });
    expect(pg.calls).toHaveLength(1);

    const update = fakeClient();
    expect((await new SqlDriver("sqlite", update.client).execute("UPDATE t SET a = 1")).lastInsertId).toBeNull();
  });

  test("queryOne returns null for no rows", async () => {
    const { client } = fakeClient();
    expect(await new SqlDriver("sqlite", client).queryOne("SELECT 1")).toBeNull();
  });

  test("transaction runs callback with a tx driver and close closes the client", async () => {
    const { client, calls, isClosed } = fakeClient();
    const db = new SqlDriver("sqlite", client);
    const value = await db.transaction(async (tx) => {
      await tx.execute("UPDATE t SET a = 1");
      return "done";
    });
    expect(value).toBe("done");
    expect(calls).toHaveLength(1);
    await db.close();
    expect(isClosed()).toBe(true);
  });

  test("createSqlDriver builds a working sqlite driver", async () => {
    const db = createSqlDriver("sqlite", ":memory:");
    await db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)");
    const res = await db.execute("INSERT INTO t (v) VALUES (?1)", ["x"]);
    expect(res.lastInsertId).toBe(1);
    expect(await db.queryOne<{ v: string }>("SELECT v FROM t")).toEqual({ v: "x" });
    await db.close();
  });
});

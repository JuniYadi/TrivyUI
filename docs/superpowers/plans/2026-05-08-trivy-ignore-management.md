# Trivy Ignore Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated Trivy ignore management page and protected generation endpoint.

**Architecture:** Two SQLite tables store ignore rules and optional tag patterns. Management endpoints return structured data; generate endpoint returns newline-separated CVE IDs. The frontend page consumes management endpoints and writes tags using wildcard patterns.

**Tech Stack:** Bun, Bun SQLite, React 18, TanStack Router, TypeScript, Bun test.

---

### Task 1: Persist ignore data in DB schema

**Files:**
- Modify: `src/db.ts`
- Modify: `src/db/schema.ts`
- Modify: `src/__tests__/db-schema.test.ts`

- [ ] **Step 1: Add ignore table DDL in `src/db.ts`**

```ts
const fullSchema = `
  CREATE TABLE IF NOT EXISTS trivy_ignores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT 'all_tags' CHECK(scope IN ('all_tags', 'selected_tags')),
    reason TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS trivy_ignore_tags (
    ignore_id INTEGER NOT NULL REFERENCES trivy_ignores(id) ON DELETE CASCADE,
    tag_group TEXT NOT NULL,
    PRIMARY KEY (ignore_id, tag_group)
  );

  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_cve_id ON trivy_ignores(cve_id);
  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_repository_id ON trivy_ignores(repository_id);
  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_expires_at ON trivy_ignores(expires_at);
`;
```

- [ ] **Step 2: Add SQLite schema evolver for existing DBs in `src/db.ts`**

```ts
function tableExists(db: TrivyUiDb, name: string): boolean {
  const rows = db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1").all(name);
  return rows.length > 0;
}

function evolveTrivyIgnoreSchema(db: TrivyUiDb): void {
  if (!tableExists(db, "trivy_ignores")) {
    db.exec("CREATE TABLE IF NOT EXISTS trivy_ignores (id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL, repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE, scope TEXT NOT NULL DEFAULT 'all_tags' CHECK(scope IN ('all_tags', 'selected_tags')), reason TEXT, expires_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
  }
  if (!tableExists(db, "trivy_ignore_tags")) {
    db.exec("CREATE TABLE IF NOT EXISTS trivy_ignore_tags (ignore_id INTEGER NOT NULL REFERENCES trivy_ignores(id) ON DELETE CASCADE, tag_group TEXT NOT NULL, PRIMARY KEY (ignore_id, tag_group))");
  }
}
```

- [ ] **Step 3: Call evolver in `initFullSchema` after schema creation**

```ts
export function initFullSchema(db: TrivyUiDb): void {
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(FULL_SCHEMA_SQL);
  evolveTrivyIgnoreSchema(db);
  backfillImageTagGroups(db);
}
```

- [ ] **Step 4: Add same tables to multi-db schema in `src/db/schema.ts`**

```ts
statements.push(`
  CREATE TABLE IF NOT EXISTS trivy_ignores (
    id ${idType(dialect)},
    cve_id TEXT NOT NULL,
    repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT 'all_tags',
    reason TEXT,
    expires_at ${ts},
    created_at ${ts} DEFAULT CURRENT_TIMESTAMP
  )
`);

statements.push(`
  CREATE TABLE IF NOT EXISTS trivy_ignore_tags (
    ignore_id INTEGER NOT NULL REFERENCES trivy_ignores(id) ON DELETE CASCADE,
    tag_group TEXT NOT NULL,
    PRIMARY KEY (ignore_id, tag_group)
  )
`);
```

- [ ] **Step 5: Assert new tables in schema test**

```ts
expect(getTables(db)).toContain("trivy_ignores");
expect(getTables(db)).toContain("trivy_ignore_tags");
```

- [ ] **Step 6: Run and commit Task 1**

Run: `bun test src/__tests__/db-schema.test.ts`
```bash
```

### Task 2: Ignore service layer

**Files:**
- Create: `src/services/trivy-ignore.ts`
- Create: `src/__tests__/trivy-ignore-service.test.ts`

- [ ] **Step 1: Add normalized interfaces and helpers in `src/services/trivy-ignore.ts`**

```ts
interface TrivyIgnoreRepositoryRow {
  id: number;
  cve_id: string;
  repository_id: number | null;
  repository_name: string | null;
  scope: "all_tags" | "selected_tags";
  reason: string | null;
  expires_at: string | null;
  created_at: string;
  tag_group: string | null;
}

export interface CreateTrivyIgnoreInput {
  cve_id: string;
  repository_id: number | null;
  scope: "all_tags" | "selected_tags";
  tag_groups?: string[];
  reason?: string | null;
  expires_at?: string | null;
}
```

- [ ] **Step 2: Implement CRUD helpers and generator in `src/services/trivy-ignore.ts`**

```ts
export function createTrivyIgnore(db: Database, input: CreateTrivyIgnoreInput): number { ... }
export function listTrivyIgnores(db: Database, repositoryId: number | null | undefined): TrivyIgnoreRepositoryRow[] { ... }
export function deleteTrivyIgnore(db: Database, id: number): boolean { ... }
export function generateTrivyIgnoreText(db: Database, repoName?: string | null, tag?: string | null): string { ... }
```

- [ ] **Step 3: Assert repository/tag semantics with service tests**

```ts
expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api", "dev-1")).toEqual("CVE-2026-0001\nCVE-2026-0100\n");
expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api")).toEqual("CVE-2026-0001\n");
expect(generateTrivyIgnoreText(db)).toEqual("CVE-2026-GLOBAL\n");
expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api", "prod-1")).not.toContain("CVE-DEV-DEV");
```

- [ ] **Step 4: Run service tests and commit**

Run: `bun test src/__tests__/trivy-ignore-service.test.ts`
```bash
```

### Task 3: Management and generation API routes

**Files:**
- Create: `src/routes/api/trivy-ignore.ts`
- Create: `src/routes/api/trivy-ignore-generate.ts`
- Modify: `src/index.ts`
- Modify: `src/services/api-key-auth.ts`
- Create: `src/__tests__/trivy-ignore-api.test.ts`

- [ ] **Step 1: Implement CRUD handler in `src/routes/api/trivy-ignore.ts`**

```ts
export function createTrivyIgnoreHandler(db: Database) {
  return async function trivyIgnoreHandler(request: Request): Promise<Response> {
    if (request.method === "GET") return buildSuccessResponse(listTrivyIgnores(...));
    if (request.method === "POST") return buildSuccessResponse(createTrivyIgnore(...), 201);
    if (request.method === "DELETE") return buildSuccessResponse({ id, removed: true });
    return sendError(405, "METHOD_NOT_ALLOWED", "...");
  };
}
```

- [ ] **Step 2: Implement generate handler in `src/routes/api/trivy-ignore-generate.ts`**

```ts
export function createTrivyIgnoreGenerateHandler(db: Database) {
  return async function trivyIgnoreGenerateHandler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const text = generateTrivyIgnoreText(db, url.searchParams.get("repo"), url.searchParams.get("tag"));
    return new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } });
  };
}
```

- [ ] **Step 3: Wire both routes in `src/index.ts`**

```ts
if (pathname === "/api/trivy-ignores" || pathname.startsWith("/api/trivy-ignores/")) {
  return trivyIgnoreHandler(request);
}

if (pathname === "/api/trivy-ignore/generate") {
  return trivyIgnoreGenerateHandler(request);
}
```

- [ ] **Step 4: Protect GET generate endpoint in `src/services/api-key-auth.ts`**

```ts
if (method === "GET" && !isProtectedGetEndpoint(pathname)) {
  return null;
}
```

- [ ] **Step 5: Add route tests for auth + CRUD + generation**

```ts
expect(response.status).toBe(401); // GET /api/trivy-ignore/generate without key
expect(response.status).toBe(201); // POST /api/trivy-ignores
expect(await response.text()).toContain("CVE-2026");
```

- [ ] **Step 6: Run tests and commit Task 3**

Run: `bun test src/__tests__/trivy-ignore-api.test.ts src/__tests__/api-key-auth.test.ts`
```bash
```

### Task 4: Frontend page and navigation

**Files:**
- Create: `src/routes/trivy-ignore.tsx`
- Create: `src/hooks/use-trivy-ignores.ts`
- Modify: `src/router.tsx`
- Modify: `src/components/app-shell.tsx`

- [ ] **Step 1: Register route and nav entry**

```ts
// router.tsx
import { TrivyIgnorePage } from "./routes/trivy-ignore";
path: "/trivy-ignore",
APP_ROUTE_PATHS.push("/trivy-ignore");

// app-shell.tsx
to="/trivy-ignore"
```

- [ ] **Step 2: Implement hook and types**

```ts
export function useTrivyIgnores(repoFilter?: number) {
  // state: list, loading, error
  // methods: loadIgnores, createIgnore, deleteIgnore
}
```

- [ ] **Step 3: Implement management page with wildcard tag pattern chips**

```tsx
const [tagPatternInput, setTagPatternInput] = useState("");
const addPattern = (value) => setPatterns((prev) => [...prev.filter((p) => p !== value), value]);
```

- [ ] **Step 4: Validate UI behavior manually and run build**

```bash
bun run build
```

- [ ] **Step 5: Commit Task 4 changes**

```bash
```

### Task 5: Final verification

- [ ] **Step 1: Run service/API + full smoke tests**

Run: `bun test src/__tests__/trivy-ignore-service.test.ts src/__tests__/trivy-ignore-api.test.ts src/__tests__/api-key-auth.test.ts`

- [ ] **Step 2: Run build for production output validation**

Run: `bun run build`

- [ ] **Step 3: Commit remaining docs/fixups**

```bash
```

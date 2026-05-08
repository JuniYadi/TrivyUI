# Trivy Ignore Management Design

## Goal
Provide a dedicated page to manage `.trivyignore` rules and API endpoints to generate CI-ready ignore files based on repository and tag scope.

## Scope
- Store suppressions for CVE IDs with optional repository and tag-scoped rules.
- Support global ignores that apply to all repositories.
- Support per-repository ignores for all tags or selected tag patterns.
- Support tag patterns using glob syntax, e.g. `dev-*`, `stg-*`.
- Render CI-friendly `.trivyignore` content (newline-separated CVE list) from a protected API.

## Data Model

```sql
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
```

## Routing and APIs

### Management endpoints (no auth)
- `GET /api/trivy-ignores?repo_id={id}`
  - List active + expired entries for optional repository filter.
- `POST /api/trivy-ignores`
  - Create one ignore row and optional pattern rows.
  - Payload: `{"cve_id":"CVE-2026-9999","repository_id":1,"scope":"selected_tags","tag_groups":["dev-*","stg-*"],"reason":"vendor lag","expires_at":null}`
- `DELETE /api/trivy-ignores/:id`
  - Delete entry and associated patterns.

### Generate endpoint (API key required)
- `GET /api/trivy-ignore/generate?repo=<repository_name>&tag=<tag>`
  - `repo` optional; when omitted returns global ignores only.
  - `tag` optional; if present, include repository all-tags + matching selected-tags.
  - If `tag` omitted and repo is set, only include repository ignores with `all_tags` scope.
  - Return type: `text/plain`
  - Body: `CVE-2026-1111\nCVE-2026-2222\n`

## Matching semantics
- Global ignores: `repository_id IS NULL`, expiry-null or future expiry.
- Repo-level all tags: `scope = 'all_tags'` and repository match.
- Repo-level selected tags: `scope = 'selected_tags'` and `tag_group` pattern matches query tag by SQLite `GLOB`.
- Expired rows are excluded from generation by default.

## UI page (`/trivy-ignore`)
- Add new route and nav item.
- Provide:
  - Form with CVE ID, repository selector (`Global` included), scope, tag pattern chips, optional reason, optional expiry.
  - Ignore list with columns: CVE, repository, scope/tags, reason, expiry, created at, actions.
  - Example `curl` for generation endpoint and copy-ready endpoint URL.

## Required changes by layer

### Backend
1. Add schema entries + evolution path for existing SQLite DBs and include multi-DB schema support.
2. Add service utilities for CRUD and generation query.
3. Add API handlers and wire routes in `src/index.ts`.
4. Update API key enforcement to protect `/api/trivy-ignore/generate`.

### Frontend
1. Add route `/trivy-ignore` and link in app shell nav.
2. Add page UI with list + create/delete actions.
3. Add data fetching for repositories for scope picker.

## Acceptance criteria
1. Global + repo scoped ignores are persisted and listed.
2. Selected tag pattern matching accepts `*` wildcards.
3. Repo+tag query returns only matching patterns plus all-tags/global rules.
4. Repo without tag returns only all-tags + global.
5. `/api/trivy-ignore/generate` is blocked when API key missing/invalid.
6. Generated payload is newline-separated CVE IDs.

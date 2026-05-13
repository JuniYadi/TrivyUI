# TrivyUI
Vulnerability Dashboard for Trivy Scanner

## Environment Variables

Copy `.env.example` to `.env` (or export these in your runtime).

```bash
PORT=3000
API_KEY_ENABLED=false
TRIVYUI_DB_PATH=trivy.db
# MYSQL_URL=mysql://user:password@127.0.0.1:3306/trivyui

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=trivyui@company.com
SMTP_PASS=app-password-here
SMTP_FROM="TrivyUI <trivyui@company.com>"
SMTP_TO=devops@company.com,security@company.com

NOTIFY_ENABLED=false
NOTIFY_MIN_SEVERITY=HIGH
APP_BASE_URL=http://localhost:3000

# Optional scan retention (opt-in; defaults keep scans unlimited)
RETENTION_ENABLED=false
RETENTION_DEFAULT_KEEP=unlimited
RETENTION_GROUP_RULES=dev-*:10,stg-*:10,prd-*:unlimited,prod-*:unlimited,production-*:unlimited
RETENTION_REPO_RULES=

```

Variable reference:
- `PORT`: HTTP server port for Bun (`3000` default).
- `API_KEY_ENABLED`: enables API key enforcement for `POST /api/*` when set to `true`.
- `TRIVYUI_DB_PATH`: SQLite file path used by current runtime and by `bun run db:seed-dashboard`.
- `MYSQL_URL`: MySQL connection string example for DB-driver based integrations.
- `SMTP_HOST`: SMTP server host.
- `SMTP_PORT`: SMTP server port (`587` for STARTTLS, `465` for SMTPS).
- `SMTP_SECURE`: `true` for implicit TLS (usually port `465`), `false` otherwise.
- `SMTP_USER` / `SMTP_PASS`: SMTP auth credentials.
- `SMTP_FROM`: sender address shown in email.
- `SMTP_TO`: comma-separated recipient list.
- `NOTIFY_ENABLED`: enables/disables notifications globally.
- `NOTIFY_MIN_SEVERITY`: minimum severity trigger (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
- `APP_BASE_URL`: base URL used for dashboard links in email body.
- `RETENTION_ENABLED`: enables scan-retention cleanup when set to `true` (opt-in; `false` by default).
- `RETENTION_DEFAULT_KEEP`: fallback keep policy when no rule matches (`unlimited` by default).
- `RETENTION_GROUP_RULES`: comma-separated `<pattern>:<keep>` rules by scan group name.
- `RETENTION_REPO_RULES`: comma-separated `<pattern>:<keep>` rules by repository/image name; higher priority than `RETENTION_GROUP_RULES`.

Practical retention example:
- Use `RETENTION_GROUP_RULES=dev-*:10,stg-*:10,prd-*:unlimited,prod-*:unlimited,production-*:unlimited` to keep only the newest 10 scans for dev/stg groups while keeping prod groups unlimited.
- Set `RETENTION_ENABLED=true` to apply rules; leave `RETENTION_DEFAULT_KEEP=unlimited` to keep unmatched groups/repos untouched.
- Leave `RETENTION_REPO_RULES=` empty to disable per-repo overrides.

Notes:
- Current HTTP runtime in `src/index.ts` initializes SQLite (`initDb()`), so `MYSQL_URL` is documented as connection format reference.
- Upload/webhook API stays successful even when SMTP send fails.
- Failed notification attempts are recorded in `notifications` table with status `failed` and an error message.

## Generate Trivy JSON

Create a JSON report from Trivy first, then upload it via UI or API.

```bash
# image scan example
trivy image --format json --output trivy-image.json nginx:latest

# filesystem scan example
trivy fs --format json --output trivy-fs.json .
```

Notes:
- Use `--format json` and `--output <file>.json`.
- Keep each file under 10 MB (larger files are rejected by API).

## Upload via UI

1. Start the app and open `http://localhost:3000/upload`.
2. Choose one input method:
   - File mode: click `Choose Files` or drag/drop one or more `.json` files.
   - Paste mode: copy JSON from CI output/artifacts and paste it into `Paste JSON directly`.
3. Click `Upload File` / `Upload Batch` (file mode) or `Upload Pasted JSON` (paste mode).

Behavior:
- 1 file -> UI calls `POST /api/upload`
- multiple files -> UI calls `POST /api/upload/batch`
- pasted JSON -> UI validates JSON syntax first, then calls `POST /api/upload`

If upload fails with `INVALID_TRIVY_FORMAT`, the JSON is valid syntax but not a valid Trivy result structure.

## Upload via API

Single file (`file` field):

```bash
curl -X POST "http://localhost:3000/api/upload" \
  -F "file=@trivy-image.json;type=application/json"
```

Batch upload (`files` field repeated):

```bash
curl -X POST "http://localhost:3000/api/upload/batch" \
  -F "files=@trivy-image.json;type=application/json" \
  -F "files=@trivy-fs.json;type=application/json"
```

Expected responses:
- `201` success
- `400` invalid/missing multipart field
- `413` file too large
- `415` unsupported content type
- `422` JSON is not recognized as Trivy result

## Useful Commands

```bash
PATH="$HOME/.bun/bin:$PATH" bun test
PATH="$HOME/.bun/bin:$PATH" bun run build
PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard
```

`db:seed-dashboard` is for **local development preview only**. It resets local SQLite data and inserts sample repositories/images/scans/vulnerabilities so `/dashboard` can be visually reviewed in non-empty state.

# TrivyUI
Vulnerability Dashboard for Trivy Scanner

## SMTP Setup (Email Notifications)

TrivyUI can send vulnerability alert emails after upload/webhook import.

1. Copy `.env.example` values into your runtime environment (or `.env` if you load it in your setup).
2. Set SMTP and notification variables:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=trivyui@company.com
SMTP_PASS=app-password-here
SMTP_FROM="TrivyUI <trivyui@company.com>"
SMTP_TO=devops@company.com,security@company.com

NOTIFY_ENABLED=true
NOTIFY_MIN_SEVERITY=HIGH
APP_BASE_URL=http://localhost:3000
```

Variable reference:
- `SMTP_HOST`: SMTP server host.
- `SMTP_PORT`: SMTP server port (`587` for STARTTLS, `465` for SMTPS).
- `SMTP_SECURE`: `true` for implicit TLS (usually port `465`), `false` otherwise.
- `SMTP_USER` / `SMTP_PASS`: SMTP auth credentials.
- `SMTP_FROM`: sender address shown in email.
- `SMTP_TO`: comma-separated recipient list.
- `NOTIFY_ENABLED`: enable/disable notifications globally.
- `NOTIFY_MIN_SEVERITY`: minimum severity trigger (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `APP_BASE_URL`: base URL used for dashboard links in email body.

Notes:
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
2. Click `Choose Files` or drag/drop one or more `.json` files.
3. Click `Upload File`.

Behavior:
- 1 file -> UI calls `POST /api/upload`
- multiple files -> UI calls `POST /api/upload/batch`

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

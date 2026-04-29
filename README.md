# TrivyUI
Vulnerability Dashboard for Trivy Scanner

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

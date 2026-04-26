# TrivyUI
Vulnerability Dashboard for Trivy Scanner

## Useful Commands

```bash
PATH="$HOME/.bun/bin:$PATH" bun test
PATH="$HOME/.bun/bin:$PATH" bun run build
PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard
```

`db:seed-dashboard` is for **local development preview only**. It resets local SQLite data and inserts sample repositories/images/scans/vulnerabilities so `/dashboard` can be visually reviewed in non-empty state.

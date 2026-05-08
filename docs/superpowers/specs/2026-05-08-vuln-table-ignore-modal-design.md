# Vulnerability Table One-Click Ignore (Confirm Modal) Design

## Context

TrivyUI already has a Trivy Ignore page and API flow for creating ignore rules:

- UI page: `/trivy-ignore`
- API endpoint: `POST /api/trivy-ignores`
- Data model: `trivy_ignores` with optional tag-scoped rows

The vulnerabilities page (`/vulnerabilities`) currently lets users inspect CVEs but does not let them add ignore rules inline. The goal is to reduce context switching by letting users add repository-scoped ignore rules directly from each vulnerability row.

## Goals

- Add an inline Ignore action from vulnerability rows.
- Use a confirm modal (not blind one-click submit) to avoid accidental ignores.
- Default ignore target to the current repository only.
- Keep compatibility with existing API key-protected environments.
- Reuse existing ignore API instead of adding a new backend endpoint.

## Non-Goals

- Bulk ignore operations.
- Editing existing ignore rules from vulnerabilities page.
- Automatically hiding ignored vulnerabilities from list results.
- Global ignore-by-default behavior.

## Product Decisions

- Default scope from vulnerabilities page is repository-only.
- Scope is fixed to `all_tags` for this flow.
- User can optionally set `reason` and `expires_at` before confirming.
- Duplicate or already-existing ignore attempts should return a friendly UX message.

## User Experience Flow

1. User opens `/vulnerabilities` and sees table rows.
2. Each row includes an `Ignore` button in a dedicated action cell.
3. Clicking `Ignore` opens a modal prefilled with:
   - CVE ID (read-only)
   - Repository (read-only)
   - Scope (read-only: `All tags`)
   - Optional reason input
   - Optional expires-at input
4. User clicks `Confirm Ignore`.
5. UI posts rule to `/api/trivy-ignores`.
6. On success, modal closes and success feedback is shown.
7. On known duplicate/conflict-style failures, UI shows a friendly "already ignored" style message.

## Architecture and Component Boundaries

### `VulnerabilityTable` (presentational)

- Keep table rendering responsibility.
- Add callback prop for ignore action, e.g. `onIgnoreRequest(item)`.
- Ensure Ignore button does not trigger row selection click.

### `VulnerabilitiesPage` (state orchestrator)

- Own modal open/close state.
- Own selected row state for ignore context.
- Own submission states: `busy`, `error`, and `success` feedback.
- Trigger ignore create mutation and map responses to user-facing messages.

### `IgnoreVulnerabilityModal` (new focused component)

- Render read-only CVE/repository/scope fields.
- Render editable optional reason/expires controls.
- Render cancel and confirm actions.
- Disable confirm button during submit.

### API helper reuse

- Reuse existing ignore-create request helper (`createTrivyIgnoreRecord`) and auth header behavior (`buildTrivyIgnoreAuthHeaders`).
- Do not wire vulnerabilities page to full ignore-list fetch unless explicitly needed.

## Data Flow and API Contract

Request:

```json
{
  "cve_id": "CVE-YYYY-NNNN",
  "repository_id": 123,
  "scope": "all_tags",
  "reason": "optional",
  "expires_at": "optional-iso-8601"
}
```

Rules:

- `repository_id` comes from the vulnerability row's repository relationship.
- If the current vulnerability data type does not expose repository id, extend API response typing and mapping accordingly.
- `scope` is always `all_tags` for this flow.
- `tag_groups` is not sent for this flow.

Response handling:

- Success (`201`): close modal, show success message.
- Validation or duplicate-like errors: keep modal behavior predictable and show actionable message.
- Network failure: show retryable error text in modal/page feedback area.

## Error Handling

- Guard against missing repository id in row data; if missing, disable Ignore button and show tooltip/title explaining unavailability.
- Normalize API errors to consistent human-readable messages.
- Map known backend codes/messages to user language:
  - Example: `already exists`/conflict -> "This CVE is already ignored for this repository."

## Security and Auth

- Respect existing optional API key protection.
- Reuse existing localStorage-backed key behavior so vulnerabilities flow works with protected endpoints without extra setup.

## Accessibility

- Modal traps focus and returns focus to triggering Ignore button on close.
- Keyboard support:
  - `Escape` closes modal (unless submitting)
  - `Enter` submits when form valid
- Buttons have clear labels and disabled states.

## Testing Strategy

### Unit/UI tests

- `VulnerabilityTable`:
  - Ignore click triggers `onIgnoreRequest`.
  - Ignore click does not trigger row `onSelect`.

- `IgnoreVulnerabilityModal`:
  - Renders prefilled read-only values.
  - Accepts optional reason/expires values.
  - Confirm button disabled during submission.

### Integration tests

- `VulnerabilitiesPage` flow:
  - Open modal from row action.
  - Submit success path closes modal and shows success feedback.
  - Failure path shows error feedback.

### Request helper tests

- Verify payload shape and API key header propagation for create-ignore requests used by vulnerabilities flow.

## Rollout and Backward Compatibility

- No database schema changes required for baseline flow.
- No API route changes required.
- Existing `/trivy-ignore` page remains canonical for full rule management.

## Open Questions Resolved

- Default scope from vulnerabilities page: repository only.
- Interaction model: confirm modal before submit.

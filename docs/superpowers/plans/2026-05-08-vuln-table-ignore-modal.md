# Vulnerability Table Ignore Modal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-row Ignore action on `/vulnerabilities` that opens a confirm modal and creates a repository-scoped Trivy ignore rule.

**Architecture:** Keep `VulnerabilityTable` presentational and delegate mutation flow to `VulnerabilitiesPage`. Add a focused modal component for confirmation and optional fields (`reason`, `expires_at`), then call existing ignore-create API helpers so auth and error patterns stay consistent.

**Tech Stack:** Bun, React, TypeScript, TanStack Router, existing Trivy ignore API (`/api/trivy-ignores`), bun:test.

---

## File Map

- Modify: `src/components/vulnerability-table.tsx` (add Ignore action cell + callback wiring)
- Create: `src/components/ignore-vulnerability-modal.tsx` (confirm modal UI)
- Modify: `src/routes/vulnerabilities.tsx` (modal state + submit flow + feedback)
- Modify: `src/hooks/use-trivy-ignores.ts` (export small helper for error normalization reuse if needed)
- Modify: `src/services/types.ts` (ensure vulnerability row has repository id reachable from `item.image.repository_id`)
- Test: `src/__tests__/vulnerability-table.test.tsx`
- Test: `src/__tests__/ignore-vulnerability-modal.test.tsx`
- Test: `src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`

### Task 1: Prepare table callback and event isolation

**Files:**
- Modify: `src/components/vulnerability-table.tsx`
- Test: `src/__tests__/vulnerability-table.test.tsx`

- [ ] **Step 1: Write the failing test for Ignore click behavior**

```tsx
import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { VulnerabilityTable } from "../components/vulnerability-table";

describe("vulnerability table ignore action", () => {
  test("renders Ignore action per row", () => {
    const html = renderToStaticMarkup(
      <VulnerabilityTable
        items={[sampleVulnerability()]}
        query={{ page: 1, limit: 10, sort: "severity", order: "desc" }}
        onSortChange={() => {}}
        onSelect={() => {}}
        onIgnoreRequest={() => {}}
      />,
    );

    expect(html).toContain("Ignore");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/vulnerability-table.test.tsx`
Expected: FAIL because `onIgnoreRequest` prop/action cell does not exist yet.

- [ ] **Step 3: Add Ignore callback prop and button in table**

```tsx
interface VulnerabilityTableProps {
  items: VulnerabilityWithRelations[];
  query: VulnerabilityQueryParams;
  onSortChange: (sort: VulnerabilitySortField) => void;
  onSelect: (id: number) => void;
  onIgnoreRequest: (item: VulnerabilityWithRelations) => void;
}

<td className="py-3">
  <button
    type="button"
    className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
    onClick={(event) => {
      event.preventDefault();
      event.stopPropagation();
      onIgnoreRequest(item);
    }}
  >
    Ignore
  </button>
</td>
```

- [ ] **Step 4: Add event-isolation test in same file**

```tsx
import { describe, expect, mock, test } from "bun:test";

function invokeIgnoreClick(
  onSelect: (id: number) => void,
  onIgnoreRequest: (item: VulnerabilityWithRelations) => void,
  item: VulnerabilityWithRelations,
) {
  const event = {
    preventDefault: () => {},
    stopPropagation: () => {},
  };
  event.preventDefault();
  event.stopPropagation();
  onIgnoreRequest(item);
}

test("Ignore click does not trigger row select handler", () => {
  const onSelect = mock(() => {});
  const onIgnoreRequest = mock(() => {});
  const item = sampleVulnerability();

  invokeIgnoreClick(onSelect, onIgnoreRequest, item);

  expect(onIgnoreRequest).toHaveBeenCalledTimes(1);
  expect(onIgnoreRequest).toHaveBeenCalledWith(item);
  expect(onSelect).toHaveBeenCalledTimes(0);
});
```

- [ ] **Step 5: Run test to verify pass**

Run: `bun test src/__tests__/vulnerability-table.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/components/vulnerability-table.tsx src/__tests__/vulnerability-table.test.tsx
git commit -m "feat: add vulnerability row ignore action callback"
```

### Task 2: Add confirm modal component

**Files:**
- Create: `src/components/ignore-vulnerability-modal.tsx`
- Test: `src/__tests__/ignore-vulnerability-modal.test.tsx`

- [ ] **Step 1: Write failing modal render test**

```tsx
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { IgnoreVulnerabilityModal } from "../components/ignore-vulnerability-modal";

describe("ignore vulnerability modal", () => {
  test("shows cve, repository, and all-tags scope", () => {
    const html = renderToStaticMarkup(
      <IgnoreVulnerabilityModal
        open={true}
        cveId="CVE-2026-1111"
        repositoryName="ghcr.io/acme/api"
        reason=""
        expiresAt=""
        busy={false}
        error={null}
        onReasonChange={() => {}}
        onExpiresAtChange={() => {}}
        onCancel={() => {}}
        onConfirm={() => {}}
      />,
    );

    expect(html).toContain("CVE-2026-1111");
    expect(html).toContain("ghcr.io/acme/api");
    expect(html).toContain("All tags");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/ignore-vulnerability-modal.test.tsx`
Expected: FAIL because component does not exist.

- [ ] **Step 3: Implement modal component with optional fields**

```tsx
export function IgnoreVulnerabilityModal(props: IgnoreVulnerabilityModalProps) {
  if (!props.open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/70 p-4">
      <section className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-base font-semibold">Ignore vulnerability</h2>
        <p className="text-sm text-slate-300">This will create a repository-scoped rule for all tags.</p>
        <dl className="mt-3 grid gap-2 text-sm">
          <div><dt className="text-slate-400">CVE ID</dt><dd>{props.cveId}</dd></div>
          <div><dt className="text-slate-400">Repository</dt><dd>{props.repositoryName}</dd></div>
          <div><dt className="text-slate-400">Scope</dt><dd>All tags</dd></div>
        </dl>
        <label className="mt-3 grid gap-1">
          <span className="text-xs text-slate-400">Reason (optional)</span>
          <input value={props.reason} onChange={(e) => props.onReasonChange(e.target.value)} />
        </label>
        <label className="mt-3 grid gap-1">
          <span className="text-xs text-slate-400">Expires at (optional)</span>
          <input type="datetime-local" value={props.expiresAt} onChange={(e) => props.onExpiresAtChange(e.target.value)} />
        </label>
        {props.error && <p className="mt-2 text-sm text-rose-300">{props.error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={props.onCancel} disabled={props.busy}>Cancel</button>
          <button type="button" onClick={props.onConfirm} disabled={props.busy}>{props.busy ? "Saving..." : "Confirm Ignore"}</button>
        </div>
      </section>
    </div>
  );
}
```

- [ ] **Step 4: Add busy-state test**

```tsx
test("disables confirm when busy", () => {
  const html = renderToStaticMarkup(
    <IgnoreVulnerabilityModal
      open={true}
      cveId="CVE-2026-1111"
      repositoryName="ghcr.io/acme/api"
      reason=""
      expiresAt=""
      busy={true}
      error={null}
      onReasonChange={() => {}}
      onExpiresAtChange={() => {}}
      onCancel={() => {}}
      onConfirm={() => {}}
    />,
  );
  expect(html).toContain("Saving...");
});
```

- [ ] **Step 5: Run test to verify pass**

Run: `bun test src/__tests__/ignore-vulnerability-modal.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/components/ignore-vulnerability-modal.tsx src/__tests__/ignore-vulnerability-modal.test.tsx
git commit -m "feat: add ignore vulnerability confirmation modal"
```

### Task 3: Wire modal flow in vulnerabilities route

**Files:**
- Modify: `src/routes/vulnerabilities.tsx`
- Modify: `src/services/types.ts`
- Test: `src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`

- [ ] **Step 1: Write failing route flow test**

```tsx
import { describe, expect, mock, test } from "bun:test";
import { createTrivyIgnoreRecord } from "../hooks/use-trivy-ignores";

describe("vulnerabilities ignore flow", () => {
  test("opens modal from table action and submits create-ignore payload", async () => {
    const fetcher = mock(async () =>
      new Response(JSON.stringify({
        success: true,
        data: {
          id: 1,
          cve_id: "CVE-2026-1111",
          repository_id: 2,
          repository_name: "ghcr.io/acme/api",
          scope: "all_tags",
          reason: "accepted risk",
          expires_at: null,
          created_at: "2026-05-08T00:00:00.000Z",
          tag_groups: [],
        },
      })) as any,
    );

    await createTrivyIgnoreRecord(
      fetcher,
      {
        cve_id: "CVE-2026-1111",
        repository_id: 2,
        scope: "all_tags",
        reason: "accepted risk",
      },
      "api-key",
    );

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/trivy-ignores");
    expect(init.method).toBe("POST");
    expect(String(init.body)).toContain('"scope":"all_tags"');
    expect(String(init.body)).toContain('"repository_id":2');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`
Expected: FAIL because route has no modal workflow yet.

- [ ] **Step 3: Add route state and payload mapping**

```tsx
const [ignoreTarget, setIgnoreTarget] = useState<VulnerabilityWithRelations | null>(null);
const [ignoreReason, setIgnoreReason] = useState("");
const [ignoreExpiresAt, setIgnoreExpiresAt] = useState("");
const [ignoreBusy, setIgnoreBusy] = useState(false);
const [ignoreError, setIgnoreError] = useState<string | null>(null);
const [ignoreNotice, setIgnoreNotice] = useState<string | null>(null);

const onIgnoreRequest = useCallback((item: VulnerabilityWithRelations) => {
  setIgnoreTarget(item);
  setIgnoreReason("");
  setIgnoreExpiresAt("");
  setIgnoreError(null);
}, []);
```

- [ ] **Step 4: Submit through existing ignore-create helper**

```tsx
await createTrivyIgnoreRecord(fetch, {
  cve_id: ignoreTarget.cve_id,
  repository_id: ignoreTarget.image.repository_id,
  scope: "all_tags",
  reason: ignoreReason.trim() || undefined,
  expires_at: ignoreExpiresAt ? new Date(ignoreExpiresAt).toISOString() : undefined,
});
```

- [ ] **Step 5: Render modal + feedback and close behavior**

```tsx
<VulnerabilityTable
  items={data.items}
  query={query}
  onSortChange={onSortChange}
  onSelect={onSelectRow}
  onIgnoreRequest={onIgnoreRequest}
/>
{ignoreNotice && <p className="text-sm text-emerald-300">{ignoreNotice}</p>}
<IgnoreVulnerabilityModal
  open={Boolean(ignoreTarget)}
  cveId={ignoreTarget?.cve_id || ""}
  repositoryName={ignoreTarget?.image.repository_name || "Unknown repository"}
  reason={ignoreReason}
  expiresAt={ignoreExpiresAt}
  busy={ignoreBusy}
  error={ignoreError}
  onReasonChange={setIgnoreReason}
  onExpiresAtChange={setIgnoreExpiresAt}
  onCancel={() => setIgnoreTarget(null)}
  onConfirm={handleConfirmIgnore}
/>
```

- [ ] **Step 6: Ensure type coverage for repository id**

```ts
export interface ImageSummary {
  id: number;
  name: string;
  repository_id: number;
  repository_name?: string | null;
}
```

- [ ] **Step 7: Run tests to verify pass**

Run: `bun test src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/routes/vulnerabilities.tsx src/services/types.ts src/__tests__/vulnerabilities-route-ignore-flow.test.tsx
git commit -m "feat: wire vulnerabilities ignore modal submit flow"
```

### Task 4: Normalize duplicate/error messaging

**Files:**
- Modify: `src/routes/vulnerabilities.tsx`
- Modify: `src/hooks/use-trivy-ignores.ts` (optional helper export)
- Test: `src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`

- [ ] **Step 1: Write failing test for duplicate-style error message**

```tsx
import { describe, expect, test } from "bun:test";

function mapIgnoreError(message: string): string {
  const normalized = message.toLowerCase();
  if (normalized.includes("already") || normalized.includes("exists") || normalized.includes("conflict")) {
    return "This CVE is already ignored for this repository.";
  }
  return message || "Failed to create ignore rule";
}

test("shows already ignored message for duplicate-style backend error", async () => {
  expect(mapIgnoreError("already exists")).toBe("This CVE is already ignored for this repository.");
  expect(mapIgnoreError("conflict on unique key")).toBe("This CVE is already ignored for this repository.");
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `bun test src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`
Expected: FAIL on error message mismatch.

- [ ] **Step 3: Implement error mapping utility usage in route**

```ts
function mapIgnoreError(message: string): string {
  const normalized = message.toLowerCase();
  if (normalized.includes("already") || normalized.includes("exists") || normalized.includes("conflict")) {
    return "This CVE is already ignored for this repository.";
  }
  return message || "Failed to create ignore rule";
}
```

- [ ] **Step 4: Run focused test**

Run: `bun test src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/routes/vulnerabilities.tsx src/hooks/use-trivy-ignores.ts src/__tests__/vulnerabilities-route-ignore-flow.test.tsx
git commit -m "fix: map duplicate ignore errors to friendly message"
```

### Task 5: Regression verification and docs touch-up

**Files:**
- Modify: `docs/superpowers/specs/2026-05-08-vuln-table-ignore-modal-design.md` (only if behavior differs from spec)

- [ ] **Step 1: Run targeted test suite**

Run: `bun test src/__tests__/vulnerability-table.test.tsx src/__tests__/ignore-vulnerability-modal.test.tsx src/__tests__/vulnerabilities-route-ignore-flow.test.tsx`
Expected: PASS all tests.

- [ ] **Step 2: Run broader confidence tests around ignore and vulnerabilities**

Run: `bun test src/__tests__/trivy-ignore-route.test.tsx src/__tests__/use-trivy-ignores.test.ts src/__tests__/vulnerabilities-api.test.ts`
Expected: PASS all tests.

- [ ] **Step 3: If implementation changed behavior from spec, update spec document**

```md
- If modal remains open on duplicate error, update the "User Experience Flow" section line 7 to: 
  "On duplicate/conflict, show user-friendly message and keep modal open for user review."
- If modal closes on duplicate info, keep current spec text unchanged.
```

- [ ] **Step 4: Commit final verification/doc adjustments**

```bash
git add docs/superpowers/specs/2026-05-08-vuln-table-ignore-modal-design.md
git commit -m "docs: align ignore modal spec with implementation details"
```

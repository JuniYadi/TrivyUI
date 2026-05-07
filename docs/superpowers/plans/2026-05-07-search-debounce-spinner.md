# Search Debounce and Request-Start Spinner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase search debounce to 1 second and show an inline spinner only when the search request starts on repository and image listing pages.

**Architecture:** Keep behavior local to each route component by introducing page-level `isSearching` state. Trigger `isSearching` only when the debounced search actually changes filters, then clear it when request loading finishes. Reuse existing Tailwind styling and loading flow without changing hooks or API contracts.

**Tech Stack:** React, TypeScript, Tailwind CSS, TanStack Router

---

## File Structure

- Modify: `src/routes/repositories.tsx`
  - Responsibility: Repository page search debounce logic and inline search UI feedback.
- Modify: `src/routes/images.tsx`
  - Responsibility: Images page search debounce logic and inline search UI feedback.

### Task 1: Update repository search debounce and request-start spinner

**Files:**
- Modify: `src/routes/repositories.tsx`
- Test: Manual verification on `/repositories`

- [ ] **Step 1: Write the failing test (manual scenario definition)**

```text
Scenario: Repository search should wait 1s before request and show spinner only when request starts.

Given the repositories page is loaded
When user types in the search input
Then no spinner is shown during the first 1000ms debounce window
When the debounced filter update starts the request
Then inline "Searching..." spinner appears
And spinner disappears after loading completes
```

- [ ] **Step 2: Run test to verify it fails (current behavior)**

Run: Open `/repositories`, type into search box, observe debounce and spinner behavior.
Expected: Fails scenario because debounce is 300ms and no inline search spinner exists.

- [ ] **Step 3: Write minimal implementation**

```tsx
// src/routes/repositories.tsx
const [isSearching, setIsSearching] = useState(false);

useEffect(() => {
  const timer = window.setTimeout(() => {
    setFilters((prev) => {
      const nextSearch = searchInput.trim();
      if ((prev.search || "") === nextSearch) {
        return prev;
      }

      setIsSearching(true);
      return {
        ...prev,
        page: 1,
        search: nextSearch || undefined,
      };
    });
  }, 1000);

  return () => window.clearTimeout(timer);
}, [searchInput, setFilters]);

useEffect(() => {
  if (!loading) {
    setIsSearching(false);
  }
}, [loading]);

// Render under the input:
{isSearching && loading && (
  <div className="mt-2 inline-flex items-center gap-2 text-xs text-slate-400">
    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-600 border-t-blue-400" aria-hidden="true" />
    <span>Searching...</span>
  </div>
)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: Open `/repositories`, type in search input, wait after typing.
Expected:
- No spinner before debounce expires.
- Spinner appears at request start.
- Spinner disappears when response returns.

- [ ] **Step 5: Commit**

```bash
git add src/routes/repositories.tsx
git commit -m "feat: add delayed repository search spinner feedback"
```

### Task 2: Update image search debounce and request-start spinner

**Files:**
- Modify: `src/routes/images.tsx`
- Test: Manual verification on `/images`

- [ ] **Step 1: Write the failing test (manual scenario definition)**

```text
Scenario: Image search should wait 1s before request and show spinner only when request starts.

Given the images page is loaded
When user types in the search input
Then no spinner is shown during the first 1000ms debounce window
When the debounced filter update starts the request
Then inline "Searching..." spinner appears
And spinner disappears after loading completes
```

- [ ] **Step 2: Run test to verify it fails (current behavior)**

Run: Open `/images`, type into search box, observe debounce and spinner behavior.
Expected: Fails scenario because debounce is 300ms and no inline search spinner exists.

- [ ] **Step 3: Write minimal implementation**

```tsx
// src/routes/images.tsx
const [isSearching, setIsSearching] = useState(false);

useEffect(() => {
  const timer = window.setTimeout(() => {
    setFilters((prev) => {
      const nextSearch = searchInput.trim();
      if ((prev.search || "") === nextSearch) {
        return prev;
      }

      setIsSearching(true);
      return {
        ...prev,
        page: 1,
        search: nextSearch || undefined,
      };
    });
  }, 1000);

  return () => window.clearTimeout(timer);
}, [searchInput, setFilters]);

useEffect(() => {
  if (!loading) {
    setIsSearching(false);
  }
}, [loading]);

// Render under the input:
{isSearching && loading && (
  <div className="mt-2 inline-flex items-center gap-2 text-xs text-slate-400">
    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-600 border-t-blue-400" aria-hidden="true" />
    <span>Searching...</span>
  </div>
)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: Open `/images`, type in search input, wait after typing.
Expected:
- No spinner before debounce expires.
- Spinner appears at request start.
- Spinner disappears when response returns.

- [ ] **Step 5: Commit**

```bash
git add src/routes/images.tsx
git commit -m "feat: add delayed image search spinner feedback"
```

### Task 3: Cross-page regression check

**Files:**
- Modify: none
- Test: Manual checks on `/repositories` and `/images`

- [ ] **Step 1: Write the failing test (manual regression scenarios)**

```text
Scenario A: Same normalized value should not trigger spinner repeatedly.
Scenario B: Sort and pagination still work with no stuck spinner.
Scenario C: Empty and error states remain unchanged.
```

- [ ] **Step 2: Run test to verify baseline risks**

Run: Exercise scenarios on both pages after Tasks 1-2 changes.
Expected: Any regressions are identified before finalizing.

- [ ] **Step 3: Apply minimal fixes if needed**

```text
If regressions appear, adjust only route-local state transitions:
- Keep setIsSearching(true) only for real search-value changes.
- Keep reset on loading completion.
Avoid hook/API contract changes.
```

- [ ] **Step 4: Run test to verify pass**

Run: Re-check all scenarios on both pages.
Expected: All pass, no regressions observed.

- [ ] **Step 5: Commit**

```bash
git status --short
# If no additional code changes, no commit is required for this task.
```

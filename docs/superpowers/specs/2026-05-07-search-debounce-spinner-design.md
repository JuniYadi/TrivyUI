# Search Debounce and Request-Start Spinner Design

## Context

The repository and image listing pages currently debounce search input updates by 300ms and do not provide explicit request-start feedback in the search control area.

Relevant files:
- `src/routes/repositories.tsx`
- `src/routes/images.tsx`

Current behavior:
- Search input changes are applied after a 300ms timeout.
- Global page loading skeletons and error states exist.
- There is no dedicated inline search spinner that reflects request-start specifically for search operations.

## Goal

Improve search UX by:
1. Increasing search debounce to 1 second.
2. Showing a clear inline spinner only when the search request starts (not while typing during debounce).

## Non-Goals

- No API contract changes.
- No changes to sort, pagination, or table structure behavior.
- No global loading-state redesign.

## Approach Options

### Option A (Recommended): Local `isSearching` state in each page

Implementation summary:
- In `repositories.tsx` and `images.tsx`, change debounce delay from `300` to `1000`.
- Add `isSearching` state for local, UI-level search intent.
- Inside the debounced callback, before calling `setFilters`, compute whether search value actually changes.
- If search value changes, set `isSearching` to `true` and then update filters.
- Add an effect to reset `isSearching` to `false` when `loading` becomes `false`.
- Render a compact inline spinner + "Searching..." near the search input when `isSearching && loading`.

Pros:
- Keeps behavior scoped and explicit per page.
- Prevents spinner display for unrelated load causes unless they were triggered by a search update.
- Minimal risk and low refactor cost.

Cons:
- Duplicated logic in two files.

### Option B: Use `loading` only

Implementation summary:
- Increase debounce to 1 second.
- Show spinner solely when `loading` is `true`.

Pros:
- Very small code change.

Cons:
- Spinner will appear for non-search events (initial load, sort, pagination), which does not meet request-start-for-search specificity.

### Option C: Centralize in hooks

Implementation summary:
- Extend `useRepositories` and `useImages` with a dedicated search-pending state.
- Route components render spinner from hook-provided state.

Pros:
- Reusable abstraction.

Cons:
- Higher complexity and broader surface area than required.

## Selected Design

Use Option A.

Design details:
- Debounce value becomes `1000` milliseconds in both route files.
- `isSearching` transitions:
  - `false -> true`: only when the debounced callback detects a real search value change and issues filter update.
  - `true -> false`: when `loading` finishes (`loading === false`).
- Spinner UI placement:
  - Inside the existing search section, directly below the input.
  - Styling follows existing tailwind theme (`slate`/`blue`) and remains subtle.
- Spinner implementation:
  - Use a small circular border spinner using `animate-spin` utility.
  - Pair with text label `Searching...` for accessibility and clarity.

## Data Flow

1. User types in search input.
2. Debounce timer waits 1000ms.
3. Timer callback compares trimmed input with current filter search value.
4. If unchanged: no filter update, no spinner.
5. If changed: set `isSearching=true`, update filters, request starts via existing hook behavior.
6. While request is loading and `isSearching=true`, inline spinner is visible.
7. When hook loading completes, `isSearching` resets to `false`.

## Error Handling

- Existing error behavior remains unchanged.
- Spinner is driven by `loading` completion; it turns off whether request succeeds or fails.

## Testing Strategy

Manual checks:
1. On repositories page, type a query and stop typing:
   - No spinner during first 1000ms debounce delay.
   - Spinner appears when request starts.
   - Spinner disappears when response resolves.
2. Repeat on images page.
3. Verify typing same normalized value does not trigger spinner/request loop.
4. Verify sort/pagination still work and do not incorrectly leave spinner stuck.
5. Verify empty/error states remain unchanged.

## Rollout and Risk

- Low-risk UI behavior change localized to two route files.
- No backend or schema impact.

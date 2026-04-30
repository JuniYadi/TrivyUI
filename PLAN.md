# Layout Consolidation and Tailwind Migration Plan

## Scope and Inspection Summary

I inspected the running app at `http://localhost:3000` and reviewed all main pages plus detail pages:

- `/dashboard`
- `/vulnerabilities`
- `/repositories`
- `/repositories/1`
- `/images`
- `/images/1`
- `/upload`
- `/settings`
- `/api-keys`
- `/email-templates`

What is true right now:

1. A shared shell already exists (`src/components/app-shell.tsx`) and is used by all routed pages.
2. Styling is fully manual CSS in one large file (`src/styles/app.css`), not Tailwind.
3. Pages still define their own internal content layout patterns independently (table areas, form widths, grids, spacing).
4. Several pages use `upload-layout` (`max-width: 720px`), while data pages are effectively full container width, causing visible width/flow differences.
5. Styling responsibilities are mixed: nav button classes are reused in non-nav contexts (example in API Keys revoke action), which indicates weak layout/UI boundaries.

So the core issue is not "no shared shell" (there is one), but "inconsistent content layout contracts + ad hoc CSS reuse".

## Problems to Solve

1. **No global content contract:** each page decides its own internal width and stacking behavior.
2. **Manual CSS sprawl:** one large stylesheet increases drift and makes consistency hard to enforce.
3. **Semantic/style coupling:** classes meant for one context are reused elsewhere.
4. **Inconsistent responsive behavior:** page-specific width caps and table/form behavior differ by route.

## Target Architecture

Move to a two-layer layout model:

1. **Global app layout (single source of truth)**
   - App background, root spacing, max width container, header, nav, and baseline vertical rhythm.
   - Implement in shell component only.

2. **Composable page content layout primitives**
   - Standardized content wrappers (e.g., `content-stack`, `content-narrow`, `content-wide`, `stats-grid`, `split-grid`, `table-card`).
   - Pages compose primitives instead of hand-rolling spacing/width each time.

## Tailwind Migration Strategy

### Phase 0 - Foundation

1. Install and configure Tailwind for current build setup.
2. Add `tailwind.config` with design tokens aligned to current brand colors.
3. Keep `app.css` temporarily for parity while introducing utility classes gradually.

### Phase 1 - Global Layout First

1. Refactor `AppShell` to Tailwind utilities.
2. Define consistent container and spacing rules once (desktop + mobile).
3. Replace shell/nav related CSS classes from `app.css`.

### Phase 2 - Introduce Layout Primitives

Create reusable React wrappers/components (or utility class patterns) for:

- `PageSection`
- `Card`
- `FormStack` (narrow)
- `DataGrid` / `StatsGrid`
- `TableSection`

Goal: stop route files from inventing custom layout structure repeatedly.

### Phase 3 - Migrate Route-by-Route

Recommended order (highest user impact first):

1. `dashboard`
2. `vulnerabilities`
3. `repositories` + `repository-detail`
4. `images` + `image-detail`
5. `upload`
6. `settings`
7. `api-keys`
8. `email-templates`

For each route:

1. Replace manual layout classes with Tailwind + shared primitives.
2. Preserve behavior and data flow (layout-only change).
3. Validate at mobile and desktop breakpoints before moving on.

### Phase 4 - CSS Decommission

1. Remove unused selectors from `src/styles/app.css` incrementally.
2. Keep only what Tailwind cannot or should not express (if any).
3. End state target: minimal global CSS file.

## Concrete Refactor Rules

1. No route defines its own top-level container width directly unless explicitly required.
2. No cross-context class reuse (`shell-nav__link` must not style non-nav buttons).
3. Form pages use one standard narrow-content primitive.
4. Data-heavy pages use one standard wide/table primitive.
5. New UI work must use Tailwind utilities and shared primitives, not new manual CSS blocks.

## Verification Checklist

For each migrated page:

1. Header/nav alignment and spacing are identical across routes.
2. Content width behavior is intentional (`narrow` vs `wide`) and documented.
3. Mobile layout remains usable (no clipped controls/tables without horizontal strategy).
4. No visual regressions in action buttons, cards, and typography hierarchy.

## Risks and Mitigations

1. **Risk:** mixed Tailwind + legacy CSS causes conflicts.
   - **Mitigation:** migrate by layout domain (shell first, then route clusters), remove old selectors immediately after each domain is complete.

2. **Risk:** accidental behavior changes during markup edits.
   - **Mitigation:** keep changes layout-focused; avoid touching hooks/data logic in migration commits.

3. **Risk:** inconsistency returns after migration.
   - **Mitigation:** enforce primitive usage in PR review and add a short contributor guideline section in README.

## Suggested Deliverables

1. `tailwind.config.*` + build integration
2. Refactored `AppShell` with global layout contract
3. Shared layout primitives for content sections
4. Route-by-route Tailwind migration
5. Cleanup of obsolete CSS in `src/styles/app.css`

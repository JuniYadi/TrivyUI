import { AppLink, ChipButton, Delta, FOCUS, LatestBadge, formatDateTime, timeAgo, toBarCounts } from "./repo-ui";
import { Pagination } from "./pagination";
import { Card } from "./ui/card";
import { Mono } from "./ui/mono";
import { SeverityBar } from "./ui/severity-bar";
import type { RepoTagPage } from "../hooks/use-repo-detail";
import type { RepoGroupHealth, RepoTagRow } from "../services/repo-state";

export const TAG_PAGE_SIZE = 10;
export const LATEST_PER_GROUP = 3;

const ROW_GRID = "grid grid-cols-[minmax(0,1fr)_3rem_3.5rem] items-center gap-x-3 sm:grid-cols-[minmax(0,11rem)_minmax(0,1fr)_3rem_3.5rem_5rem]";

function TagRow({ tag, onReset }: { tag: RepoTagRow; onReset?: (tag: RepoTagRow) => void }) {
  return (
    <li className={`${ROW_GRID} border-t border-rowline px-4`}>
      <AppLink href={`/images/${tag.image_id}`} className="inline-flex min-h-11 min-w-0 items-center gap-2 text-link hover:underline sm:min-h-9">
        <Mono className="truncate">{tag.tag ?? tag.name}</Mono>
        {tag.is_latest && <LatestBadge />}
      </AppLink>
      <span className="hidden sm:block">
        <SeverityBar counts={toBarCounts(tag.by_severity)} />
      </span>
      <span className="text-right text-sm font-semibold tabular-nums" title={`${tag.fixable} fixable`}>
        {tag.open}
      </span>
      <span className="text-right text-xs">
        <Delta value={tag.change} />
      </span>
      <span className="hidden text-right text-xs text-fg2 sm:block" title={formatDateTime(tag.last_scanned_at)}>
        {timeAgo(tag.last_scanned_at)}
        {onReset && (
          <button type="button" onClick={() => onReset(tag)} className={`ml-2 text-red-300 hover:underline ${FOCUS}`} aria-label={`Reset scan data for ${tag.tag ?? tag.name}`}>
            Reset
          </button>
        )}
      </span>
    </li>
  );
}

export function groupLinkClass(): string {
  return `inline-flex min-h-11 items-center text-sm font-medium text-link hover:underline sm:min-h-9 ${FOCUS}`;
}

export interface RepoTagsSectionProps {
  tagGroups: RepoGroupHealth[];
  /** At most the latest 3 tags of each group (from the detail payload). */
  latestTags: RepoTagRow[];
  group: string | null;
  onGroupChange: (group: string | null) => void;
  page: number;
  onPage: (page: number) => void;
  groupTags: { data: RepoTagPage | null; loading: boolean; error: string | null };
  onResetTag?: (tag: RepoTagRow) => void;
}

export function RepoTagsSection({ tagGroups, latestTags, group, onGroupChange, page, onPage, groupTags, onResetTag }: RepoTagsSectionProps) {
  const selected = group ? tagGroups.find((g) => g.group_name === group) : undefined;
  const pageData = groupTags.data && groupTags.data.group === group ? groupTags.data : null;

  return (
    <section aria-label="Tags">
      <Card className="!p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
          <h3 className="text-base font-semibold">
            Tags{" "}
            <span className="font-normal text-fg2">
              {"·"} {selected ? `${selected.group_name} (${selected.tag_count})` : `latest ${LATEST_PER_GROUP} per group`}
            </span>
          </h3>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Tag view">
            <ChipButton active={group === null} onClick={() => onGroupChange(null)}>
              Latest per group
            </ChipButton>
            {tagGroups.map((g) => (
              <ChipButton key={g.group_name} active={group === g.group_name} onClick={() => onGroupChange(g.group_name)}>
                {g.group_name} {"·"} {g.tag_count}
              </ChipButton>
            ))}
          </div>
        </div>

        {tagGroups.length === 0 && <p className="border-t border-rowline px-4 py-6 text-center text-sm text-muted">No tags scanned yet.</p>}

        {selected === undefined &&
          tagGroups.map((g) => {
            const rows = latestTags.filter((tag) => tag.tag_group === g.group_name);
            return (
              <div key={g.group_name}>
                <p className="m-0 border-t border-line bg-bg px-4 py-1.5 text-xs text-fg2">
                  <strong className="text-fg">{g.group_name}</strong> {"·"} latest {rows.length} of {g.tag_count}
                </p>
                <ul className="m-0 list-none p-0">
                  {rows.map((tag) => (
                    <TagRow key={tag.image_id} tag={tag} onReset={onResetTag} />
                  ))}
                </ul>
                {g.tag_count > rows.length && (
                  <div className="border-t border-rowline px-4">
                    <button type="button" onClick={() => onGroupChange(g.group_name)} className={groupLinkClass()}>
                      Show all {g.tag_count} {g.group_name} tags {"→"}
                    </button>
                  </div>
                )}
              </div>
            );
          })}

        {selected !== undefined && (
          <div>
            <div className="border-t border-line bg-bg px-4">
              <button type="button" onClick={() => onGroupChange(null)} className={groupLinkClass()}>
                {"←"} Latest {LATEST_PER_GROUP} per group
              </button>
            </div>
            {groupTags.error ? (
              <p role="alert" className="px-4 py-6 text-sm text-fg2">{groupTags.error}</p>
            ) : (
              <ul className={`m-0 list-none p-0 ${groupTags.loading ? "opacity-60" : ""}`} aria-busy={groupTags.loading}>
                {(pageData?.items ?? []).map((tag) => (
                  <TagRow key={tag.image_id} tag={tag} onReset={onResetTag} />
                ))}
                {pageData && pageData.items.length === 0 && <li className="border-t border-rowline px-4 py-6 text-center text-sm text-muted">No tags in this group.</li>}
              </ul>
            )}
            {pageData && (
              <Pagination
                embedded
                noun="tags"
                page={pageData.pagination.page}
                totalPages={pageData.pagination.total_pages}
                totalItems={pageData.pagination.total_items}
                limit={TAG_PAGE_SIZE}
                onPageChange={onPage}
              />
            )}
          </div>
        )}
        {tagGroups.length > 0 && <p className="m-0 border-t border-rowline px-4 py-2 text-xs text-muted">Newest first {"·"} change vs previous tag in the same group</p>}
      </Card>
    </section>
  );
}

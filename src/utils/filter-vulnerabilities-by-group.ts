export function filterVulnerabilitiesByGroup<T extends { tag_group?: string }>(items: T[], selectedGroup: string | null): T[] {
  if (!selectedGroup) {
    return items;
  }

  return items.filter((item) => (item.tag_group || "ungrouped") === selectedGroup);
}

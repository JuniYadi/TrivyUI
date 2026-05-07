export function filterVulnerabilitiesByGroup<T extends { tag_group?: string }>(items: T[], selectedGroup: string | null): T[] {
  if (!selectedGroup) {
    return items;
  }

  const normalizedSelectedGroup = selectedGroup.trim().toLowerCase();

  return items.filter((item) => ((item.tag_group || "ungrouped").trim().toLowerCase() === normalizedSelectedGroup));
}

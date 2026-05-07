export interface ImageTagGrouping {
  original: string;
  repository_base: string;
  tag: string | null;
  tag_group: string;
}

export function parseImageTagGrouping(imageRef: string): ImageTagGrouping {
  const original = normalizeName(imageRef, "unknown-image");
  const digestIndex = original.indexOf("@");
  const withoutDigest = digestIndex >= 0 ? original.slice(0, digestIndex) : original;

  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  const hasTag = lastColon > lastSlash;
  const repositoryBase = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const tag = hasTag ? withoutDigest.slice(lastColon + 1) : null;

  return {
    original,
    repository_base: repositoryBase || "unknown-repository",
    tag,
    tag_group: toTagGroup(tag),
  };
}

function toTagGroup(tag: string | null): string {
  if (!tag) {
    return "ungrouped";
  }

  const match = /^(.*)-\d+$/.exec(tag);
  if (!match || !match[1]) {
    return tag;
  }

  return match[1];
}

function normalizeName(name: string, fallback: string): string {
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

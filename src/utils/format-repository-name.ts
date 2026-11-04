import { repoLabel } from "../lib/image-ref";

/** Repository name without registry host, truncated to `maxLength`. Prefer <ImageName> for display. */
export function formatRepositoryName(value: string, maxLength = 24): string {
  const name = value.trim() ? repoLabel(value) : "-";
  return name.length <= maxLength ? name : `${name.slice(0, Math.max(maxLength - 3, 1))}...`;
}

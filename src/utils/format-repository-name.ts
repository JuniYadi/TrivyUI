export function formatRepositoryName(value: string, maxLength = 24): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return "-";
  }

  const parts = trimmed.split("/").filter(Boolean);
  const withoutRegistry = parts.length >= 3 ? parts.slice(-2).join("/") : trimmed;
  if (withoutRegistry.length <= maxLength) {
    return withoutRegistry;
  }

  return `${withoutRegistry.slice(0, Math.max(maxLength - 3, 1))}...`;
}

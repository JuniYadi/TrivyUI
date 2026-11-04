export function formatRelativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) {
    return "-";
  }

  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) {
    return "-";
  }

  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} d ago`;
  return new Date(iso).toISOString().slice(0, 10);
}

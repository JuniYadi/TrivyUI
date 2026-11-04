interface ApiEnvelope<T> {
  success?: boolean;
  data?: T;
  error?: { message?: string };
}

export async function fetchApi<T>(path: string, fallbackMessage: string, fetcher: typeof fetch = fetch): Promise<T> {
  const response = await fetcher(path);

  let payload: ApiEnvelope<T> | null = null;
  try {
    payload = (await response.json()) as ApiEnvelope<T>;
  } catch {
    throw new Error(fallbackMessage);
  }

  if (!response.ok || !payload || payload.success !== true || payload.data === undefined) {
    throw new Error(payload?.error?.message || fallbackMessage);
  }

  return payload.data;
}

export const ALLOWED_LIMITS = [10, 25, 50, 100] as const;

export function parseLimit(value: string | null, fallback: number): number {
  const parsed = Number.parseInt(value || String(fallback), 10);
  return (ALLOWED_LIMITS as readonly number[]).includes(parsed) ? parsed : fallback;
}

export function parsePage(value: string | null): number {
  const parsed = Number.parseInt(value || "1", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
}

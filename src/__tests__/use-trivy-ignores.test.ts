import { describe, expect, test } from "bun:test";
import { buildTrivyIgnoreAuthHeaders, createTrivyIgnoreRecord, deleteTrivyIgnoreRecord, fetchRepositories, fetchTrivyIgnores } from "../hooks/use-trivy-ignores";

interface StorageLike {
  getItem: (key: string) => string | null;
}

function headersToRecord(headers: HeadersInit | undefined): Record<string, string> {
  return headers ? Object.fromEntries(new Headers(headers).entries()) : {};
}

function headersToLowercaseRecord(headers: HeadersInit | undefined): Record<string, string> {
  const raw = headersToRecord(headers);
  const normalized: Record<string, string> = {};

  for (const [name, value] of Object.entries(raw)) {
    normalized[name.toLowerCase()] = value;
  }

  return normalized;
}

describe("trivy ignore API header helpers", () => {
  test("uses an explicit API key for auth headers", () => {
    const headers = buildTrivyIgnoreAuthHeaders("  trivy_secret  ");

    expect(headers).toEqual({ "X-API-Key": "trivy_secret" });
  });

  test("falls back to storage key when explicit key is missing", () => {
    const storage: StorageLike = {
      getItem: (key) => (key === "trivyui_trivy_ignore_api_key" ? "  storage_key  " : null),
    };

    const headers = buildTrivyIgnoreAuthHeaders(undefined, storage);

    expect(headers).toEqual({ "X-API-Key": "storage_key" });
  });

  test("returns no auth headers when no key is available", () => {
    const headers = buildTrivyIgnoreAuthHeaders();

    expect(headers).toEqual({});
  });
});

describe("trivy ignore API request helpers", () => {
  test("fetchTrivyIgnores includes the API key header", async () => {
    let capturedInit: RequestInit | undefined;
    const fetcher = ((_: string, init?: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(new Response(JSON.stringify({ success: true, data: [] })));
    }) as typeof fetch;

    await fetchTrivyIgnores(fetcher, undefined, "list-key");

    expect(headersToLowercaseRecord(capturedInit?.headers)).toEqual(
      expect.objectContaining({
        "x-api-key": "list-key",
      }),
    );
  });

  test("fetchRepositories includes the API key header", async () => {
    const seenUrls: string[] = [];
    let capturedInit: RequestInit | undefined;
    const fetcher = ((url: string, init?: RequestInit) => {
      capturedInit = init;
      seenUrls.push(url);

      const page = Number(new URL(url, "http://localhost").searchParams.get("page") || "1");
      const payload =
        page === 1
          ? {
              items: [
                { id: 2, name: "repo-b" },
                { id: 1, name: "repo-a" },
              ],
              pagination: { page: 1, limit: 100, total_items: 3, total_pages: 2 },
            }
          : {
              items: [
                { id: 1, name: "repo-a" },
                { id: 3, name: "repo-c" },
              ],
              pagination: { page: 2, limit: 100, total_items: 3, total_pages: 2 },
            };

      return Promise.resolve(new Response(JSON.stringify({ success: true, data: payload })));
    }) as typeof fetch;

    const repositories = await fetchRepositories(fetcher, "repo-key");

    expect(headersToLowercaseRecord(capturedInit?.headers)).toEqual(
      expect.objectContaining({
        "x-api-key": "repo-key",
      }),
    );
    expect(seenUrls).toEqual([
      "/api/repositories?limit=100&sort=name&order=asc&page=1",
      "/api/repositories?limit=100&sort=name&order=asc&page=2",
    ]);
    expect(repositories).toEqual([
      { id: 1, name: "repo-a" },
      { id: 2, name: "repo-b" },
      { id: 3, name: "repo-c" },
    ]);
  });

  test("createTrivyIgnoreRecord includes API key and content-type", async () => {
    let capturedInit: RequestInit | undefined;
    const fetcher = ((_: string, init?: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            success: true,
            data: {
              id: 1,
              cve_id: "CVE-2026-1234",
              repository_id: null,
              scope: "all_tags",
              reason: null,
              expires_at: null,
              created_at: new Date().toISOString(),
              tag_groups: [],
              repository_name: null,
            },
          }),
        ),
      );
    }) as typeof fetch;

    await createTrivyIgnoreRecord(fetcher, {
      cve_id: "CVE-2026-1234",
      repository_id: null,
      scope: "all_tags",
    }, "create-key");

    expect(headersToLowercaseRecord(capturedInit?.headers)).toEqual(
      expect.objectContaining({
        "content-type": "application/json",
        "x-api-key": "create-key",
      }),
    );
  });

  test("deleteTrivyIgnoreRecord includes API key header", async () => {
    let capturedInit: RequestInit | undefined;
    const fetcher = ((_: string, init?: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(new Response(JSON.stringify({ success: true, data: { id: 1, removed: true } })));
    }) as typeof fetch;

    await deleteTrivyIgnoreRecord(fetcher, 1, "delete-key");

    expect(headersToLowercaseRecord(capturedInit?.headers)).toEqual(
      expect.objectContaining({
        "x-api-key": "delete-key",
      }),
    );
  });
});

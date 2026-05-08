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
    let capturedInit: RequestInit | undefined;
    const fetcher = ((_: string, init?: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            success: true,
            data: {
              items: [],
              pagination: {
                page: 1,
                limit: 1,
                total_items: 0,
                total_pages: 0,
              },
            },
          }),
        ),
      );
    }) as typeof fetch;

    await fetchRepositories(fetcher, "repo-key");

    expect(headersToLowercaseRecord(capturedInit?.headers)).toEqual(
      expect.objectContaining({
        "x-api-key": "repo-key",
      }),
    );
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

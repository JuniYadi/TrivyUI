import { useCallback, useMemo, useSyncExternalStore } from "react";

const URL_EVENT = "trivyui:url-search";

function subscribe(listener: () => void): () => void {
  window.addEventListener("popstate", listener);
  window.addEventListener(URL_EVENT, listener);
  return () => {
    window.removeEventListener("popstate", listener);
    window.removeEventListener(URL_EVENT, listener);
  };
}

const getSnapshot = () => window.location.search;
const getServerSnapshot = () => "";

export type SearchPatch = Record<string, string | number | null | undefined>;

/** Applies a patch to a query string: null/undefined/"" removes the key. Pure, for tests. */
export function patchSearch(search: string, patch: SearchPatch): string {
  const params = new URLSearchParams(search);
  for (const [key, value] of Object.entries(patch)) {
    if (value === null || value === undefined || value === "") {
      params.delete(key);
    } else {
      params.set(key, String(value));
    }
  }
  const next = params.toString();
  return next ? `?${next}` : "";
}

/**
 * Reads and writes the current page's query string without a router round trip.
 * `replace` (default) for filters and paging; `push` when Back should undo the change (opening a panel).
 */
export function useUrlSearch() {
  const search = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const params = useMemo(() => new URLSearchParams(search), [search]);

  const update = useCallback((patch: SearchPatch, mode: "push" | "replace" = "replace") => {
    const next = patchSearch(window.location.search, patch);
    const url = `${window.location.pathname}${next}${window.location.hash}`;
    if (url !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
      if (mode === "push") window.history.pushState({}, "", url);
      else window.history.replaceState({}, "", url);
    }
    window.dispatchEvent(new Event(URL_EVENT));
  }, []);

  return { params, update };
}

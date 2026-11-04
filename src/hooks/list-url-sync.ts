/**
 * Shared URL plumbing for list hooks (repositories, images, vulnerabilities).
 * Both helpers are no-ops unless the browser is on the list's own path, so a
 * still-mounted list never reacts to (or overwrites) navigation to a detail page.
 */
export function replaceListUrl(listPath: string, queryString: string): void {
  if (window.location.pathname !== listPath) return;
  const nextUrl = `${listPath}?${queryString}`;
  const currentUrl = `${window.location.pathname}${window.location.search}`;
  if (currentUrl !== nextUrl) {
    window.history.replaceState({}, "", nextUrl);
  }
}

export function onListPopState(listPath: string, handler: () => void): () => void {
  const listener = () => {
    if (window.location.pathname !== listPath) return;
    handler();
  };
  window.addEventListener("popstate", listener);
  return () => window.removeEventListener("popstate", listener);
}

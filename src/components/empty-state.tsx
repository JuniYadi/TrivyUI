function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function EmptyState() {
  return (
    <section className="empty-state">
      <h2>No scan results yet</h2>
      <p className="muted">Upload your first Trivy scan to see dashboard insights.</p>
      <a
        href="/upload"
        className="link-anchor"
        onClick={(event) => {
          event.preventDefault();
          navigate("/upload");
        }}
      >
        Go to Upload
      </a>
    </section>
  );
}

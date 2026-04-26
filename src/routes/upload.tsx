function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function UploadPage() {
  return (
    <main className="page-shell" role="main">
      <div className="container upload-layout">
        <header className="page-header">
          <h1 className="page-title">Upload Trivy Scan</h1>
          <p className="page-subtitle">
            Upload parser flow will be handled in the upload phase. This page is active so dashboard empty-state
            navigation never falls into 404.
          </p>
        </header>

        <section className="card">
          <h2 className="card-title">Upload endpoint ready</h2>
          <p className="muted mt-0">
            API endpoints are available at <code>/api/upload</code> and <code>/api/upload/batch</code>.
          </p>
          <button type="button" className="secondary-button" onClick={() => navigate("/dashboard")}>
            Back to Dashboard
          </button>
        </section>
      </div>
    </main>
  );
}

import { AppShell } from "../components/app-shell";

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function UploadPage() {
  return (
    <AppShell
      activeRoute="/upload"
      title="Upload Trivy Scan"
      subtitle="Use this page to ingest scan results and preview dashboard states during local development."
    >
      <div className="upload-layout">
        <section className="card">
          <h2 className="card-title">Upload endpoint ready</h2>
          <p className="muted mt-0">
            API endpoints are available at <code>/api/upload</code> and <code>/api/upload/batch</code>.
          </p>
          <button type="button" className="secondary-button" onClick={() => navigate("/dashboard")}>Back to Dashboard</button>
        </section>

        <section className="card">
          <h2 className="card-title">Local sample data (dev only)</h2>
          <p className="muted mt-0">
            Need non-empty dashboard quickly? Seed local SQLite data for preview. This command is for local development only and does not affect API contract.
          </p>
          <code className="code-block">PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard</code>
        </section>
      </div>
    </AppShell>
  );
}

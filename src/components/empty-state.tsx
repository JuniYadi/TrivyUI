export function EmptyState() {
  return (
    <section
      style={{
        border: "1px dashed #475569",
        borderRadius: 12,
        padding: "1.5rem",
        color: "#cbd5e1",
      }}
    >
      <h2 style={{ marginTop: 0 }}>No scan results yet</h2>
      <p>Upload your first Trivy scan to see dashboard insights.</p>
      <a
        href="/upload"
        style={{
          display: "inline-block",
          background: "#2563eb",
          color: "white",
          textDecoration: "none",
          borderRadius: 8,
          padding: "0.5rem 0.8rem",
          fontWeight: 600,
        }}
      >
        Go to Upload
      </a>
    </section>
  );
}

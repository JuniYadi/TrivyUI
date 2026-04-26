export function DashboardSkeleton() {
  const block = {
    background: "#1e293b",
    borderRadius: 10,
    minHeight: 88,
    border: "1px solid #334155",
  } as const;

  return (
    <section aria-label="dashboard-loading" style={{ display: "grid", gap: "1rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "1rem" }}>
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} style={block} />
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem" }}>
        <div style={{ ...block, minHeight: 220 }} />
        <div style={{ ...block, minHeight: 220 }} />
      </div>
      <div style={{ ...block, minHeight: 220 }} />
    </section>
  );
}

export function DashboardSkeleton() {
  return (
    <section aria-label="dashboard-loading" className="skeleton-stack">
      <div className="skeleton-grid skeleton-grid--stats">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="skeleton-block" />
        ))}
      </div>
      <div className="skeleton-grid skeleton-grid--split">
        <div className="skeleton-block" style={{ minHeight: 220 }} />
        <div className="skeleton-block" style={{ minHeight: 220 }} />
      </div>
      <div className="skeleton-block" style={{ minHeight: 220 }} />
    </section>
  );
}

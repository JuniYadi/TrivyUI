const BLOCK = "animate-pulse rounded-xl border border-line bg-card";

export function DashboardSkeleton() {
  return (
    <section aria-label="dashboard-loading" className="grid gap-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={index} className={`h-24 ${BLOCK} ${index === 4 ? "col-span-2 lg:col-span-1" : ""}`} />
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className={`h-72 ${BLOCK}`} />
        <div className={`h-72 ${BLOCK}`} />
      </div>
      <div className={`h-56 ${BLOCK}`} />
    </section>
  );
}

export function DashboardSkeleton() {
  return (
    <section aria-label="dashboard-loading" className="grid gap-4">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="h-24 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
        ))}
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="h-56 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
        <div className="h-56 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
      </div>
      <div className="h-56 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
    </section>
  );
}

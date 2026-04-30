import { navigate } from "../lib/navigation";

export function EmptyState() {
  return (
    <section className="rounded-xl border border-dashed border-slate-600 p-8 text-center">
      <h2 className="mt-0 text-xl font-semibold">No scan results yet</h2>
      <p className="text-slate-400">Upload your first Trivy scan to see dashboard insights.</p>
      <a
        href="/upload"
        className="mt-4 inline-block rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white no-underline transition hover:bg-blue-700"
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

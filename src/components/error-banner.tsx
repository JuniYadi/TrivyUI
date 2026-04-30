interface ErrorBannerProps {
  message: string;
  onRetry: () => void;
}

export function ErrorBanner({ message, onRetry }: ErrorBannerProps) {
  return (
    <section role="alert" className="rounded-xl border border-red-900 bg-red-950 p-4 text-red-200">
      <strong>Failed to load dashboard data</strong>
      <span className="ml-2">{message}</span>
      <div className="mt-3">
        <button type="button" onClick={onRetry} className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700">
          Retry
        </button>
      </div>
    </section>
  );
}

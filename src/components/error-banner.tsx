interface ErrorBannerProps {
  message: string;
  onRetry: () => void;
}

export function ErrorBanner({ message, onRetry }: ErrorBannerProps) {
  return (
    <section role="alert" className="alert">
      <strong>Failed to load dashboard data</strong>
      <span>{message}</span>
      <div>
        <button type="button" onClick={onRetry} className="primary-button">
          Retry
        </button>
      </div>
    </section>
  );
}

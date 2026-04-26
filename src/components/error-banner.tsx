interface ErrorBannerProps {
  message: string;
  onRetry: () => void;
}

export function ErrorBanner({ message, onRetry }: ErrorBannerProps) {
  return (
    <section
      role="alert"
      style={{
        border: "1px solid #7f1d1d",
        background: "#450a0a",
        color: "#fecaca",
        borderRadius: 12,
        padding: "1rem",
        display: "grid",
        gap: "0.75rem",
      }}
    >
      <strong>Failed to load dashboard data</strong>
      <span>{message}</span>
      <div>
        <button
          type="button"
          onClick={onRetry}
          style={{
            background: "#ef4444",
            color: "white",
            border: 0,
            borderRadius: 8,
            padding: "0.45rem 0.75rem",
            cursor: "pointer",
          }}
        >
          Retry
        </button>
      </div>
    </section>
  );
}

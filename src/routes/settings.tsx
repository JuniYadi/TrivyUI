import { useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";

type NotificationMinSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

type SaveState = "idle" | "saving" | "saved" | "error";

interface ApiResponse {
  success: boolean;
  data?: {
    enabled: boolean;
    min_severity: NotificationMinSeverity;
  };
  error?: { code: string; message: string };
}

const MIN_SEVERITY_OPTIONS: NotificationMinSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [minSeverity, setMinSeverity] = useState<NotificationMinSeverity>("HIGH");
  const [status, setStatus] = useState<SaveState>("idle");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let mounted = true;

    async function loadSettings() {
      try {
        const response = await fetch("/api/settings/notifications");
        const payload = (await response.json()) as ApiResponse;

        if (!response.ok || !payload.success || !payload.data) {
          throw new Error(payload.error?.message || "Failed to load notification settings");
        }

        if (!mounted) {
          return;
        }

        setEnabled(payload.data.enabled);
        setMinSeverity(payload.data.min_severity);
      } catch (error) {
        if (!mounted) {
          return;
        }
        setStatus("error");
        setMessage(error instanceof Error ? error.message : "Failed to load settings");
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    void loadSettings();

    return () => {
      mounted = false;
    };
  }, []);

  async function onSave() {
    setStatus("saving");
    setMessage("");

    try {
      const response = await fetch("/api/settings/notifications", {
        method: "PUT",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          enabled,
          min_severity: minSeverity,
        }),
      });

      const payload = (await response.json()) as ApiResponse;
      if (!response.ok || !payload.success || !payload.data) {
        throw new Error(payload.error?.message || "Failed to save notification settings");
      }

      setEnabled(payload.data.enabled);
      setMinSeverity(payload.data.min_severity);
      setStatus("saved");
      setMessage("Notification settings saved.");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Failed to save settings");
    }
  }

  return (
    <AppShell
      activeRoute="/settings"
      title="Settings"
      subtitle="Configure SMTP alerting behavior for scan uploads."
    >
      <section className="card upload-layout">
        <h2 className="card-title">Email Notifications</h2>
        <p className="muted mt-0">This setting controls alert triggering. SMTP host/credentials/recipient are still read from environment variables.</p>

        <label className="filter-control" htmlFor="notify-enabled">
          <span className="filter-label">Enable notifications</span>
          <input
            id="notify-enabled"
            type="checkbox"
            checked={enabled}
            disabled={loading || status === "saving"}
            onChange={(event) => setEnabled(event.target.checked)}
          />
        </label>

        <label className="filter-control" htmlFor="notify-min-severity">
          <span className="filter-label">Minimum severity to trigger</span>
          <select
            id="notify-min-severity"
            className="filter-select"
            value={minSeverity}
            disabled={loading || status === "saving"}
            onChange={(event) => setMinSeverity(event.target.value as NotificationMinSeverity)}
          >
            {MIN_SEVERITY_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <div className="upload-actions">
          <button type="button" className="primary-button" onClick={onSave} disabled={loading || status === "saving"}>
            {status === "saving" ? "Saving..." : "Save Settings"}
          </button>
        </div>

        {message && (
          <div className={`upload-feedback ${status === "error" ? "upload-feedback--error" : "upload-feedback--success"}`}>{message}</div>
        )}
      </section>
    </AppShell>
  );
}

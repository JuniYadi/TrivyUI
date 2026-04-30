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
      <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-5 shadow-inner grid gap-4">
        <h2 className="mb-0 text-base font-semibold">Email Notifications</h2>
        <p className="mt-0 text-sm text-slate-400">This setting controls alert triggering. SMTP host/credentials/recipient are still read from environment variables.</p>

        <label className="flex items-center gap-3 cursor-pointer" htmlFor="notify-enabled">
          <input
            id="notify-enabled"
            type="checkbox"
            className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600"
            checked={enabled}
            disabled={loading || status === "saving"}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          <span className="text-sm font-semibold text-slate-300">Enable notifications</span>
        </label>

        <label className="grid gap-1" htmlFor="notify-min-severity">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Minimum severity to trigger</span>
          <select
            id="notify-min-severity"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
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

        <div className="flex flex-wrap gap-2">
          <button type="button" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-40" onClick={onSave} disabled={loading || status === "saving"}>
            {status === "saving" ? "Saving..." : "Save Settings"}
          </button>
        </div>

        {message && (
          <div className={`rounded-lg border px-3 py-2 text-sm font-semibold ${status === "error" ? "border-red-900 bg-red-950/40 text-red-200" : "border-green-800 bg-green-950/30 text-green-200"}`}>
            {message}
          </div>
        )}
      </section>
    </AppShell>
  );
}

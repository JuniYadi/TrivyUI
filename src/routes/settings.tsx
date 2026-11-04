import { useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";

type NotificationMinSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

type SaveState = "idle" | "saving" | "saved" | "error";

interface SmtpStatus {
  configured: boolean;
  host: string;
  port: number;
  secure: boolean;
  from: string;
  recipient_count: number;
}

interface ApiResponse {
  success: boolean;
  data?: {
    enabled: boolean;
    min_severity: NotificationMinSeverity;
    smtp?: SmtpStatus;
  };
  error?: { code: string; message: string };
}

const MIN_SEVERITY_OPTIONS: NotificationMinSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [minSeverity, setMinSeverity] = useState<NotificationMinSeverity>("HIGH");
  const [smtp, setSmtp] = useState<SmtpStatus | undefined>();
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
        setSmtp(payload.data.smtp);
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

  const busy = loading || status === "saving";
  const field =
    "h-11 w-full rounded-lg border border-line bg-bg px-3 text-sm text-fg focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50";

  return (
    <AppShell activeRoute="/settings" title="Settings" meta="Notifications and email delivery for scan uploads.">
      <div className="grid gap-4 pb-24 lg:max-w-3xl">
        <Card className="grid gap-4">
          <div>
            <h2 className="text-base font-semibold">Notifications</h2>
            <p className="text-sm text-fg2">Send an email alert when an uploaded scan meets the severity threshold.</p>
          </div>
          <label className="flex min-h-11 cursor-pointer items-center gap-3" htmlFor="notify-enabled">
            <input
              id="notify-enabled"
              type="checkbox"
              className="h-5 w-5 accent-accent"
              checked={enabled}
              disabled={busy}
              onChange={(event) => setEnabled(event.target.checked)}
            />
            <span className="text-sm font-medium">Enable notifications</span>
          </label>
          <label className="grid gap-1" htmlFor="notify-min-severity">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted">Minimum severity to trigger</span>
            <select
              id="notify-min-severity"
              className={field}
              value={minSeverity}
              disabled={busy}
              onChange={(event) => setMinSeverity(event.target.value as NotificationMinSeverity)}
            >
              {MIN_SEVERITY_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
            <span className="text-xs text-muted">Scans with at least one finding at or above this level trigger an alert.</span>
          </label>
        </Card>

        <Card className="grid gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-base font-semibold">Email delivery (SMTP)</h2>
            {smtp && (
              <span
                className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
                  smtp.configured ? "border-success text-success" : "border-warning text-warning"
                }`}
              >
                {smtp.configured ? "Configured" : "Not configured"}
              </span>
            )}
          </div>
          <p className="text-sm text-fg2">
            SMTP host, credentials and recipients are read from server environment variables (<Mono>SMTP_HOST</Mono>,{" "}
            <Mono>SMTP_PORT</Mono>, <Mono>SMTP_FROM</Mono>, <Mono>SMTP_TO</Mono>) and cannot be edited here.
          </p>
          {smtp && (
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted">Host</dt>
              <dd className="break-all">
                <Mono>{smtp.host ? `${smtp.host}:${smtp.port || "?"}` : "—"}</Mono>
              </dd>
              <dt className="text-muted">TLS</dt>
              <dd>{smtp.secure ? "Implicit TLS" : "STARTTLS / plain"}</dd>
              <dt className="text-muted">From</dt>
              <dd className="break-all">
                <Mono>{smtp.from || "—"}</Mono>
              </dd>
              <dt className="text-muted">Recipients</dt>
              <dd>{smtp.recipient_count}</dd>
            </dl>
          )}
        </Card>

        {message && (
          <div
            role={status === "error" ? "alert" : "status"}
            className={`rounded-lg border px-3 py-2 text-sm font-medium ${
              status === "error" ? "border-red-400 text-red-300" : "border-success text-success"
            }`}
          >
            {message}
          </div>
        )}
      </div>

      <div className="fixed inset-x-0 bottom-0 z-20 flex justify-end gap-2 border-t border-line bg-sidebar px-4 py-3 sm:px-6 lg:left-[232px]">
        <Button variant="primary" className="min-h-11 px-5" onClick={onSave} disabled={busy}>
          {status === "saving" ? "Saving..." : "Save settings"}
        </Button>
      </div>
    </AppShell>
  );
}

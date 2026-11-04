import { useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: { code: string; message: string };
}

interface ApiKeyItem {
  id: number;
  label: string;
  masked_key: string;
  is_active: boolean;
  created_at: string;
  last_used_at: string | null;
}

interface CreatedKey {
  id: number;
  label: string;
  api_key: string;
  masked_key: string;
  created_at: string;
}

function formatDate(value: string | null): string {
  if (!value) {
    return "—";
  }
  const date = new Date(value.includes("T") ? value : `${value.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function ApiKeysPage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<ApiKeyItem[]>([]);
  const [label, setLabel] = useState("");
  const [createError, setCreateError] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [latestPlaintext, setLatestPlaintext] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmId, setConfirmId] = useState<number | null>(null);

  async function loadKeys() {
    const response = await fetch("/api/api-keys");
    const payload = (await response.json()) as ApiResponse<ApiKeyItem[]>;
    if (!response.ok || !payload.success || !payload.data) {
      throw new Error(payload.error?.message || "Failed to load API keys");
    }
    setItems(payload.data);
  }

  useEffect(() => {
    let mounted = true;

    async function start() {
      try {
        await loadKeys();
      } catch (error) {
        if (mounted) {
          setCreateError(error instanceof Error ? error.message : "Failed to load API keys");
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    void start();

    return () => {
      mounted = false;
    };
  }, []);

  async function onCreate() {
    setCreateBusy(true);
    setCreateError("");
    setLatestPlaintext(null);
    setCopied(false);

    try {
      const response = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label }),
      });

      const payload = (await response.json()) as ApiResponse<CreatedKey>;
      if (!response.ok || !payload.success || !payload.data) {
        throw new Error(payload.error?.message || "Failed to create API key");
      }

      setLatestPlaintext(payload.data.api_key);
      setLabel("");
      await loadKeys();
    } catch (error) {
      setCreateError(error instanceof Error ? error.message : "Failed to create API key");
    } finally {
      setCreateBusy(false);
    }
  }

  async function onRevoke(id: number) {
    setConfirmId(null);
    const response = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
    if (!response.ok) {
      setCreateError("Failed to revoke API key");
      return;
    }
    await loadKeys();
  }

  async function onCopy() {
    if (!latestPlaintext) {
      return;
    }
    try {
      await navigator.clipboard.writeText(latestPlaintext);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <AppShell activeRoute="/api-keys" title="API keys" meta="Keys authorise protected POST endpoints such as scan upload.">
      <div className="grid gap-4">
        <Card className="grid gap-3">
          <div>
            <h2 className="text-base font-semibold">Create key</h2>
            <p className="text-sm text-fg2">The plaintext key is shown only once. Store it securely before leaving this page.</p>
          </div>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              void onCreate();
            }}
          >
            <label className="grid min-w-0 flex-1 basis-56 gap-1" htmlFor="api-key-label">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">Label</span>
              <input
                id="api-key-label"
                className="h-11 w-full rounded-lg border border-line bg-bg px-3 text-sm text-fg placeholder:text-muted focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50"
                value={label}
                disabled={loading || createBusy}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="e.g. CI uploader"
              />
            </label>
            <Button type="submit" variant="primary" className="min-h-11 px-5" disabled={loading || createBusy}>
              {createBusy ? "Creating..." : "Create key"}
            </Button>
          </form>

          {latestPlaintext && (
            <div role="status" className="grid gap-2 rounded-lg border border-success bg-bg p-3">
              <p className="text-sm font-medium text-success">Copy your new key now. It will not be shown again.</p>
              <div className="flex flex-wrap items-center gap-2">
                <code className="min-w-0 flex-1 basis-56 break-all rounded-md border border-line bg-card px-2 py-2 font-mono text-sm text-fg">
                  {latestPlaintext}
                </code>
                <Button className="min-h-11" onClick={() => void onCopy()}>
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
            </div>
          )}
          {createError && (
            <div role="alert" className="rounded-lg border border-red-400 px-3 py-2 text-sm font-medium text-red-300">
              {createError}
            </div>
          )}
        </Card>

        <Card className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-muted">
                  <th className="px-4 py-3 font-semibold">Name</th>
                  <th className="px-4 py-3 font-semibold">Key</th>
                  <th className="px-4 py-3 font-semibold">Created</th>
                  <th className="px-4 py-3 font-semibold">Last used</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 text-right font-semibold">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} className="border-b border-rowline last:border-0">
                    <td className="px-4 py-2 font-medium">{item.label}</td>
                    <td className="px-4 py-2">
                      <Mono className="text-fg2">{item.masked_key}</Mono>
                    </td>
                    <td className="px-4 py-2 text-fg2">{formatDate(item.created_at)}</td>
                    <td className="px-4 py-2 text-fg2">{formatDate(item.last_used_at)}</td>
                    <td className="px-4 py-2">
                      <span
                        className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${
                          item.is_active ? "border-success text-success" : "border-line text-muted"
                        }`}
                      >
                        {item.is_active ? "Active" : "Revoked"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      {item.is_active &&
                        (confirmId === item.id ? (
                          <span className="inline-flex items-center gap-1">
                            <Button variant="quiet" className="min-h-11" onClick={() => setConfirmId(null)}>
                              Cancel
                            </Button>
                            <Button className="min-h-11 border-red-400 text-red-300" onClick={() => void onRevoke(item.id)}>
                              Confirm revoke
                            </Button>
                          </span>
                        ) : (
                          <Button variant="quiet" className="min-h-11" onClick={() => setConfirmId(item.id)}>
                            Revoke
                          </Button>
                        ))}
                    </td>
                  </tr>
                ))}
                {!loading && items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-6 text-center text-muted">
                      No API keys yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

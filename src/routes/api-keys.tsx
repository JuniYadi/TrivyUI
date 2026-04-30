import { useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";

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

export function ApiKeysPage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<ApiKeyItem[]>([]);
  const [label, setLabel] = useState("");
  const [createError, setCreateError] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [latestPlaintext, setLatestPlaintext] = useState<string | null>(null);

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
    const response = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
    if (!response.ok) {
      return;
    }
    await loadKeys();
  }

  return (
      <AppShell
       activeRoute="/api-keys"
       title="API Keys"
       subtitle="Generate one-time view keys for protected POST endpoints."
     >
      <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-5 shadow-inner grid gap-4">
        <h2 className="mb-0 text-base font-semibold">Generate API Key</h2>
        <p className="mt-0 text-sm text-slate-400">The plaintext key is shown only once. Save it securely before leaving this page.</p>

        <label className="grid gap-1" htmlFor="api-key-label">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Label</span>
          <input
            id="api-key-label"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
            value={label}
            disabled={loading || createBusy}
            onChange={(event) => setLabel(event.target.value)}
            placeholder="e.g. CI uploader"
          />
        </label>

        <div className="flex flex-wrap gap-2">
          <button type="button" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-40" onClick={onCreate} disabled={loading || createBusy}>
            {createBusy ? "Generating..." : "Generate Key"}
          </button>
        </div>

        {latestPlaintext && <div className="rounded-lg border border-green-800 bg-green-950/30 px-3 py-2 text-sm font-semibold text-green-200">One-time key: {latestPlaintext}</div>}
        {createError && <div className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm font-semibold text-red-200">{createError}</div>}
      </section>

      <section className="mt-4 rounded-xl border border-slate-700 bg-slate-900/90 p-5 shadow-inner">
        <h2 className="mb-4 text-base font-semibold">Existing Keys</h2>
        <ul className="m-0 list-none space-y-3 p-0">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between rounded-lg border border-slate-700/80 bg-slate-950/60 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold">{item.label}</span>
                <span className="text-sm text-slate-400">{item.masked_key}</span>
                <span className={`rounded-full px-2 py-0.5 text-xs font-bold ${item.is_active ? "bg-green-950 text-green-200" : "bg-gray-800 text-gray-400"}`}>
                  {item.is_active ? "active" : "revoked"}
                </span>
              </div>
              {item.is_active && (
                <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm font-semibold text-slate-300 transition hover:border-slate-500" onClick={() => void onRevoke(item.id)}>
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      </section>
    </AppShell>
  );
}

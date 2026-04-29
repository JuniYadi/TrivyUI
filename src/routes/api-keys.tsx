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
      <section className="card upload-layout">
        <h2 className="card-title">Generate API Key</h2>
        <p className="muted mt-0">The plaintext key is shown only once. Save it securely before leaving this page.</p>

        <label className="filter-control" htmlFor="api-key-label">
          <span className="filter-label">Label</span>
          <input
            id="api-key-label"
            className="filter-select"
            value={label}
            disabled={loading || createBusy}
            onChange={(event) => setLabel(event.target.value)}
            placeholder="e.g. CI uploader"
          />
        </label>

        <div className="upload-actions">
          <button type="button" className="primary-button" onClick={onCreate} disabled={loading || createBusy}>
            {createBusy ? "Generating..." : "Generate Key"}
          </button>
        </div>

        {latestPlaintext && <div className="upload-feedback upload-feedback--success">One-time key: {latestPlaintext}</div>}
        {createError && <div className="upload-feedback upload-feedback--error">{createError}</div>}
      </section>

      <section className="card mt-4">
        <h2 className="card-title">Existing Keys</h2>
        <ul>
          {items.map((item) => (
            <li key={item.id}>
              <strong>{item.label}</strong> - {item.masked_key} - {item.is_active ? "active" : "revoked"}
              {item.is_active && (
                <button type="button" className="shell-nav__link" onClick={() => void onRevoke(item.id)}>
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

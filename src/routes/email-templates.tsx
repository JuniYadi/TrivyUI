import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../components/app-shell";

type SaveState = "idle" | "saving" | "saved" | "error";

interface EmailTemplate {
  template_key: string;
  name: string;
  subject: string;
  html_body: string;
  text_body: string | null;
  enabled: boolean;
}

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: { code: string; message: string };
}

export function EmailTemplatesPage() {
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<SaveState>("idle");
  const [message, setMessage] = useState("");
  const [templates, setTemplates] = useState<EmailTemplate[]>([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [subject, setSubject] = useState("");
  const [htmlBody, setHtmlBody] = useState("");
  const [textBody, setTextBody] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [snapshot, setSnapshot] = useState<{ subject: string; htmlBody: string; textBody: string; enabled: boolean } | null>(null);

  const selected = useMemo(() => templates.find((item) => item.template_key === selectedKey) ?? null, [templates, selectedKey]);

  const isDirty = Boolean(
    snapshot &&
      (snapshot.subject !== subject || snapshot.htmlBody !== htmlBody || snapshot.textBody !== textBody || snapshot.enabled !== enabled)
  );

  useEffect(() => {
    let mounted = true;

    async function loadTemplates() {
      try {
        const response = await fetch("/api/email-templates");
        const payload = (await response.json()) as ApiResponse<EmailTemplate[]>;

        if (!response.ok || !payload.success || !payload.data) {
          throw new Error(payload.error?.message || "Failed to load email templates");
        }

        if (!mounted) {
          return;
        }

        setTemplates(payload.data);

        if (payload.data.length > 0) {
          setSelectedKey(payload.data[0].template_key);
          hydrateForm(payload.data[0]);
        }
      } catch (error) {
        if (!mounted) {
          return;
        }
        setStatus("error");
        setMessage(error instanceof Error ? error.message : "Failed to load email templates");
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    void loadTemplates();

    return () => {
      mounted = false;
    };
  }, []);

  function hydrateForm(template: EmailTemplate) {
    setSubject(template.subject);
    setHtmlBody(template.html_body);
    setTextBody(template.text_body ?? "");
    setEnabled(template.enabled);
    setSnapshot({
      subject: template.subject,
      htmlBody: template.html_body,
      textBody: template.text_body ?? "",
      enabled: template.enabled,
    });
  }

  function onSelectTemplate(key: string) {
    const next = templates.find((item) => item.template_key === key);
    if (!next) {
      return;
    }

    setSelectedKey(key);
    setStatus("idle");
    setMessage("");
    hydrateForm(next);
  }

  function onCancel() {
    if (!snapshot) {
      return;
    }

    setSubject(snapshot.subject);
    setHtmlBody(snapshot.htmlBody);
    setTextBody(snapshot.textBody);
    setEnabled(snapshot.enabled);
    setStatus("idle");
    setMessage("Changes discarded.");
  }

  async function onSave() {
    if (!selected) {
      return;
    }

    setStatus("saving");
    setMessage("");

    try {
      const response = await fetch(`/api/email-templates/${encodeURIComponent(selected.template_key)}`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          subject,
          html_body: htmlBody,
          text_body: textBody,
          enabled,
        }),
      });

      const payload = (await response.json()) as ApiResponse<EmailTemplate>;

      if (!response.ok || !payload.success || !payload.data) {
        throw new Error(payload.error?.message || "Failed to save template");
      }

      setTemplates((current) =>
        current.map((item) => (item.template_key === payload.data!.template_key ? payload.data! : item))
      );
      hydrateForm(payload.data);
      setStatus("saved");
      setMessage("Template saved.");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Failed to save template");
    }
  }

  return (
      <AppShell
       activeRoute="/email-templates"
       title="Email Templates"
       subtitle="Edit global templates used for vulnerability notifications."
     >
      <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-5 shadow-inner grid gap-4">
        <h2 className="mb-0 text-base font-semibold">Templates</h2>
        <p className="mt-0 text-sm text-slate-400">Templates are database-backed and applied immediately to new notification sends.</p>

        {loading && <div className="text-slate-400">Loading templates...</div>}

        {!loading && templates.length === 0 && <div className="rounded-lg border border-slate-700 px-3 py-2 text-sm">No templates found.</div>}

        {!loading && templates.length > 0 && (
          <>
            <label className="grid gap-1" htmlFor="email-template-select">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Template</span>
              <select
                id="email-template-select"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
                value={selectedKey}
                disabled={status === "saving"}
                onChange={(event) => onSelectTemplate(event.target.value)}
              >
                {templates.map((template) => (
                  <option key={template.template_key} value={template.template_key}>
                    {template.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="flex items-center gap-3 cursor-pointer" htmlFor="email-template-enabled">
              <input
                id="email-template-enabled"
                type="checkbox"
                className="h-4 w-4 rounded border-slate-600 bg-slate-950 accent-blue-600"
                checked={enabled}
                disabled={status === "saving"}
                onChange={(event) => setEnabled(event.target.checked)}
              />
              <span className="text-sm font-semibold text-slate-300">Enabled</span>
            </label>

            <label className="grid gap-1" htmlFor="email-template-subject">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Subject</span>
              <input
                id="email-template-subject"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
                value={subject}
                disabled={status === "saving"}
                onChange={(event) => setSubject(event.target.value)}
              />
            </label>

            <label className="grid gap-1" htmlFor="email-template-html">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">HTML body</span>
              <textarea
                id="email-template-html"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
                rows={12}
                value={htmlBody}
                disabled={status === "saving"}
                onChange={(event) => setHtmlBody(event.target.value)}
              />
            </label>

            <label className="grid gap-1" htmlFor="email-template-text">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Text body (optional)</span>
              <textarea
                id="email-template-text"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
                rows={8}
                value={textBody}
                disabled={status === "saving"}
                onChange={(event) => setTextBody(event.target.value)}
              />
            </label>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-40"
                onClick={onSave}
                disabled={status === "saving" || !isDirty || !selected}
              >
                {status === "saving" ? "Saving..." : "Save Template"}
              </button>
              <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500 disabled:opacity-40" onClick={onCancel} disabled={status === "saving" || !isDirty}>
                Cancel
              </button>
            </div>
          </>
        )}

        {message && (
          <div className={`rounded-lg border px-3 py-2 text-sm font-semibold ${status === "error" ? "border-red-900 bg-red-950/40 text-red-200" : "border-green-800 bg-green-950/30 text-green-200"}`}>
            {message}
          </div>
        )}
      </section>
    </AppShell>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "../components/app-shell";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";

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

const VARIABLES: Record<string, string> = {
  repository: "acme/payments-api",
  image: "acme/payments-api:1.4.2",
  parsed_at: "2026-01-15 09:30 UTC",
  critical_count: "3",
  high_count: "12",
  medium_count: "27",
  low_count: "8",
  unknown_count: "0",
  total_count: "50",
  dashboard_url: "http://localhost:3000/repositories",
  critical_list_items: "<li><strong>CVE-2026-0001</strong> - openssl (CVSS 9.8) (fixed: 3.0.14)</li>",
  top_cves_text: "CVE-2026-0001 (openssl)",
};

function renderPreview(template: string): string {
  return template.replace(/\{\{\s*([a-z0-9_]+)\s*\}\}/gi, (_, key: string) => VARIABLES[key] ?? "");
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
  const htmlRef = useRef<HTMLTextAreaElement>(null);
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

  function insertVariable(name: string) {
    const token = `{{${name}}}`;
    const el = htmlRef.current;
    const start = el?.selectionStart ?? htmlBody.length;
    const end = el?.selectionEnd ?? htmlBody.length;
    setHtmlBody(htmlBody.slice(0, start) + token + htmlBody.slice(end));
    requestAnimationFrame(() => {
      el?.focus();
      el?.setSelectionRange(start + token.length, start + token.length);
    });
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

  const input =
    "w-full rounded-lg border border-line bg-bg px-3 text-sm text-fg focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50";
  const saving = status === "saving";

  return (
    <AppShell activeRoute="/email-templates" title="Email templates" meta="Global templates used for vulnerability notifications. Changes apply to new sends immediately.">
      {loading && <div className="text-muted">Loading templates...</div>}
      {!loading && templates.length === 0 && <Card className="text-sm">No templates found.</Card>}

      {!loading && templates.length > 0 && (
        <div className="grid gap-4 pb-24 lg:grid-cols-[200px_minmax(0,1fr)] xl:grid-cols-[200px_minmax(0,1fr)_minmax(0,1fr)]">
          <nav aria-label="Templates" className="flex gap-2 overflow-x-auto lg:flex-col lg:overflow-visible">
            {templates.map((template) => {
              const active = template.template_key === selectedKey;
              return (
                <button
                  key={template.template_key}
                  type="button"
                  aria-current={active ? "true" : undefined}
                  disabled={saving}
                  onClick={() => onSelectTemplate(template.template_key)}
                  className={`min-h-11 shrink-0 rounded-lg border px-3 text-left text-sm font-medium focus-visible:outline-2 focus-visible:outline-accent ${
                    active ? "border-accent bg-accent/15 text-link" : "border-line bg-card text-fg2 hover:border-accent"
                  }`}
                >
                  {template.name}
                </button>
              );
            })}
          </nav>

          <Card className="grid min-w-0 content-start gap-4">
            <label className="flex min-h-11 cursor-pointer items-center gap-3" htmlFor="email-template-enabled">
              <input
                id="email-template-enabled"
                type="checkbox"
                className="h-5 w-5 accent-accent"
                checked={enabled}
                disabled={saving}
                onChange={(event) => setEnabled(event.target.checked)}
              />
              <span className="text-sm font-medium">Enabled</span>
            </label>

            <label className="grid gap-1" htmlFor="email-template-subject">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">Subject</span>
              <input
                id="email-template-subject"
                className={`${input} h-11`}
                value={subject}
                disabled={saving}
                onChange={(event) => setSubject(event.target.value)}
              />
            </label>

            <div className="grid gap-1">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">Insert variable at cursor in HTML body</span>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(VARIABLES).map((name) => (
                  <button
                    key={name}
                    type="button"
                    disabled={saving}
                    onClick={() => insertVariable(name)}
                    className="min-h-11 rounded-full border border-line bg-bg px-3 font-mono text-xs text-fg2 hover:border-accent focus-visible:outline-2 focus-visible:outline-accent lg:min-h-8"
                  >
                    {name}
                  </button>
                ))}
              </div>
            </div>

            <label className="grid gap-1" htmlFor="email-template-html">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">HTML body</span>
              <textarea
                id="email-template-html"
                ref={htmlRef}
                className={`${input} py-2 font-mono`}
                rows={12}
                value={htmlBody}
                disabled={saving}
                onChange={(event) => setHtmlBody(event.target.value)}
              />
            </label>

            <label className="grid gap-1" htmlFor="email-template-text">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">Text body (optional)</span>
              <textarea
                id="email-template-text"
                className={`${input} py-2 font-mono`}
                rows={6}
                value={textBody}
                disabled={saving}
                onChange={(event) => setTextBody(event.target.value)}
              />
            </label>

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
          </Card>

          <Card className="grid min-w-0 content-start gap-3 lg:col-span-2 xl:col-span-1">
            <h2 className="text-base font-semibold">Live preview</h2>
            <p className="break-words text-sm">
              <span className="text-muted">Subject: </span>
              {renderPreview(subject)}
            </p>
            <iframe
              title="Email HTML preview"
              sandbox=""
              srcDoc={`<body style="font-family:sans-serif;font-size:14px;margin:12px">${renderPreview(htmlBody)}</body>`}
              className="h-96 w-full rounded-lg border border-line bg-white"
            />
            <p className="text-xs text-muted">Preview uses sample values.</p>
          </Card>
        </div>
      )}

      {!loading && templates.length > 0 && (
        <div className="fixed inset-x-0 bottom-0 z-20 flex justify-end gap-2 border-t border-line bg-sidebar px-4 py-3 sm:px-6 lg:left-[232px]">
          <Button className="min-h-11" onClick={onCancel} disabled={saving || !isDirty}>
            Reset
          </Button>
          <Button variant="primary" className="min-h-11 px-5" onClick={onSave} disabled={saving || !isDirty || !selected}>
            {saving ? "Saving..." : "Save template"}
          </Button>
        </div>
      )}
    </AppShell>
  );
}

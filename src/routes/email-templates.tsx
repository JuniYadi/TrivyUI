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
      <section className="card upload-layout">
        <h2 className="card-title">Templates</h2>
        <p className="muted mt-0">Templates are database-backed and applied immediately to new notification sends.</p>

        {loading && <div className="muted">Loading templates...</div>}

        {!loading && templates.length === 0 && <div className="upload-feedback">No templates found.</div>}

        {!loading && templates.length > 0 && (
          <>
            <label className="filter-control" htmlFor="email-template-select">
              <span className="filter-label">Template</span>
              <select
                id="email-template-select"
                className="filter-select"
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

            <label className="filter-control" htmlFor="email-template-enabled">
              <span className="filter-label">Enabled</span>
              <input
                id="email-template-enabled"
                type="checkbox"
                checked={enabled}
                disabled={status === "saving"}
                onChange={(event) => setEnabled(event.target.checked)}
              />
            </label>

            <label className="filter-control" htmlFor="email-template-subject">
              <span className="filter-label">Subject</span>
              <input
                id="email-template-subject"
                className="filter-input"
                value={subject}
                disabled={status === "saving"}
                onChange={(event) => setSubject(event.target.value)}
              />
            </label>

            <label className="filter-control" htmlFor="email-template-html">
              <span className="filter-label">HTML body</span>
              <textarea
                id="email-template-html"
                className="upload-textarea"
                rows={12}
                value={htmlBody}
                disabled={status === "saving"}
                onChange={(event) => setHtmlBody(event.target.value)}
              />
            </label>

            <label className="filter-control" htmlFor="email-template-text">
              <span className="filter-label">Text body (optional)</span>
              <textarea
                id="email-template-text"
                className="upload-textarea"
                rows={8}
                value={textBody}
                disabled={status === "saving"}
                onChange={(event) => setTextBody(event.target.value)}
              />
            </label>

            <div className="upload-actions">
              <button
                type="button"
                className="primary-button"
                onClick={onSave}
                disabled={status === "saving" || !isDirty || !selected}
              >
                {status === "saving" ? "Saving..." : "Save Template"}
              </button>
              <button type="button" className="secondary-button" onClick={onCancel} disabled={status === "saving" || !isDirty}>
                Cancel
              </button>
            </div>
          </>
        )}

        {message && (
          <div className={`upload-feedback ${status === "error" ? "upload-feedback--error" : "upload-feedback--success"}`}>{message}</div>
        )}
      </section>
    </AppShell>
  );
}

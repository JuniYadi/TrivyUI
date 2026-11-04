import type React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent } from "react";
import { navigate } from "../lib/navigation";
import { AppShell } from "../components/app-shell";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";

type UploadMode = "single" | "batch";
type FeedbackType = "success" | "error";
type UploadTab = "file" | "paste";

type UploadFeedback = {
  type: FeedbackType;
  message: string;
};

interface RecentUpload {
  id: number;
  repository: string;
  image: string;
  vulnerability_count: number;
  scanned_at: string;
}

function formatFileSize(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }

  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }

  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function NavLink({ to, className, children }: { to: string; className?: string; children: React.ReactNode }) {
  return (
    <a
      href={to}
      className={className}
      onClick={(event) => {
        event.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export function formatRelativeTime(value: string, now: number = Date.now()): string {
  const hasZone = /Z$|[+-]\d{2}:?\d{2}$/.test(value);
  const iso = value.includes("T") ? value : value.replace(" ", "T");
  const ms = Date.parse(hasZone ? iso : `${iso}Z`);
  if (!Number.isFinite(ms)) return value;
  const minutes = Math.max(0, Math.round((now - ms) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

/** Three-step CI snippet. `--show-suppressed` keeps ignored CVEs in the report (Trivy >= v0.50.0). */
export function buildCiSnippet(origin: string): string {
  return [
    "# 1. Get the ignore file for this repo + tag",
    `curl -s -H "X-API-Key: $TRIVYUI_API_KEY" -o .trivyignore \\`,
    `  "${origin}/api/trivy-ignore/generate?repo=$REPO&tag=$TAG"`,
    "",
    "# 2. Scan: ignore rules apply, ignored CVEs stay in the report",
    "trivy image --format json \\",
    "  --ignorefile .trivyignore \\",
    "  --show-suppressed \\",
    '  -o report.json "$IMAGE"',
    "",
    "# 3. Upload",
    `curl -X POST ${origin}/api/upload \\`,
    `  -H "X-API-Key: $TRIVYUI_API_KEY" \\`,
    '  -F "file=@report.json;type=application/json"',
  ].join("\n");
}

const IS_DEV = typeof process !== "undefined" && process.env?.NODE_ENV !== "production";

function uploadWithProgress(url: string, formData: FormData, onProgress: (value: number) => void): Promise<Response> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);

    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });

    xhr.addEventListener("load", () => {
      const body = xhr.responseText;
      resolve(
        new Response(body, {
          status: xhr.status,
          statusText: xhr.statusText,
          headers: {
            "content-type": xhr.getResponseHeader("content-type") || "application/json",
          },
        })
      );
    });

    xhr.addEventListener("error", () => {
      reject(new Error("Network error while uploading files"));
    });

    xhr.send(formData);
  });
}

function RecentUploads({ items, loaded }: { items: RecentUpload[]; loaded: boolean }) {
  return (
    <Card className="p-0">
      <div className="flex items-center justify-between border-b border-rowline px-4 py-3">
        <h2 className="m-0 text-sm font-semibold">Recent uploads</h2>
        <NavLink to="/images" className="inline-flex min-h-11 items-center text-sm text-link">
          View all
        </NavLink>
      </div>
      {items.length === 0 ? (
        <p className="m-0 px-4 py-4 text-sm text-muted">{loaded ? "No uploads yet." : "Loading..."}</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-3 border-b border-rowline px-4 py-3 last:border-0">
              <div className="min-w-0">
                <Mono className="block truncate text-sm">{item.image}</Mono>
                <p className="m-0 text-xs text-muted">
                  {formatRelativeTime(item.scanned_at)} · {item.vulnerability_count} vulns
                </p>
              </div>
              <span className="shrink-0 rounded-full bg-success/15 px-2 py-0.5 text-xs font-semibold text-success">Processed</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function CiSnippetCard({ origin }: { origin: string }) {
  const [copied, setCopied] = useState(false);
  const snippet = buildCiSnippet(origin);

  return (
    <Card>
      <details open>
        <summary className="flex min-h-11 cursor-pointer items-center text-sm font-semibold">Upload via API / CI</summary>
        <p className="mt-1 text-sm text-fg2">
          Send reports from your pipeline. Create a key under{" "}
          <NavLink to="/api-keys" className="text-link">
            API keys
          </NavLink>
          ; use <Mono>/api/upload</Mono> for one file, <Mono>/api/upload/batch</Mono> for several.
        </p>
        <p className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-sm">
          Keep <Mono>--show-suppressed</Mono> in the scan step. Ignored CVEs stay visible (marked suppressed), so{" "}
          <NavLink to="/trivy-ignore" className="text-link">
            Ignore rules
          </NavLink>{" "}
          can show which repositories have already fixed them. Needs Trivy v0.50.0 or newer.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-line bg-bg p-3 font-mono text-xs leading-relaxed">{snippet}</pre>
        <Button
          onClick={() => {
            void navigator.clipboard?.writeText(snippet).then(() => setCopied(true));
          }}
          className="mt-3 min-h-11"
        >
          {copied ? "Copied" : "Copy snippet"}
        </Button>
      </details>
    </Card>
  );
}

export function UploadPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [tab, setTab] = useState<UploadTab>("file");
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [files, setFiles] = useState<File[]>([]);
  const [pastedJson, setPastedJson] = useState("");
  const [feedback, setFeedback] = useState<UploadFeedback | null>(null);
  const [recent, setRecent] = useState<RecentUpload[]>([]);
  const [recentLoaded, setRecentLoaded] = useState(false);

  const mode: UploadMode = files.length > 1 ? "batch" : "single";
  const pastedJsonTrimmed = pastedJson.trim();
  const isPastedJsonValid = useMemo(() => {
    if (pastedJsonTrimmed.length === 0) {
      return false;
    }

    try {
      JSON.parse(pastedJsonTrimmed);
      return true;
    } catch {
      return false;
    }
  }, [pastedJsonTrimmed]);

  async function loadRecent() {
    try {
      const response = await fetch("/api/stats");
      const payload = (await response.json()) as { success: boolean; data?: { recent_scans?: RecentUpload[] } };
      setRecent(payload.success ? (payload.data?.recent_scans ?? []).slice(0, 5) : []);
    } catch {
      setRecent([]);
    } finally {
      setRecentLoaded(true);
    }
  }

  useEffect(() => {
    void loadRecent();
  }, []);

  function onPickFiles(nextFiles: FileList | null) {
    if (!nextFiles) {
      return;
    }

    const normalized = Array.from(nextFiles);
    setFiles(normalized);
    setProgress(0);

    if (normalized.length === 0) {
      setFeedback({ type: "error", message: "No files selected. Please choose at least one file." });
      return;
    }

    setFeedback(null);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    onPickFiles(event.dataTransfer.files);
  }

  async function send(endpoint: string, formData: FormData, describe: (data: Record<string, number | undefined>) => string) {
    setIsUploading(true);
    setFeedback(null);
    setProgress(0);

    try {
      const response = await uploadWithProgress(endpoint, formData, setProgress);
      const payload = (await response.json()) as {
        success: boolean;
        data?: Record<string, number | undefined>;
        error?: { code: string; message: string };
      };

      if (!response.ok || !payload.success) {
        const code = payload.error?.code || "UPLOAD_FAILED";
        const message = payload.error?.message || "Upload failed";
        throw new Error(`${code}: ${message}`);
      }

      setFeedback({ type: "success", message: describe(payload.data ?? {}) });
      setFiles([]);
      void loadRecent();
    } catch (error) {
      setFeedback({ type: "error", message: error instanceof Error ? error.message : "Unexpected upload error" });
    } finally {
      setIsUploading(false);
    }
  }

  async function onUpload() {
    if (files.length === 0) {
      setFeedback({ type: "error", message: "No files selected. Please choose at least one file before uploading." });
      return;
    }

    if (isUploading) {
      return;
    }

    const formData = new FormData();
    if (mode === "batch") {
      for (const file of files) {
        formData.append("files", file);
      }
    } else {
      formData.set("file", files[0]!);
    }

    await send(mode === "batch" ? "/api/upload/batch" : "/api/upload", formData, (data) =>
      mode === "batch"
        ? `Batch upload completed. Success: ${data.successful ?? 0}, failed: ${data.failed ?? 0}.`
        : `Upload completed (scan_result_id: ${data.scan_result_id ?? "n/a"}, vulnerabilities: ${data.vulnerability_count ?? 0}, packages: ${data.package_count ?? 0}).`,
    );
  }

  async function onUploadPastedJson() {
    if (isUploading) {
      return;
    }

    if (pastedJsonTrimmed.length === 0) {
      setFeedback({ type: "error", message: "Paste JSON content before uploading." });
      return;
    }

    if (!isPastedJsonValid) {
      setFeedback({ type: "error", message: "Pasted content must be valid JSON." });
      return;
    }

    const formData = new FormData();
    formData.set("file", new File([pastedJsonTrimmed], "trivy-pasted.json", { type: "application/json" }));

    await send("/api/upload", formData, (data) =>
      `Pasted JSON uploaded (scan_result_id: ${data.scan_result_id ?? "n/a"}, vulnerabilities: ${data.vulnerability_count ?? 0}, packages: ${data.package_count ?? 0}).`,
    );
    setPastedJson("");
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "https://your-host";
  const tabClass = (active: boolean) =>
    `min-h-11 border-b-2 px-4 text-sm font-medium ${active ? "border-accent text-fg" : "border-transparent text-fg2 hover:text-fg"}`;

  return (
    <AppShell activeRoute="/upload" title="Upload scan" meta="Add Trivy JSON reports. Results appear on the dashboard as soon as processing finishes.">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
        <Card className="p-0">
          <div role="tablist" aria-label="Upload method" className="flex border-b border-rowline px-2">
            <button type="button" role="tab" aria-selected={tab === "file"} className={tabClass(tab === "file")} onClick={() => setTab("file")}>
              File
            </button>
            <button type="button" role="tab" aria-selected={tab === "paste"} className={tabClass(tab === "paste")} onClick={() => setTab("paste")}>
              Paste JSON
            </button>
          </div>

          <div className="grid gap-3 p-4">
            {tab === "file" ? (
              <>
                <div
                  role="button"
                  tabIndex={0}
                  className={`grid min-h-[140px] cursor-pointer place-content-center gap-1 rounded-xl border border-dashed border-accent p-5 text-center ${isDragging ? "bg-accent/10" : "bg-bg"}`}
                  onDragOver={(event) => {
                    event.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={onDrop}
                  onClick={() => inputRef.current?.click()}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      inputRef.current?.click();
                    }
                  }}
                >
                  <strong>Drop Trivy JSON files here</strong>
                  <span className="text-sm text-fg2">
                    or <span className="text-link underline">browse files</span> · multiple files allowed
                  </span>
                  <input
                    ref={inputRef}
                    className="hidden"
                    type="file"
                    accept="application/json,.json"
                    multiple
                    onChange={(event) => onPickFiles(event.target.files)}
                  />
                </div>

                {files.length > 0 && (
                  <ul className="m-0 grid list-none gap-2 p-0" aria-label="Selected files">
                    {files.map((file) => (
                      <li key={`${file.name}-${file.size}`} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-bg px-3 py-2 text-sm">
                        <Mono className="truncate">{file.name}</Mono>
                        <span className="shrink-0 text-muted">{formatFileSize(file.size)}</span>
                      </li>
                    ))}
                  </ul>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm text-fg2">{files.length > 0 ? `${files.length} file${files.length === 1 ? "" : "s"} ready` : "No file selected."}</span>
                  <div className="flex gap-2">
                    {files.length > 0 && (
                      <Button variant="quiet" className="min-h-11" onClick={() => setFiles([])} disabled={isUploading}>
                        Clear
                      </Button>
                    )}
                    <Button variant="primary" className="min-h-11" onClick={onUpload} disabled={files.length === 0 || isUploading}>
                      {isUploading ? "Uploading..." : files.length > 1 ? `Upload ${files.length} files` : "Upload"}
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <>
                <p className="m-0 text-sm text-fg2">If CI output cannot be downloaded as a file, paste the JSON here. Only valid JSON is accepted.</p>
                <textarea
                  aria-label="Trivy JSON"
                  className="min-h-[10rem] w-full rounded-lg border border-line bg-bg px-3 py-2 font-mono text-sm outline-none focus:border-accent"
                  placeholder='Paste full Trivy JSON here, e.g. {"SchemaVersion":2,"Results":[...]}'
                  value={pastedJson}
                  onChange={(event) => {
                    setPastedJson(event.target.value);
                    if (feedback?.type === "error") {
                      setFeedback(null);
                    }
                  }}
                  spellCheck={false}
                />
                {pastedJsonTrimmed.length > 0 && !isPastedJsonValid && <p className="m-0 text-sm font-semibold text-red-500">Invalid JSON format. Please paste valid JSON only.</p>}
                {pastedJsonTrimmed.length > 0 && isPastedJsonValid && <p className="m-0 text-sm font-semibold text-success">Valid JSON format detected.</p>}
                <div className="flex justify-end">
                  <Button variant="primary" className="min-h-11" onClick={onUploadPastedJson} disabled={!isPastedJsonValid || isUploading}>
                    {isUploading ? "Uploading..." : "Upload"}
                  </Button>
                </div>
              </>
            )}

            {isUploading && (
              <div aria-live="polite">
                <div className="h-2 w-full overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
                  <div className="h-full rounded-full bg-accent transition-all duration-200" style={{ width: `${progress}%` }} />
                </div>
                <p className="m-0 mt-1 text-xs text-muted">Uploading... {progress}%</p>
              </div>
            )}

            {feedback && (
              <div
                role={feedback.type === "error" ? "alert" : "status"}
                className={`rounded-lg border px-3 py-2 text-sm font-semibold ${feedback.type === "success" ? "border-success/40 bg-success/10 text-success" : "border-red-500/40 bg-red-500/10 text-red-500"}`}
              >
                {feedback.message}
              </div>
            )}
          </div>
        </Card>

        <RecentUploads items={recent} loaded={recentLoaded} />
      </div>

      <div className="mt-4 grid gap-4">
        <CiSnippetCard origin={origin} />

        {IS_DEV && (
          <Card>
            <h2 className="mb-2 mt-0 text-sm font-semibold">Local sample data (dev only)</h2>
            <p className="mt-0 text-sm text-fg2">Seed local SQLite data to preview a non-empty dashboard.</p>
            <code className="mt-2 block overflow-x-auto rounded-lg border border-line bg-bg px-3 py-2 text-sm text-link">PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard</code>
          </Card>
        )}
      </div>
    </AppShell>
  );
}

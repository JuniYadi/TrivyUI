import { useMemo, useRef, useState } from "react";
import type { DragEvent } from "react";
import { AppShell } from "../components/app-shell";
import { navigate } from "../lib/navigation";

type UploadMode = "single" | "batch";
type FeedbackType = "success" | "error";

type UploadFeedback = {
  type: FeedbackType;
  message: string;
};

function formatFileSize(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }

  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }

  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

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

export function UploadPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [files, setFiles] = useState<File[]>([]);
  const [feedback, setFeedback] = useState<UploadFeedback | null>(null);

  const mode: UploadMode = files.length > 1 ? "batch" : "single";

  const fileSummary = useMemo(() => {
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
    return {
      count: files.length,
      totalBytes,
    };
  }, [files]);

  function onPickFiles(nextFiles: FileList | null) {
    if (!nextFiles) {
      return;
    }

    const normalized = Array.from(nextFiles);
    setFiles(normalized);
    setProgress(0);

    if (normalized.length === 0) {
      setFeedback({
        type: "error",
        message: "No files selected. Please choose at least one file.",
      });
      return;
    }

    setFeedback(null);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    onPickFiles(event.dataTransfer.files);
  }

  async function onUpload() {
    if (files.length === 0) {
      setFeedback({
        type: "error",
        message: "No files selected. Please choose at least one file before uploading.",
      });
      return;
    }

    if (isUploading) {
      return;
    }

    const endpoint = mode === "batch" ? "/api/upload/batch" : "/api/upload";
    const formData = new FormData();

    if (mode === "batch") {
      for (const file of files) {
        formData.append("files", file);
      }
    } else {
      formData.set("file", files[0]);
    }

    setIsUploading(true);
    setFeedback(null);
    setProgress(0);

    try {
      const response = await uploadWithProgress(endpoint, formData, setProgress);
      const payload = (await response.json()) as {
        success: boolean;
        data?: {
          scan_result_id?: number;
          vulnerability_count?: number;
          package_count?: number;
          successful?: number;
          failed?: number;
        };
        error?: { code: string; message: string };
      };

      if (!response.ok || !payload.success) {
        const code = payload.error?.code || "UPLOAD_FAILED";
        const message = payload.error?.message || "Upload failed";
        throw new Error(`${code}: ${message}`);
      }

      if (mode === "batch") {
        setFeedback({
          type: "success",
          message: `Batch upload completed. Success: ${payload.data?.successful ?? 0}, failed: ${payload.data?.failed ?? 0}.`,
        });
      } else {
        setFeedback({
          type: "success",
          message: `Upload completed (scan_result_id: ${payload.data?.scan_result_id ?? "n/a"}, vulnerabilities: ${payload.data?.vulnerability_count ?? 0}, packages: ${payload.data?.package_count ?? 0}).`,
        });
      }

      setProgress(100);
    } catch (error) {
      setFeedback({
        type: "error",
        message: error instanceof Error ? error.message : "Unexpected upload error",
      });
    } finally {
      setProgress(100);
      setIsUploading(false);
    }
  }

  return (
      <AppShell
       activeRoute="/upload"
       title="Upload Trivy Scan"
       subtitle="Upload one or multiple Trivy JSON reports with progress tracking and API feedback."
     >
      <div className="grid gap-4">
        <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner grid gap-4">
          <h2 className="mb-0 text-base font-semibold">Upload reports</h2>
          <p className="mt-0 text-sm text-slate-400">Drag-and-drop JSON files or use file picker. One file uses /api/upload, multiple files use /api/upload/batch.</p>

          <div
            role="button"
            tabIndex={0}
            className={`rounded-xl border border-dashed border-blue-500 bg-slate-950/60 p-5 text-center cursor-pointer grid gap-1 ${isDragging ? "border-blue-300 bg-blue-950/20" : ""}`}
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
            <span className="text-sm text-slate-400">or click to choose file(s)</span>
            <input
              ref={inputRef}
              className="hidden"
              type="file"
              accept="application/json,.json"
              multiple
              onChange={(event) => onPickFiles(event.target.files)}
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500 disabled:opacity-40" onClick={() => inputRef.current?.click()} disabled={isUploading}>
              Choose Files
            </button>
            <button type="button" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-40" onClick={onUpload} disabled={files.length === 0 || isUploading}>
              {isUploading ? "Uploading..." : mode === "batch" ? "Upload Batch" : "Upload File"}
            </button>
            <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500" onClick={() => navigate("/dashboard")}>Back to Dashboard</button>
          </div>

          <div className="text-sm text-slate-400">
            {fileSummary.count > 0
              ? `${fileSummary.count} file(s) selected • ${formatFileSize(fileSummary.totalBytes)} • mode: ${mode}`
              : "No file selected."}
          </div>

          {files.length > 0 && (
            <ul className="m-0 list-none space-y-1 p-0 pl-4">
              {files.map((file) => (
                <li key={`${file.name}-${file.size}`} className="text-sm">{file.name} ({formatFileSize(file.size)})</li>
              ))}
            </ul>
          )}

          <div className="h-2.5 w-full overflow-hidden rounded-full border border-slate-700 bg-slate-900" aria-live="polite">
            <div className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-200" style={{ width: `${progress}%` }} />
          </div>
          <p className="m-0 text-sm text-slate-400">Progress: {progress}%</p>

          {feedback && (
            <div className={`rounded-lg border px-3 py-2 text-sm font-semibold ${feedback.type === "success" ? "border-green-800 bg-green-950/30 text-green-200" : "border-red-900 bg-red-950/40 text-red-200"}`}>
              {feedback.message}
            </div>
          )}
        </section>

        <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
          <h2 className="mb-2 text-base font-semibold">Local sample data (dev only)</h2>
          <p className="mt-0 text-sm text-slate-400">
            Need non-empty dashboard quickly? Seed local SQLite data for preview. This command is for local development only and does not affect API contract.
          </p>
          <code className="mt-2 block rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-cyan-300 overflow-x-auto">PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard</code>
        </section>
      </div>
    </AppShell>
  );
}

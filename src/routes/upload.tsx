import { useMemo, useRef, useState } from "react";
import type { DragEvent } from "react";
import { AppShell } from "../components/app-shell";

type UploadMode = "single" | "batch";
type FeedbackType = "success" | "error";

type UploadFeedback = {
  type: FeedbackType;
  message: string;
};

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
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

    const normalized = Array.from(nextFiles).filter((file) => file.name.toLowerCase().endsWith(".json"));
    setFiles(normalized);
    setFeedback(null);
    setProgress(0);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    onPickFiles(event.dataTransfer.files);
  }

  async function onUpload() {
    if (files.length === 0 || isUploading) {
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
          message: `Upload completed (scan_result_id: ${payload.data?.scan_result_id ?? "n/a"}, vulnerabilities: ${payload.data?.vulnerability_count ?? 0}).`,
        });
      }

      setProgress(100);
    } catch (error) {
      setFeedback({
        type: "error",
        message: error instanceof Error ? error.message : "Unexpected upload error",
      });
    } finally {
      setIsUploading(false);
    }
  }

  return (
    <AppShell
      activeRoute="/upload"
      title="Upload Trivy Scan"
      subtitle="Upload one or multiple Trivy JSON reports with progress tracking and API feedback."
    >
      <div className="upload-layout">
        <section className="card upload-card">
          <h2 className="card-title">Upload reports</h2>
          <p className="muted mt-0">Drag-and-drop JSON files or use file picker. One file uses /api/upload, multiple files use /api/upload/batch.</p>

          <div
            role="button"
            tabIndex={0}
            className={`upload-dropzone ${isDragging ? "upload-dropzone--active" : ""}`}
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
            <span className="muted">or click to choose file(s)</span>
            <input
              ref={inputRef}
              className="upload-hidden-input"
              type="file"
              accept="application/json,.json"
              multiple
              onChange={(event) => onPickFiles(event.target.files)}
            />
          </div>

          <div className="upload-actions">
            <button type="button" className="secondary-button" onClick={() => inputRef.current?.click()} disabled={isUploading}>
              Choose Files
            </button>
            <button type="button" className="primary-button" onClick={onUpload} disabled={files.length === 0 || isUploading}>
              {isUploading ? "Uploading..." : mode === "batch" ? "Upload Batch" : "Upload File"}
            </button>
            <button type="button" className="secondary-button" onClick={() => navigate("/dashboard")}>Back to Dashboard</button>
          </div>

          <div className="upload-meta muted">
            {fileSummary.count > 0
              ? `${fileSummary.count} file(s) selected • ${formatFileSize(fileSummary.totalBytes)} • mode: ${mode}`
              : "No file selected."}
          </div>

          {files.length > 0 && (
            <ul className="upload-file-list">
              {files.map((file) => (
                <li key={`${file.name}-${file.size}`}>{file.name} ({formatFileSize(file.size)})</li>
              ))}
            </ul>
          )}

          <div className="upload-progress-wrap" aria-live="polite">
            <div className="upload-progress-bar" style={{ width: `${progress}%` }} />
          </div>
          <p className="muted mt-0 mb-0">Progress: {progress}%</p>

          {feedback && <div className={`upload-feedback upload-feedback--${feedback.type}`}>{feedback.message}</div>}
        </section>

        <section className="card">
          <h2 className="card-title">Local sample data (dev only)</h2>
          <p className="muted mt-0">
            Need non-empty dashboard quickly? Seed local SQLite data for preview. This command is for local development only and does not affect API contract.
          </p>
          <code className="code-block">PATH="$HOME/.bun/bin:$PATH" bun run db:seed-dashboard</code>
        </section>
      </div>
    </AppShell>
  );
}

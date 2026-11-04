import type { HTMLAttributes } from "react";

/** Monospace, non-wrapping text for CVE/GHSA IDs, versions, tags, digests. */
export function Mono({ className = "", ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={`whitespace-nowrap font-mono text-[0.92em] ${className}`} {...props} />;
}

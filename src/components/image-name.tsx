import { maskAccount, parseImageRef, repoLabel } from "../lib/image-ref";

interface ImageNameProps {
  /** Full image or repository reference, e.g. 123456789012.dkr.ecr.eu-west-1.amazonaws.com/api:1.2 */
  imageRef: string;
  /** Show `:tag` after the repository name (uses `tag` when given, else the tag in the ref). */
  withTag?: boolean;
  tag?: string | null;
  /** Show a masked account (e.g. ••••9012); useful when several accounts share a region. */
  showAccount?: boolean;
  /** "row": two lines (name, registry badge). "inline": single line, name plus badge. */
  variant?: "row" | "inline";
  className?: string;
}

/** Plain-text repository name for places that need a string (aria labels, breadcrumbs). */
export function displayRepoName(ref: string): string {
  return repoLabel(ref);
}

/** Readable image/repository name: repo (+ tag) on line 1, registry badge + region on line 2. */
export function ImageName({ imageRef, withTag = false, tag, showAccount = false, variant = "row", className = "" }: ImageNameProps) {
  const parsed = parseImageRef(imageRef);
  const shownTag = withTag ? (tag ?? parsed.tag) : undefined;
  const name = parsed.repository || "-";

  const title = tag && withTag && !parsed.tag ? `${imageRef}:${tag}` : imageRef;
  const meta = (
    <span className={`flex min-w-0 items-center gap-1.5 text-xs text-muted ${variant === "row" ? "mt-0.5" : ""}`}>
      <span className="shrink-0 rounded bg-line px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide text-fg2">{parsed.registryLabel}</span>
      {(parsed.region || (showAccount && parsed.account)) && (
        <span className="min-w-0 truncate">
          {parsed.region}
          {showAccount && parsed.account && <span className="font-mono">{parsed.region ? " · " : ""}{maskAccount(parsed.account)}</span>}
        </span>
      )}
    </span>
  );

  const nameLine = (
    <span className="flex min-w-0 items-baseline">
      <span className="min-w-0 truncate font-semibold text-fg">{name}</span>
      {shownTag && <span className="max-w-[60%] shrink-0 truncate font-mono text-[0.92em] text-link">:{shownTag}</span>}
    </span>
  );

  if (variant === "inline") {
    return (
      <span className={`inline-flex min-w-0 max-w-full items-baseline gap-2 ${className}`} title={title}>
        {nameLine}
        <span className="hidden shrink-0 sm:inline-flex">{meta}</span>
      </span>
    );
  }

  return (
    <span className={`flex min-w-0 flex-col ${className}`} title={title}>
      {nameLine}
      {meta}
    </span>
  );
}

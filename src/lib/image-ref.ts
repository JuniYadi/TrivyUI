/** Parsed container image reference. `registry` is the host (with port) or "docker.io". */
export interface ImageRef {
  registry: string;
  registryLabel: string;
  region?: string;
  /** ECR account id, or GCP project for GCR / Artifact Registry. */
  account?: string;
  repository: string;
  tag?: string;
  digest?: string;
}

const ECR = /^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$/;
const ARTIFACT = /^([a-z0-9-]+)-docker\.pkg\.dev$/;
const GCR = /^(?:([a-z]+)\.)?gcr\.io$/;
const DOCKER_HUBS = new Set(["docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"]);

function looksLikeHost(segment: string): boolean {
  return segment.includes(".") || segment.includes(":") || segment === "localhost";
}

/** Split `host/path[:tag][@digest]` into its parts. Never throws. */
export function parseImageRef(ref: string): ImageRef {
  let rest = ref.trim();
  let digest: string | undefined;
  let tag: string | undefined;

  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1) || undefined;
    rest = rest.slice(0, at);
  }
  const lastSlash = rest.lastIndexOf("/");
  const colon = rest.indexOf(":", lastSlash + 1);
  if (colon >= 0) {
    tag = rest.slice(colon + 1) || undefined;
    rest = rest.slice(0, colon);
  }

  const parts = rest.split("/").filter(Boolean);
  const withTag = (value: Omit<ImageRef, "tag" | "digest">): ImageRef => ({
    ...value,
    ...(tag ? { tag } : {}),
    ...(digest ? { digest } : {}),
  });

  let host = "docker.io";
  if (parts.length > 1 && looksLikeHost(parts[0]!)) {
    host = parts.shift()!;
  }
  const lowerHost = host.toLowerCase();
  const path = parts.join("/");

  if (DOCKER_HUBS.has(lowerHost)) {
    const repository = parts.length > 1 && parts[0] === "library" ? parts.slice(1).join("/") : path;
    return withTag({ registry: "docker.io", registryLabel: "Docker Hub", repository });
  }

  const ecr = ECR.exec(lowerHost);
  if (ecr) {
    return withTag({ registry: host, registryLabel: "ECR", region: ecr[2], account: ecr[1], repository: path });
  }

  const artifact = ARTIFACT.exec(lowerHost);
  if (artifact && parts.length >= 2) {
    return withTag({
      registry: host,
      registryLabel: "Artifact Registry",
      region: artifact[1],
      account: parts[0],
      repository: parts.slice(1).join("/"),
    });
  }

  const gcr = GCR.exec(lowerHost);
  if (gcr && parts.length >= 2) {
    return withTag({
      registry: host,
      registryLabel: "GCR",
      ...(gcr[1] ? { region: gcr[1] } : {}),
      account: parts[0],
      repository: parts.slice(1).join("/"),
    });
  }

  if (lowerHost === "ghcr.io") {
    return withTag({ registry: host, registryLabel: "GHCR", repository: path });
  }

  return withTag({ registry: host, registryLabel: host, repository: path });
}

/** "••••9012" for a long id; short ids are returned as-is. */
export function maskAccount(account: string): string {
  return account.length > 4 ? `••••${account.slice(-4)}` : account;
}

/** Plain-text repository name (no registry host), for places that need a string. */
export function repoLabel(ref: string): string {
  return parseImageRef(ref).repository || "-";
}

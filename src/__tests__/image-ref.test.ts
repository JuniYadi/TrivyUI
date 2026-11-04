import { describe, expect, test } from "bun:test";
import { maskAccount, parseImageRef, repoLabel } from "../lib/image-ref";

const ECR_HOST = "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com";

describe("parseImageRef", () => {
  test("ECR with tag", () => {
    expect(parseImageRef(`${ECR_HOST}/payments-api:v1.2.3`)).toEqual({
      registry: ECR_HOST,
      registryLabel: "ECR",
      region: "ap-southeast-1",
      account: "123456789012",
      repository: "payments-api",
      tag: "v1.2.3",
    });
  });

  test("ECR with digest and nested repo", () => {
    const r = parseImageRef(`${ECR_HOST}/team/svc@sha256:abcdef`);
    expect(r.repository).toBe("team/svc");
    expect(r.digest).toBe("sha256:abcdef");
    expect(r.tag).toBeUndefined();
  });

  test("ECR with tag and digest", () => {
    const r = parseImageRef(`${ECR_HOST}/a:1@sha256:ff`);
    expect(r.tag).toBe("1");
    expect(r.digest).toBe("sha256:ff");
  });

  test("GHCR", () => {
    expect(parseImageRef("ghcr.io/JuniYadi/trivyui:latest")).toEqual({
      registry: "ghcr.io",
      registryLabel: "GHCR",
      repository: "JuniYadi/trivyui",
      tag: "latest",
    });
  });

  test("Docker Hub long, short and user forms", () => {
    expect(parseImageRef("docker.io/library/nginx")).toEqual({ registry: "docker.io", registryLabel: "Docker Hub", repository: "nginx" });
    expect(parseImageRef("nginx:1.25")).toEqual({ registry: "docker.io", registryLabel: "Docker Hub", repository: "nginx", tag: "1.25" });
    expect(parseImageRef("user/app").repository).toBe("user/app");
    expect(parseImageRef("docker.io/user/app").repository).toBe("user/app");
    expect(parseImageRef("index.docker.io/library/redis:7").repository).toBe("redis");
  });

  test("Artifact Registry", () => {
    expect(parseImageRef("europe-west1-docker.pkg.dev/my-proj/apps/web/api:2")).toEqual({
      registry: "europe-west1-docker.pkg.dev",
      registryLabel: "Artifact Registry",
      region: "europe-west1",
      account: "my-proj",
      repository: "apps/web/api",
      tag: "2",
    });
  });

  test("Artifact Registry host without a path falls back to generic", () => {
    expect(parseImageRef("us-docker.pkg.dev/only").registryLabel).toBe("us-docker.pkg.dev");
  });

  test("GCR global and regional", () => {
    expect(parseImageRef("gcr.io/proj/img:1")).toEqual({
      registry: "gcr.io",
      registryLabel: "GCR",
      account: "proj",
      repository: "img",
      tag: "1",
    });
    const eu = parseImageRef("eu.gcr.io/proj/a/b");
    expect(eu.region).toBe("eu");
    expect(eu.repository).toBe("a/b");
  });

  test("GCR host with single segment is generic", () => {
    expect(parseImageRef("gcr.io/img").registryLabel).toBe("gcr.io");
  });

  test("host:port and localhost", () => {
    expect(parseImageRef("registry.local:5000/app:1")).toEqual({
      registry: "registry.local:5000",
      registryLabel: "registry.local:5000",
      repository: "app",
      tag: "1",
    });
    expect(parseImageRef("localhost/app").registryLabel).toBe("localhost");
    expect(parseImageRef("localhost:5000/a/b/c").repository).toBe("a/b/c");
  });

  test("generic host and nested paths", () => {
    const r = parseImageRef("quay.io/org/team/app:3");
    expect(r.registryLabel).toBe("quay.io");
    expect(r.repository).toBe("org/team/app");
  });

  test("empty tag/digest and blank input", () => {
    expect(parseImageRef("nginx:").tag).toBeUndefined();
    expect(parseImageRef("nginx@").digest).toBeUndefined();
    expect(parseImageRef("  ").repository).toBe("");
  });
});

describe("helpers", () => {
  test("maskAccount", () => {
    expect(maskAccount("123456789012")).toBe("••••9012");
    expect(maskAccount("abc")).toBe("abc");
  });

  test("repoLabel", () => {
    expect(repoLabel(`${ECR_HOST}/payments-api`)).toBe("payments-api");
    expect(repoLabel("")).toBe("-");
  });
});

import { describe, expect, test } from "bun:test";
import { detectSchemaVersion, parseTrivyResult } from "../services/trivy-parser";

describe("trivy parser", () => {
  test("parses Trivy JSON Results -> Packages -> Vulnerabilities into normalized records", () => {
    const payload = {
      SchemaVersion: 2,
      ArtifactName: "ghcr.io/acme/trivyui:1.0.0",
      Metadata: {
        TrivyVersion: "0.58.1",
      },
      Results: [
        {
          Target: "ghcr.io/acme/trivyui:1.0.0",
          Packages: [
            {
              Name: "openssl",
              Version: "3.0.0",
              Vulnerabilities: [
                {
                  VulnerabilityID: "CVE-2026-0001",
                  Severity: "HIGH",
                  PkgName: "openssl",
                  InstalledVersion: "3.0.0",
                  FixedVersion: "3.0.1",
                  Title: "OpenSSL issue",
                  Description: "Example vulnerability",
                  CVSS: {
                    nvd: {
                      V3Score: 7.8,
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const result = parseTrivyResult(payload);

    expect(result.repo_name).toBe("ghcr.io/acme/trivyui");
    expect(result.image_name).toBe("ghcr.io/acme/trivyui:1.0.0");
    expect(result.schema_version).toBe("2");
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0]).toMatchObject({
      cve_id: "CVE-2026-0001",
      severity: "HIGH",
      package_name: "openssl",
      installed_version: "3.0.0",
      fixed_version: "3.0.1",
      score: 7.8,
    });
  });

  test("falls back safely for small field variations and unknown severity", () => {
    const payload = {
      artifactName: "docker.io/library/nginx:latest",
      results: [
        {
          vulnerabilities: [
            {
              VulnerabilityID: "CVE-2026-0002",
              Severity: "MODERATE",
              PkgName: "busybox",
              InstalledVersion: "1.36.0",
            },
          ],
        },
      ],
    };

    const result = parseTrivyResult(payload);

    expect(detectSchemaVersion(payload)).toBe("unknown");
    expect(result.repo_name).toBe("docker.io/library/nginx");
    expect(result.vulnerabilities[0].severity).toBe("UNKNOWN");
  });
});

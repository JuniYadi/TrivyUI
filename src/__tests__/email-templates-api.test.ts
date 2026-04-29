import { describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createEmailTemplatesHandler } from "../routes/api/email-templates";

describe("email templates api", () => {
  test("GET list returns seeded repo_vuln_alert template", async () => {
    const db = initDb(":memory:");
    const handler = createEmailTemplatesHandler(db);

    const response = await handler(new Request("http://localhost/api/email-templates", { method: "GET" }));
    const body = (await response.json()) as {
      success: boolean;
      data: Array<{ template_key: string; subject: string; html_body: string }>;
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);
    expect(body.data.some((row) => row.template_key === "repo_vuln_alert")).toBe(true);

    db.close();
  });

  test("PUT updates template and GET detail returns persisted values", async () => {
    const db = initDb(":memory:");
    const handler = createEmailTemplatesHandler(db);

    const updateResponse = await handler(
      new Request("http://localhost/api/email-templates/repo_vuln_alert", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subject: "[TrivyUI] New subject",
          html_body: "<div>Hello {{repository}}</div>",
          text_body: "Hello {{repository}}",
          enabled: true,
        }),
      })
    );

    expect(updateResponse.status).toBe(200);

    const detailResponse = await handler(new Request("http://localhost/api/email-templates/repo_vuln_alert", { method: "GET" }));
    const detailBody = (await detailResponse.json()) as {
      success: boolean;
      data: { subject: string; html_body: string; text_body: string | null; enabled: boolean };
    };

    expect(detailResponse.status).toBe(200);
    expect(detailBody.success).toBe(true);
    expect(detailBody.data.subject).toBe("[TrivyUI] New subject");
    expect(detailBody.data.html_body).toContain("{{repository}}");
    expect(detailBody.data.text_body).toContain("{{repository}}");
    expect(detailBody.data.enabled).toBe(true);

    db.close();
  });

  test("PUT rejects empty subject", async () => {
    const db = initDb(":memory:");
    const handler = createEmailTemplatesHandler(db);

    const response = await handler(
      new Request("http://localhost/api/email-templates/repo_vuln_alert", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subject: "   ",
          html_body: "<div>ok</div>",
          enabled: true,
        }),
      })
    );

    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_REQUEST");

    db.close();
  });

  test("GET unknown template key returns 404", async () => {
    const db = initDb(":memory:");
    const handler = createEmailTemplatesHandler(db);

    const response = await handler(new Request("http://localhost/api/email-templates/unknown", { method: "GET" }));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(404);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("NOT_FOUND");

    db.close();
  });
});

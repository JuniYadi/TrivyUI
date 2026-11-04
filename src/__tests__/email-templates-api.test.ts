import { describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createEmailTemplatesHandler } from "../routes/api/email-templates";
import { updateEmailTemplate } from "../services/email-templates";

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

describe("email templates api validation", () => {
  const put = (handler: ReturnType<typeof createEmailTemplatesHandler>, payload: unknown, path = "/api/email-templates/repo_vuln_alert") =>
    handler(new Request(`http://localhost${path}`, { method: "PUT", body: JSON.stringify(payload) }));
  const valid = { subject: "s", html_body: "<p>h</p>", enabled: true };

  test("rejects PUT without template key", async () => {
    const db = initDb(":memory:");
    const response = await put(createEmailTemplatesHandler(db), valid, "/api/email-templates");
    expect(response.status).toBe(405);
    db.close();
  });

  test.each([
    ["subject", { ...valid, subject: 1 }],
    ["html_body", { ...valid, html_body: null }],
    ["text_body", { ...valid, text_body: 5 }],
    ["enabled", { ...valid, enabled: "yes" }],
  ])("rejects invalid %s", async (field, payload) => {
    const db = initDb(":memory:");
    const response = await put(createEmailTemplatesHandler(db), payload);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(response.status).toBe(400);
    expect(body.error.message).toContain(field);
    db.close();
  });

  test("rejects unsupported methods", async () => {
    const db = initDb(":memory:");
    const response = await createEmailTemplatesHandler(db)(new Request("http://localhost/api/email-templates", { method: "DELETE" }));
    expect(response.status).toBe(405);
    db.close();
  });
});

describe("email templates service validation", () => {
  const base = { subject: "s", html_body: "<p>h</p>", enabled: true };
  test.each([
    ["blank subject", { ...base, subject: "  " }, "'subject' is required"],
    ["blank html_body", { ...base, html_body: "" }, "'html_body' is required"],
    ["long subject", { ...base, subject: "x".repeat(256) }, "<= 255"],
    ["huge html_body", { ...base, html_body: "x".repeat(100001) }, "too large"],
    ["huge text_body", { ...base, text_body: "x".repeat(100001) }, "'text_body' is too large"],
  ])("rejects %s", (_name, input, message) => {
    const db = initDb(":memory:");
    expect(() => updateEmailTemplate(db, "repo_vuln_alert", input)).toThrow(message);
    db.close();
  });

  test("throws not found for unknown template key", () => {
    const db = initDb(":memory:");
    expect(() => updateEmailTemplate(db, "missing", base)).toThrow("not found");
    db.close();
  });
});

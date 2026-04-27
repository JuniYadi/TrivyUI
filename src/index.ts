import appHtml from "./index.html";
import { getHealthMessage, initDb } from "./db";
import { sendError } from "./routes/api/_shared";
import { createBatchUploadHandler } from "./routes/api/upload-batch";
import { createUploadHandler } from "./routes/api/upload";
import { createWebhookHandler } from "./routes/api/webhook";
import { createStatsHandler } from "./routes/api/stats";
import { createVulnerabilitiesHandler } from "./routes/api/vulnerabilities";
import { createRepositoriesHandler } from "./routes/api/repositories";
import { createImagesHandler } from "./routes/api/images";

const db = initDb();
const uploadHandler = createUploadHandler(db);
const batchUploadHandler = createBatchUploadHandler(db);
const webhookHandler = createWebhookHandler(db);
const statsHandler = createStatsHandler(db);
const vulnerabilitiesHandler = createVulnerabilitiesHandler(db);
const repositoriesHandler = createRepositoriesHandler(db);
const imagesHandler = createImagesHandler(db);

function methodNotAllowed(method: string, endpoint: string): Response {
  return sendError(405, "METHOD_NOT_ALLOWED", `Method ${method} is not allowed for ${endpoint}`);
}

async function serveAsset(pathname: string): Promise<Response> {
  const assetFile = Bun.file(new URL(`.${pathname}`, import.meta.url));

  if (!(await assetFile.exists())) {
    return sendError(404, "NOT_FOUND", "Asset not found");
  }

  return new Response(assetFile);
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  development: true,
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === "/api/health") {
      if (request.method !== "GET") {
        return methodNotAllowed(request.method, pathname);
      }

      return Response.json({
        status: "ok",
        database: getHealthMessage(db),
      });
    }

    if (pathname === "/api/upload") {
      if (request.method !== "POST") {
        return methodNotAllowed(request.method, pathname);
      }

      return uploadHandler(request);
    }

    if (pathname === "/api/upload/batch") {
      if (request.method !== "POST") {
        return methodNotAllowed(request.method, pathname);
      }

      return batchUploadHandler(request);
    }

    if (pathname === "/api/webhook") {
      if (request.method !== "POST") {
        return methodNotAllowed(request.method, pathname);
      }

      return webhookHandler(request);
    }

    if (pathname === "/api/stats") {
      if (request.method !== "GET") {
        return methodNotAllowed(request.method, pathname);
      }

      return statsHandler();
    }

    if (pathname === "/api/vulnerabilities" || pathname.startsWith("/api/vulnerabilities/")) {
      if (request.method !== "GET") {
        return methodNotAllowed(request.method, "/api/vulnerabilities");
      }

      return vulnerabilitiesHandler(request);
    }

    if (pathname === "/api/repositories" || pathname.startsWith("/api/repositories/")) {
      if (request.method !== "GET") {
        return methodNotAllowed(request.method, "/api/repositories");
      }

      return repositoriesHandler(request);
    }

    if (pathname === "/api/images" || pathname.startsWith("/api/images/")) {
      if (request.method !== "GET") {
        return methodNotAllowed(request.method, "/api/images");
      }

      return imagesHandler(request);
    }

    if (pathname.startsWith("/api/")) {
      return sendError(404, "NOT_FOUND", "Endpoint not found");
    }

    if (pathname === "/main.js" || pathname === "/main.css") {
      return await serveAsset(pathname);
    }

    return new Response(appHtml, {
      headers: {
        "content-type": "text/html; charset=utf-8",
      },
    });
  },
});

console.log(`TrivyUI running on http://localhost:${server.port}`);

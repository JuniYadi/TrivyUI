import appHtml from "./index.html";
import { getHealthMessage, initDb } from "./db";
import { createBatchUploadHandler } from "./routes/api/upload-batch";
import { createUploadHandler } from "./routes/api/upload";
import { createWebhookHandler } from "./routes/api/webhook";
import { createStatsHandler } from "./routes/api/stats";
import { createVulnerabilitiesHandler } from "./routes/api/vulnerabilities";

const db = initDb();
const vulnerabilitiesHandler = createVulnerabilitiesHandler(db);

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  development: true,
  routes: {
    "/api/health": () =>
      Response.json({
        status: "ok",
        database: getHealthMessage(db),
      }),
    "/api/upload": createUploadHandler(db),
    "/api/upload/batch": createBatchUploadHandler(db),
    "/api/webhook": createWebhookHandler(db),
    "/api/stats": createStatsHandler(db),
    "/api/vulnerabilities": vulnerabilitiesHandler,
    "/api/vulnerabilities/*": vulnerabilitiesHandler,
    "/*": appHtml,
  },
});

console.log(`TrivyUI running on http://localhost:${server.port}`);

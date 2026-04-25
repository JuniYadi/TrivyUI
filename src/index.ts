import appHtml from "./index.html";
import { getHealthMessage, initDb } from "./db";

const db = initDb();

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  development: true,
  routes: {
    "/api/health": () =>
      Response.json({
        status: "ok",
        database: getHealthMessage(db),
      }),
    "/*": appHtml,
  },
});

console.log(`TrivyUI running on http://localhost:${server.port}`);

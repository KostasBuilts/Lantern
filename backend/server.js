// Lantern backend: collector (/ingest), read APIs, SSE, AI gateway, dashboard.
import express from "express";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadConfig, watchConfig } from "./config.js";
import { initDb, prepare } from "./db.js";
import { seedDemo } from "./demo.js";
import { llmEnabled, assess } from "./risk.js";
import { ingest } from "./ingest.js";
import { api } from "./routes.js";
import { gateway, warmUpstream } from "./gateway.js";

const here = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

loadConfig();
initDb();
prepare();
await seedDemo();
// Load the model now (and retry while it is still downloading) so the first real prompt is fast.
const warmUp = () => assess("warm-up").then((r) => (r ? console.log("[llm] model ready") : setTimeout(warmUp, 30_000)));
if (llmEnabled()) warmUp();
warmUpstream();
watchConfig(() => {});

const app = express();
app.disable("x-powered-by");

// body parsers: NDJSON text for /ingest, JSON elsewhere
app.use("/ingest", express.text({ type: "*/*", limit: "8mb" }), (req, _res, next) => {
  // allow a JSON array/object too
  if (typeof req.body === "string" && req.body.trim().startsWith("[")) {
    try { req.body = JSON.parse(req.body); } catch {}
  }
  next();
}, ingest);

app.use(express.json({ limit: "4mb" }));
app.use("/api", api);
app.use("/gateway", gateway);
app.get("/health", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// dashboard (static)
app.use("/", express.static(join(here, "..", "public"), { extensions: ["html"] }));

app.use((err, _req, res, _next) => {
  console.error("[error]", err.message);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`Lantern backend on http://localhost:${PORT}`);
  console.log(`  dashboard   http://localhost:${PORT}/`);
  console.log(`  ingest      POST http://localhost:${PORT}/ingest   (NDJSON)`);
  console.log(`  gateway     http://localhost:${PORT}/gateway.html  (API: /gateway/v1/chat/completions)`);
  console.log(`  risk LLM    ${llmEnabled() ? `${process.env.LLM_MODEL || "qwen2.5:3b"} at ${process.env.LLM_BASE_URL}` : "off (rules only); set LLM_BASE_URL"}`);
});

// AI gateway (the "safe path"): an OpenAI-compatible endpoint that redacts
// sensitive data from prompts before forwarding, and logs metadata only.
// If no upstream is configured it returns a canned reply so the redaction
// path is demonstrable standalone.
import { Router } from "express";
import { redact, scan, summarise } from "./detectors.js";
import { processEvent } from "./engine.js";

export const gateway = Router();
const UPSTREAM = process.env.LANTERN_UPSTREAM || null;   // e.g. http://localhost:11434/v1/chat/completions

gateway.post("/v1/chat/completions", async (req, res) => {
  const body = req.body || {};
  const user = req.get("x-lantern-user") || body.user || "unknown";
  const host = req.get("x-lantern-host") || "gateway";
  const messages = Array.isArray(body.messages) ? body.messages : [];

  // redact every message; collect hit types (never raw values)
  let allHits = [];
  for (const m of messages) {
    if (typeof m.content === "string") {
      allHits = allHits.concat(scan(m.content));
      m.content = redact(m.content).text;
    }
  }
  const hits = summarise(allHits);

  // record a prompt event -> engine classifies/alerts
  processEvent({
    ts: new Date().toISOString(), src: "gateway", host, user, kind: "prompt",
    app: "gateway", detail: { model: body.model || "unknown", hits, tokens_in: approxTokens(messages) },
  });

  // forward (redacted) or return a canned response
  if (UPSTREAM) {
    try {
      const r = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...body, messages }) });
      res.status(r.status);
      r.body.pipe ? r.body.pipe(res) : res.send(await r.text());
      return;
    } catch (e) {
      return res.status(502).json({ error: "upstream_unreachable", detail: String(e) });
    }
  }
  res.json({
    id: "lantern-" + Date.now(), object: "chat.completion", model: body.model || "approved-model",
    lantern: { redacted_hits: hits, note: "No upstream configured; prompt was redacted and logged." },
    choices: [{ index: 0, finish_reason: "stop",
      message: { role: "assistant",
        content: hits.length
          ? `Your prompt reached the approved model with ${hits.map(h => h.count + "×" + h.type).join(", ")} redacted.`
          : "Your prompt reached the approved model. No sensitive data was found." } }],
  });
});

function approxTokens(messages) {
  return Math.ceil(messages.reduce((n, m) => n + (typeof m.content === "string" ? m.content.length : 0), 0) / 4);
}

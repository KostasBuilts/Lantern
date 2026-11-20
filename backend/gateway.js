// AI gateway (the "safe path"): an OpenAI-compatible endpoint that scores each
// prompt (rules + local LLM), then enforces the policy: allow, warn, redact or block.
// Only metadata and the redacted prompt are stored. With no upstream configured it
// returns a canned reply, so the whole path can be demonstrated standalone.
import { Router } from "express";
import { decidePrompt, verdictOf } from "./risk.js";
import { processEvent } from "./engine.js";
import { redact } from "./detectors.js";

export const gateway = Router();
const UPSTREAM = process.env.LANTERN_UPSTREAM || null;       // e.g. https://api.openai.com/v1/chat/completions
const UPSTREAM_KEY = process.env.LANTERN_UPSTREAM_KEY || "";

const NOTICE = {
  allow: "Your prompt was sent to the model.",
  warn: "Your prompt was sent, but it was flagged. Please use an approved model and avoid company or client data.",
  redact: "Sensitive values were removed from your prompt before it was sent.",
  block: "Your prompt was blocked and did not leave the company.",
};

gateway.post("/v1/chat/completions", async (req, res) => {
  const body = req.body || {};
  const user = req.get("x-lantern-user") || body.user || "unknown";
  const host = req.get("x-lantern-host") || "gateway";
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const model = String(body.model || "unknown");
  const text = messages.map((m) => (typeof m.content === "string" ? m.content : "")).join("\n");

  const d = await decidePrompt(text, model);
  const verdict = { ...verdictOf(d), redacted_hits: d.hits, notice: NOTICE[d.action] };

  processEvent({ ts: new Date().toISOString(), src: "gateway", host, user, kind: "prompt", app: model,
    detail: { model, hits: d.hits, decision: verdict, preview: d.redacted.slice(0, 200), tokens_in: Math.ceil(text.length / 4) } });

  if (d.action === "block")
    return res.status(403).json({ error: { type: "lantern_blocked", message: `${NOTICE.block} ${d.explanation}` }, lantern: verdict });
  if (d.action === "redact")
    for (const m of messages) if (typeof m.content === "string") m.content = redact(m.content).text;
  verdict.sent_prompt = messages.map((m) => (typeof m.content === "string" ? m.content : "")).join("\n");

  if (UPSTREAM) {
    try {
      const r = await fetch(UPSTREAM, { method: "POST",
        headers: { "content-type": "application/json", ...(UPSTREAM_KEY ? { authorization: `Bearer ${UPSTREAM_KEY}` } : {}) },
        body: JSON.stringify({ ...body, messages, stream: false }) });
      // shortcut: replies are buffered (stream:false); pipe r.body if token streaming to the client matters.
      const reply = await r.json().catch(() => ({}));
      return res.status(r.status).json({ ...reply, lantern: verdict });
    } catch (e) {
      return res.status(502).json({ error: { type: "upstream_unreachable", message: String(e) }, lantern: verdict });
    }
  }
  res.json({
    id: "lantern-" + Date.now(), object: "chat.completion", model,
    choices: [{ index: 0, finish_reason: "stop",
      message: { role: "assistant", content: `${NOTICE[d.action]} (No upstream model is configured, so this is a placeholder reply.)` } }],
    lantern: verdict,
  });
});

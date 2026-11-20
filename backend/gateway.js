// AI gateway (the "safe path"): an OpenAI-compatible endpoint that scores each
// prompt (rules + local LLM), then enforces the policy: allow, warn, redact or block.
// Only metadata and the redacted prompt are stored. With no upstream configured it
// returns a canned reply, so the whole path can be demonstrated standalone.
import { Router } from "express";
import { decidePrompt, verdictOf } from "./risk.js";
import { processEvent } from "./engine.js";
import { redact } from "./detectors.js";
import { config } from "./config.js";

export const gateway = Router();
const UPSTREAM = process.env.LANTERN_UPSTREAM || null;       // e.g. https://api.openai.com/v1/chat/completions
const UPSTREAM_KEY = process.env.LANTERN_UPSTREAM_KEY || "";
const UPSTREAM_MODEL = process.env.LANTERN_UPSTREAM_MODEL || ""; // answer every request with this model (e.g. local Ollama)
const UPSTREAM_TIMEOUT = +process.env.LANTERN_UPSTREAM_TIMEOUT_MS || 180_000;
// The model that answers chats (shown on the gateway page). "placeholder" = canned replies, no upstream.
export const chatStatus = { model: UPSTREAM_MODEL || (UPSTREAM ? "as requested" : "placeholder"), state: UPSTREAM ? "starting" : "off" };

const NOTICE = {
  allow: "Your prompt was sent to the model.",
  warn: "Your prompt was sent, but it was flagged. Please use an approved model and avoid company or client data.",
  redact: "Sensitive values were removed from your prompt before it was sent.",
  block: "Your prompt was blocked and did not leave the company.",
};

// OpenAI message content is a string or an array of parts ({type:"text", text}, images, files...).
const isTextPart = (p) => p?.type === "text" && typeof p.text === "string";
const textOf = (m) => typeof m?.content === "string" ? m.content
  : Array.isArray(m?.content) ? m.content.filter(isTextPart).map((p) => p.text).join("\n") : "";
const hasUninspectable = (msgs) => msgs.some((m) => Array.isArray(m?.content) && m.content.some((p) => !isTextPart(p)));
function redactMessage(m) {
  if (typeof m.content === "string") m.content = redact(m.content).text;
  else if (Array.isArray(m.content)) for (const p of m.content) if (isTextPart(p)) p.text = redact(p.text).text;
}

function parse(req) {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const messages = Array.isArray(body.messages) ? body.messages : [];
  return { body, messages, model: String(body.model || "unknown"), text: messages.map(textOf).join("\n") };
}

// Draft check: rules only (fast), nothing stored, nothing forwarded. The chat page calls it while the user types.
gateway.post("/v1/check", async (req, res) => {
  const { model, text } = parse(req);
  const d = await decidePrompt(text, model, { rulesOnly: true });
  res.json({ ...verdictOf(d), hits: d.hits, redacted: d.redacted });
});

// Lets OpenAI-compatible tools (SDKs, chat UIs) list what they may use.
gateway.get("/v1/models", (_req, res) => res.json({ object: "list",
  data: (config.policy.approved_models || []).map((id) => ({ id, object: "model", owned_by: "lantern-approved" })) }));

gateway.post("/v1/chat/completions", async (req, res) => {
  const { body, messages, model, text } = parse(req);
  const user = req.get("x-lantern-user") || body.user || "unknown";
  const host = req.get("x-lantern-host") || "gateway";

  // Earlier turns were checked when they were sent: the LLM judges only the newest user message.
  const lastUser = messages.findLast((m) => m?.role === "user");
  const d = await decidePrompt(text, model, { llmText: lastUser ? textOf(lastUser) : undefined });
  if (hasUninspectable(messages)) Object.assign(d, { action: "block", risk: 100,
    explanation: "Images and files can't be inspected, so they are blocked. Paste the text instead." });
  const verdict = { ...verdictOf(d), redacted_hits: d.hits, notice: NOTICE[d.action] };

  processEvent({ ts: new Date().toISOString(), src: "gateway", host, user, kind: "prompt", app: model,
    detail: { model, hits: d.hits, decision: verdict, preview: (lastUser ? redact(textOf(lastUser)).text : d.redacted).slice(0, 200), tokens_in: Math.ceil(text.length / 4) } });

  if (d.action === "block")
    return res.status(403).json({ error: { type: "lantern_blocked", message: `${NOTICE.block} ${d.explanation}` }, lantern: verdict });
  if (d.action === "redact") for (const m of messages) redactMessage(m);
  verdict.sent_prompt = textOf(messages.at(-1));      // the newest message, as forwarded (redacted if needed)

  if (!UPSTREAM) {
    const content = `${NOTICE[d.action]} (No upstream model is configured, so this is a placeholder reply.)`;
    if (body.stream) {
      sseStart(res, model, verdict);
      res.write(`data: ${JSON.stringify({ object: "chat.completion.chunk", model,
        choices: [{ index: 0, delta: { role: "assistant", content }, finish_reason: "stop" }] })}\n\n`);
      return res.end("data: [DONE]\n\n");
    }
    return res.json({ id: "lantern-" + Date.now(), object: "chat.completion", model, lantern: verdict,
      choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content } }] });
  }

  const abort = new AbortController();
  res.on("close", () => abort.abort());            // client left: stop the upstream (frees the shared local model)
  try {
    const r = await fetch(UPSTREAM, { method: "POST", signal: AbortSignal.any([abort.signal, AbortSignal.timeout(UPSTREAM_TIMEOUT)]),
      headers: { "content-type": "application/json", ...(UPSTREAM_KEY ? { authorization: `Bearer ${UPSTREAM_KEY}` } : {}) },
      body: JSON.stringify({ ...body, messages, ...(UPSTREAM_MODEL ? { model: UPSTREAM_MODEL } : {}) }) });
    chatStatus.state = r.ok ? "ready" : "unreachable";
    if (body.stream && r.ok && r.body) {             // pass the token stream through, verdict first
      sseStart(res, model, verdict);
      for await (const chunk of r.body) res.write(chunk);
      return res.end();
    }
    const reply = await r.json().catch(() => ({ error: { type: "upstream_bad_reply", message: `Upstream answered ${r.status}` } }));
    res.status(r.status).json({ ...reply, lantern: verdict });
  } catch (e) {
    if (res.headersSent) return res.end();
    if (e.name !== "AbortError") chatStatus.state = "unreachable";
    res.status(502).json({ error: { type: "upstream_unreachable", message: String(e.message || e) }, lantern: verdict });
  }
});

// Streaming replies open with one extra chunk (no choices) that carries the Lantern verdict.
function sseStart(res, model, verdict) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "x-accel-buffering": "no" });
  res.write(`data: ${JSON.stringify({ object: "chat.completion.chunk", model, choices: [], lantern: verdict })}\n\n`);
}

// Load the local chat model at startup (retrying while it downloads), so the first chat isn't slow.
// Only with LANTERN_UPSTREAM_MODEL set (the local default): never pings a paid upstream.
export async function warmUpstream() {
  if (!UPSTREAM || !UPSTREAM_MODEL) return;
  const ok = await fetch(UPSTREAM, { method: "POST", signal: AbortSignal.timeout(UPSTREAM_TIMEOUT),
    headers: { "content-type": "application/json", ...(UPSTREAM_KEY ? { authorization: `Bearer ${UPSTREAM_KEY}` } : {}) },
    body: JSON.stringify({ model: UPSTREAM_MODEL, max_tokens: 1, messages: [{ role: "user", content: "hi" }] }) })
    .then((r) => r.ok).catch(() => false);
  chatStatus.state = ok ? "ready" : "unreachable";
  if (ok) console.log("[gateway] chat model ready"); else setTimeout(warmUpstream, 30_000);
}

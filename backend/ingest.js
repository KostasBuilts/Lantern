// POST /ingest : newline-delimited JSON, one event per line (Doc 0 schema).
// Malformed lines are skipped and counted, never 500 the whole batch.
import { Router } from "express";
import { processEvent } from "./engine.js";

export const ingest = Router();

const REQUIRED = ["ts", "src", "host", "user", "kind"];

function validate(ev) {
  if (!ev || typeof ev !== "object") return "event must be a JSON object";
  for (const f of REQUIRED) if (!ev[f]) return `missing ${f}`;
  if (typeof ev.ts !== "string" || isNaN(Date.parse(ev.ts))) return "ts must be an ISO 8601 string";
  ev.ts = new Date(ev.ts).toISOString();   // time queries compare ts as strings: one format only
  return null;
}

// net_sensor -j emits its own shape. Translate the events the engine uses;
// hello/burst/flow_end/stats are sensor diagnostics and are dropped (null).
// The network can't see users, so the client IP stands in for host and user.
export function fromSensor(s) {
  const ip = s.event === "dns" ? s.client : String(s.client || "").replace(/^\[?(.*?)\]?:\d+$/, "$1");
  const cat = s.category && s.category !== "unclassified" ? s.category : undefined;
  const base = { ts: s.ts, src: "net", host: ip, user: ip };
  const d = { sni: s.name, dst: s.server, matched_category: cat, ja4: s.ja4 };
  if (s.event === "dns") return { ...base, kind: "dns", detail: { qname: s.qname, matched_category: cat } };
  if (s.event === "conn") return { ...base, kind: "tls", detail: d };
  if (s.event === "alert" && s.kind === "ai_stream")
    return { ...base, kind: "flow", score: s.score, detail: { ...d, stream_score: s.score } };
  if (s.event === "alert" && s.kind === "ai_upload")
    return { ...base, kind: "tls", detail: { ...d, up_bytes: s.up_bytes } };
  return null;
}

ingest.post("/", (req, res) => {
  // accept NDJSON (text) or a JSON array / single object
  let lines = [];
  if (typeof req.body === "string") lines = req.body.split("\n");
  else if (Array.isArray(req.body)) lines = req.body;
  else if (req.body && typeof req.body === "object") lines = [req.body];

  let accepted = 0, skipped = 0, ignored = 0;
  const errors = [];
  for (const line of lines) {
    let ev = line;
    if (typeof line === "string") {
      const s = line.trim();
      if (!s) continue;
      try { ev = JSON.parse(s); } catch { skipped++; if (errors.length < 10) errors.push("bad json"); continue; }
    }
    if (ev && ev.event) {
      ev = fromSensor(ev);
      if (!ev) { ignored++; continue; }
    }
    const err = validate(ev);
    if (err) { skipped++; if (errors.length < 10) errors.push(err); continue; }
    try { processEvent(ev); accepted++; }
    catch (e) { skipped++; if (errors.length < 10) errors.push(String(e.message || e)); }
  }
  res.status(202).json({ accepted, skipped, ignored, errors });
});

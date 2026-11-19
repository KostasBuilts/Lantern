// POST /ingest : newline-delimited JSON, one event per line (Doc 0 schema).
// Malformed lines are skipped and counted, never 500 the whole batch.
import { Router } from "express";
import { processEvent } from "./engine.js";

export const ingest = Router();

const REQUIRED = ["ts", "src", "host", "user", "kind"];

function validate(ev) {
  for (const f of REQUIRED) if (!ev[f]) return `missing ${f}`;
  if (typeof ev.ts !== "string") return "ts must be a string";
  return null;
}

ingest.post("/", (req, res) => {
  // accept NDJSON (text) or a JSON array / single object
  let lines = [];
  if (typeof req.body === "string") lines = req.body.split("\n");
  else if (Array.isArray(req.body)) lines = req.body;
  else if (req.body && typeof req.body === "object") lines = [req.body];

  let accepted = 0, skipped = 0;
  const errors = [];
  for (const line of lines) {
    let ev = line;
    if (typeof line === "string") {
      const s = line.trim();
      if (!s) continue;
      try { ev = JSON.parse(s); } catch { skipped++; errors.push("bad json"); continue; }
    }
    const err = validate(ev);
    if (err) { skipped++; if (errors.length < 10) errors.push(err); continue; }
    try { processEvent(ev); accepted++; }
    catch (e) { skipped++; if (errors.length < 10) errors.push(String(e.message || e)); }
  }
  res.status(202).json({ accepted, skipped, errors: errors.slice(0, 10) });
});

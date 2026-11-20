// Read APIs for the dashboard, the agent policy endpoint, and the SSE stream.
import { Router } from "express";
import { db } from "./db.js";
import { config } from "./config.js";
import { userRisk, riskScore } from "./engine.js";
import { toolRisk } from "./risk.js";
import { addClient, clientCount } from "./bus.js";

export const api = Router();

function parseDetail(row) { try { row.detail = JSON.parse(row.detail); } catch {} return row; }

// --- headline stats for the hero + stat tiles ---
api.get("/stats", (_req, res) => {
  const since24 = new Date(Date.now() - 24 * 3600_000).toISOString();
  const q = (sql, ...a) => db.prepare(sql).get(...a);
  const openAlerts = q(`SELECT COUNT(*) c FROM alerts WHERE ack=0`).c;
  const eventsToday = q(`SELECT COUNT(*) c FROM events WHERE ts>=?`, since24).c;
  const shadowApps = q(`SELECT COUNT(*) c FROM apps WHERE sanctioned=0`).c;
    const blockedEgress = q(`SELECT COUNT(*) c FROM events WHERE action='block' AND ts>=?`, since24).c;
  const highStream = q(`SELECT COUNT(*) c FROM events WHERE cls='high_stream' AND ts>=?`, since24).c;
  const perUser = db.prepare(`SELECT SUM(weight) t FROM events WHERE ts>=? GROUP BY user`).all(since24);
  const atRiskThreshold = config.policy.risk_at_risk ?? 50;
  const usersAtRisk = perUser.filter((u) => riskScore(u.t) >= atRiskThreshold).length;
  res.json({ openAlerts, eventsToday, shadowApps, blockedEgress, highStream, usersAtRisk,
    clients: clientCount(), policyVersion: config.policy.version });
});

// --- events over time, bucketed, split by severity (for the area/line chart) ---
api.get("/timeseries", (req, res) => {
  const hours = Math.min(+req.query.hours || 24, 24 * 14);
  const buckets = Math.min(+req.query.buckets || 48, 200);
  const now = Date.now(), span = hours * 3600_000, width = span / buckets;
  const since = new Date(now - span).toISOString();
  const rows = db.prepare(`SELECT ts, cls FROM events WHERE ts>=?`).all(since);
  const series = { shadow_domain: [], high_stream: [], injection: [], sensitive: [] };
  const counts = Array.from({ length: buckets }, () => ({ shadow_domain: 0, high_stream: 0, injection: 0, sensitive: 0 }));
  for (const r of rows) {
    const i = Math.min(buckets - 1, Math.floor((Date.parse(r.ts) - (now - span)) / width));
    if (i >= 0 && counts[i][r.cls] !== undefined) counts[i][r.cls]++;
  }
  const labels = [];
  for (let i = 0; i < buckets; i++) {
    labels.push(new Date(now - span + i * width + width / 2).toISOString());
    for (const k of Object.keys(series)) series[k].push(counts[i][k]);
  }
  res.json({ labels, series, width });
});

// --- app inventory ---
api.get("/apps", (_req, res) => {
  const apps = db.prepare(`SELECT name,category,sanctioned,first_seen,last_seen,event_count FROM apps`).all();
  for (const a of apps) a.risk = toolRisk(a.category, a.sanctioned);
  res.json(apps.sort((a, b) => b.risk - a.risk || b.event_count - a.event_count));
});

// --- per-user risk table ---
api.get("/users", (_req, res) => {
  const since = new Date(Date.now() - (config.policy.risk_window_hours || 24) * 3600_000).toISOString();
  const rows = db.prepare(`
    SELECT user, MAX(team) team,
           COUNT(*) events,
           SUM(CASE WHEN action!='allow' THEN 1 ELSE 0 END) alerts,
           COALESCE(SUM(weight),0) weightSum,
           MAX(ts) last_seen
    FROM events WHERE ts>=? GROUP BY user`).all(since);
  for (const r of rows) { r.risk = riskScore(r.weightSum); delete r.weightSum; }
  rows.sort((a, b) => b.risk - a.risk || b.alerts - a.alerts);
  res.json(rows);
});

api.get("/users/:user/risk", (req, res) => {
  const user = req.params.user;
  const since = new Date(Date.now() - (config.policy.risk_window_hours || 24) * 3600_000).toISOString();
  const events = db.prepare(`SELECT id,ts,kind,app,tier,action,cls,weight FROM events
                             WHERE user=? AND ts>=? ORDER BY ts DESC LIMIT 100`).all(user, since);
  res.json({ user, risk: userRisk(user), window_hours: config.policy.risk_window_hours, events });
});

// --- recent events, with optional filters ---
api.get("/events", (req, res) => {
  const limit = Math.min(+req.query.limit || 100, 1000);
  const where = [], args = [];
  for (const f of ["user", "host", "kind", "tier", "cls"]) if (req.query[f]) { where.push(`${f}=?`); args.push(req.query[f]); }
  const sql = `SELECT id,ts,src,host,user,kind,app,score,tier,action,cls,weight,detail FROM events
               ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ts DESC, id DESC LIMIT ?`;
  res.json(db.prepare(sql).all(...args, limit).map(parseDetail));
});

// --- alerts feed (historical) ---
api.get("/alerts", (req, res) => {
  const limit = Math.min(+req.query.limit || 100, 1000);
  res.json(db.prepare(`SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT ?`).all(limit));
});

api.post("/alerts/:id/ack", (req, res) => {
  db.prepare(`UPDATE alerts SET ack=1 WHERE id=?`).run(+req.params.id);
  res.json({ ok: true });
});

// --- agent-facing policy slice ---
api.get("/policy", (_req, res) => {
  const p = config.policy;
  res.json({ version: p.version, stream_score_threshold: p.stream_score_threshold,
    risk_window_hours: p.risk_window_hours, tiers: p.tiers, approved_models: p.approved_models, override_allowed: p.override_allowed,
    categories: config.indicators.categories, sanctioned: config.indicators.sanctioned });
});

// --- Server-Sent Events: live events + alerts ---
api.get("/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream", "Cache-Control": "no-cache",
    Connection: "keep-alive", "X-Accel-Buffering": "no",
  });
  res.write(`event: hello\ndata: ${JSON.stringify({ ts: new Date().toISOString() })}\n\n`);
  addClient(res);
  const ping = setInterval(() => { try { res.write(`:keepalive\n\n`); } catch {} }, 15000);
  req.on("close", () => clearInterval(ping));
});

api.get("/directory", (_req, res) => res.json(config.directory.users || []));

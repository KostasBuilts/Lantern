// Detection + policy engine: classify each event into a tier, score it,
// map it to an action + severity, persist, and raise an alert when needed.
import { config, matchDomain, isSanctioned } from "./config.js";
import { db, stmts } from "./db.js";
import { publish } from "./bus.js";

// Map an event (per Doc 0 schema) to { tier, class } using rules + config.
function classify(ev) {
  const d = ev.detail || {};
  const pol = config.policy;
  const host = d.sni || d.qname || d.dst || null;

  if (host && isSanctioned(host)) return { tier: "allow", cls: "sanctioned" };

  switch (ev.kind) {
    case "local_ai":
      return { tier: pol.tiers.local_ai, cls: "local_ai" };
    case "usb_copy":
    case "prompt": {
      const hits = (d.hits || []).length || (d.hits_count || 0);
      if (hits > 0) return { tier: pol.tiers.sensitive, cls: "sensitive" };
      return { tier: "allow", cls: "clean" };
    }
    case "file_open":
      return d.verdict === "deny"
        ? { tier: pol.tiers.local_ai, cls: "local_ai" }
        : { tier: "allow", cls: "observe" };
    case "flow": {
      const score = d.stream_score ?? ev.score ?? 0;
      if (score >= pol.stream_score_threshold && !isSanctioned(host))
        return { tier: pol.tiers.high_stream, cls: "high_stream" };
      if (matchDomain(host)) return { tier: pol.tiers.shadow_domain, cls: "shadow_domain" };
      return { tier: "allow", cls: "observe" };
    }
    case "dns":
    case "tls": {
      const cat = d.matched_category || matchDomain(host);
      if (cat) return { tier: pol.tiers.shadow_domain, cls: "shadow_domain" };
      return { tier: "allow", cls: "observe" };
    }
    default:
      return { tier: "allow", cls: "observe" };
  }
}

const SEVERITY = { sanctioned: "good", clean: "good", observe: "good",
  shadow_domain: "warning", high_stream: "serious", local_ai: "serious", sensitive: "critical" };
const WEIGHT_KEY = { shadow_domain: "shadow_domain", high_stream: "high_stream_unknown",
  local_ai: "local_ai", sensitive: "sensitive_egress" };

function weightFor(cls) {
  const k = WEIGHT_KEY[cls];
  return k ? (config.policy.weights[k] || 0) : 0;
}

export function appName(ev) {
  const d = ev.detail || {};
  if (ev.kind === "prompt") return d.model && d.model !== "unknown" ? d.model : "gateway";
  if (ev.app && ev.app !== "unknown") return ev.app;
  const host = d.sni || d.qname || d.dst;
  if (ev.kind === "local_ai" || ev.kind === "file_open") return d.binary ? "local-model" : "local-ai";
  if (host) return host;
  return ev.app || "unknown";
}

// Which kinds represent a usable "AI app" for the inventory (USB egress is not an app).
const APP_KINDS = new Set(["dns", "tls", "flow", "local_ai", "file_open", "prompt"]);

// Process one validated event: classify, persist, update inventory, maybe alert.
export function processEvent(ev) {
  const { tier, cls } = classify(ev);
  const action = tier;                                  // tier name == action name here
  const detailJson = JSON.stringify(ev.detail || {});
  const score = ev.detail?.stream_score ?? ev.score ?? 0;

  const severity = SEVERITY[cls] || "good";
  const weight = weightFor(cls);

  const info = stmts().insertEvent.run(ev.ts, ev.src, ev.host, ev.user, ev.kind,
    appName(ev), score, tier, action, cls, weight, detailJson);
  const eventId = Number(info.lastInsertRowid);

  // App inventory: only AI endpoints belong here. Ordinary business traffic
  // (github, slack, a CDN) is not shadow AI and must not pollute the list.
  const host = ev.detail?.sni || ev.detail?.qname || ev.detail?.dst;
  // A prompt recorded by our own gateway IS the approved route, so it counts as sanctioned.
  const viaGateway = ev.kind === "prompt" || ev.src === "gateway";
  const sanctioned = (host && isSanctioned(host)) || viaGateway ? 1 : 0;
  const known = ev.detail?.matched_category || matchDomain(host);
  const isLocal = ev.kind === "local_ai" || ev.kind === "file_open";
  const category = known
    || (isLocal ? "local" : null)
    || (viaGateway ? "gateway" : null)
    || (cls === "high_stream" ? "unknown_ai" : null);   // found by streaming behaviour
  const isAiApp = APP_KINDS.has(ev.kind) && (known || sanctioned || isLocal
    || ev.kind === "prompt" || cls === "high_stream");
  if (isAiApp)
    stmts().upsertApp.run({ name: appName(ev), category, sanctioned, ts: ev.ts });

  let alert = null;
  if (action !== "allow") {
    const reason = reasonText(ev, cls);
    const a = stmts().insertAlert.run(ev.ts, ev.host, ev.user, tier, action, severity, reason, appName(ev), eventId);
    alert = { id: Number(a.lastInsertRowid), ts: ev.ts, host: ev.host, user: ev.user,
      tier, action, severity, reason, app: appName(ev), event_id: eventId };
    publish("alert", alert);
  }

  const outEvent = { id: eventId, ts: ev.ts, src: ev.src, host: ev.host, user: ev.user,
    kind: ev.kind, app: appName(ev), score, tier, action, severity, weight };
  publish("event", outEvent);
  return outEvent;
}

function reasonText(ev, cls) {
  const d = ev.detail || {};
  switch (cls) {
    case "shadow_domain": return `Shadow AI domain ${d.sni || d.qname || d.dst || ""}`.trim();
    case "high_stream": return `LLM streaming pattern to ${d.sni || d.dst || "unknown host"} (score ${(d.stream_score ?? 0).toFixed(2)})`;
    case "local_ai": return `Local model ${d.model_file || (d.models || []).join(",") || ""} via ${d.binary || "unknown"}`.trim();
    case "sensitive": {
      const types = (d.hits || []).map((h) => h.type || h).join(", ");
      return `Sensitive data (${types || "detected"}) to ${ev.kind === "usb_copy" ? (d.device || "USB") : "AI prompt"}`;
    }
    default: return ev.kind;
  }
}

// Map a raw weight sum to a 0..100 risk score with diminishing returns, so
// activity spreads across the range instead of everyone pinning at the cap.
export function riskScore(weightSum) {
  const k = config.policy.risk_saturation || 300;
  return Math.round(100 * (1 - Math.exp(-(weightSum || 0) / k)));
}

// Per-user rolling risk over the window.
export function userRisk(user) {
  const since = new Date(Date.now() - (config.policy.risk_window_hours || 24) * 3600_000).toISOString();
  const row = db.prepare(`SELECT COALESCE(SUM(weight),0) AS total FROM events WHERE user=? AND ts>=?`).get(user, since);
  return riskScore(row.total);
}

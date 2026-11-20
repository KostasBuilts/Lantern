// Detection + policy engine: classify each event into a tier, score it,
// map it to an action + severity, persist, and raise an alert when needed.
import { config, matchDomain, isSanctioned, identify } from "./config.js";
import { toolRisk, severityFor } from "./risk.js";
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
    case "prompt": {
      const dec = d.decision;                         // decided by the gateway (risk.js)
      if (!dec) return { tier: "allow", cls: "clean" };
      const cls = dec.injection ? "injection"
        : dec.risk >= (pol.risk_actions?.redact ?? 50) ? "sensitive"
        : dec.approved ? "clean" : "shadow_domain";
      return { tier: dec.action, cls };
    }
    case "usb_copy": {
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

const WEIGHT_KEY = { shadow_domain: "shadow_domain", high_stream: "high_stream_unknown",
  local_ai: "local_ai", sensitive: "sensitive_egress", injection: "sensitive_egress" };

// Rule risk (0-100) of a network/endpoint detection; prompts carry the gateway's decision.
function riskOf(ev, cls, category) {
  const d = ev.detail || {};
  if (d.decision) return d.decision.risk;
  switch (cls) {
    case "shadow_domain": return Math.min(100, toolRisk(category) + (d.up_bytes ? 30 : 0));
    case "high_stream": return category === "unknown_ai" ? toolRisk("unknown_ai") : Math.min(100, toolRisk(category) + 15);
    case "local_ai": return toolRisk("local");
    case "sensitive": return 80;
    default: return 0;
  }
}

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
  const { user, team } = identify(ev.user);
  ev = { ...ev, user };
  const { tier, cls } = classify(ev);
  const action = tier;                                  // tier name == action name here
  const detailJson = JSON.stringify(ev.detail || {});
  const score = ev.detail?.stream_score ?? ev.score ?? 0;

  const weight = weightFor(cls);

  // App inventory: only AI endpoints belong here. Ordinary business traffic
  // (github, slack, a CDN) is not shadow AI and must not pollute the list.
  const host = ev.detail?.sni || ev.detail?.qname || ev.detail?.dst;
  const isPrompt = ev.kind === "prompt";
  const approvedModel = Boolean(ev.detail?.decision?.approved);
  const sanctioned = (host && isSanctioned(host)) || (isPrompt && approvedModel) ? 1 : 0;
  const known = ev.detail?.matched_category || matchDomain(host);
  const isLocal = ev.kind === "local_ai" || ev.kind === "file_open";
  const category = known
    || (isLocal ? "local" : null)
    || (isPrompt ? (approvedModel ? "approved_model" : "unapproved_model") : null)
    || (cls === "high_stream" ? "unknown_ai" : null);   // found by streaming behaviour
  const isAiApp = APP_KINDS.has(ev.kind) && (known || sanctioned || isLocal
    || isPrompt || cls === "high_stream");
  const risk = riskOf(ev, cls, category);
  const severity = severityFor(risk);

  const info = stmts().insertEvent.run(ev.ts, ev.src, ev.host, ev.user, team, ev.kind,
    appName(ev), score, risk, tier, action, cls, weight, detailJson);
  const eventId = Number(info.lastInsertRowid);
  if (isAiApp)
    stmts().upsertApp.run({ name: appName(ev), category, sanctioned, ts: ev.ts });

  let alert = null;
  const reason = action !== "allow" ? reasonText(ev, cls) : null;
  // One alert per (user, app, reason) per dedup window: a browser tab opens many connections.
  const since = new Date(Date.parse(ev.ts) - (config.policy.dedup_window_seconds ?? 300) * 1000).toISOString();
  if (reason && !stmts().recentAlert.get(ev.user, appName(ev), reason, since)) {
    const a = stmts().insertAlert.run(ev.ts, ev.host, ev.user, team, tier, action, severity, risk, reason, appName(ev), eventId);
    alert = { id: Number(a.lastInsertRowid), ts: ev.ts, host: ev.host, user: ev.user, team,
      tier, action, severity, risk, reason, app: appName(ev), event_id: eventId };
    publish("alert", alert);
  }

  const outEvent = { id: eventId, ts: ev.ts, src: ev.src, host: ev.host, user: ev.user, team,
    kind: ev.kind, app: appName(ev), score, risk, tier, action, severity, weight };
  publish("event", outEvent);
  return outEvent;
}

function reasonText(ev, cls) {
  const d = ev.detail || {};
  if (d.decision) return d.decision.explanation;
  switch (cls) {
    case "shadow_domain": {
      const up = d.up_bytes ? ` (uploaded ${(d.up_bytes / 1048576).toFixed(1)} MiB)` : "";
      return `Shadow AI domain ${d.sni || d.qname || d.dst || ""}${up}`.trim();
    }
    case "high_stream": return `LLM streaming pattern to ${d.sni || d.dst || "unknown host"} (score ${Number(d.stream_score ?? ev.score ?? 0).toFixed(2)})`;
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

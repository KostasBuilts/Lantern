"""Detection engine: classify each event, store it, raise/collapse alerts,
maintain the app inventory, and compute rolling per-user risk.

Severity ladder (what the analyst triages by):
  critical  sensitive data leaving to AI (usb_copy / prompt with hits + block)
  high      a local LLM running, or a high stream score to an unknown server
  medium    traffic to a known shadow-AI domain
  low       sanctioned / benign observations
"""
from __future__ import annotations
import json, time
from datetime import datetime, timezone

from config import config
import db
from hub import hub

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify(ev: dict):
    """Return (tier, action, severity, weight, reason). Pure function of the event + config."""
    kind = ev.get("kind")
    detail = ev.get("detail") or {}
    app = ev.get("app") or "unknown"

    if kind in ("dns", "tls"):
        host = detail.get("sni") or detail.get("qname")
        cat, sanct = config.match_domain(host)
        if sanct:
            return ("sanctioned", "allow", "low", 0, "Sanctioned endpoint")
        if cat or detail.get("matched_category"):
            c = cat or detail.get("matched_category")
            return ("shadow_domain", config.tier_action("shadow_domain"), "medium",
                    config.weight("shadow_domain"), f"Traffic to shadow-AI domain ({c})")
        return ("observe", "observe", "low", 0, "Observed traffic")

    if kind == "flow":
        score = float(ev.get("score") or detail.get("stream_score") or 0)
        host = detail.get("sni")
        cat, sanct = config.match_domain(host)
        thr = float(config.get("stream_score_threshold", 0.70))
        if sanct:
            return ("sanctioned", "allow", "low", 0, "Sanctioned endpoint")
        if score >= thr:
            where = host or detail.get("dst_ip") or "unknown server"
            known = " (known AI domain)" if cat else " on an unknown server"
            return ("high_stream", config.tier_action("high_stream"), "high",
                    config.weight("high_stream_unknown"),
                    f"LLM streaming pattern{known}, score {score:.2f}")
        return ("observe", "observe", "low", 0, f"Flow, score {score:.2f}")

    if kind == "local_ai":
        models = detail.get("models") or []
        m = (", ".join(models)) if models else (detail.get("model_file") or "model")
        return ("local_ai", config.tier_action("local_ai"), "high",
                config.weight("local_ai"), f"Local LLM running: {m}")

    if kind == "file_open":
        if detail.get("verdict") == "deny":
            return ("local_ai", config.tier_action("local_ai"), "high",
                    config.weight("local_ai"),
                    f"Blocked model load ({detail.get('fmt','model')}) from {detail.get('drive','disk')}")
        return ("observe", "observe", "low", 0, "Model file opened")

    if kind == "usb_copy":
        hits = detail.get("hits") or []
        if hits and detail.get("verdict", "block") == "block":
            return ("sensitive", config.tier_action("sensitive"), "critical",
                    config.weight("sensitive_egress"),
                    f"Sensitive data blocked to USB: {', '.join(hits)}")
        if hits:
            return ("sensitive", "coach", "medium", config.weight("sensitive_egress") // 2,
                    f"Sensitive data to USB (allowed): {', '.join(hits)}")
        return ("observe", "allow", "low", 0, "Clean file to USB")

    if kind == "prompt":
        hits = detail.get("hits") or []
        act = detail.get("action", "redact")
        if act == "block" or detail.get("doc_match"):
            return ("sensitive", "block", "critical", config.weight("sensitive_egress"),
                    "Confidential document blocked at AI gateway")
        if hits:
            return ("high_stream", "redact", "medium", config.weight("shadow_domain"),
                    f"Sensitive data redacted at gateway: {', '.join(hits)}")
        return ("sanctioned", "allow", "low", 0, "Clean prompt via gateway")

    return ("observe", "observe", "low", 0, "Observed")


def _dedup_key(ev, tier):
    return "|".join([ev.get("host", ""), ev.get("user", ""), ev.get("app", "") or "unknown",
                     ev.get("kind", ""), tier])


def _update_apps(ev):
    app = ev.get("app") or "unknown"
    if app == "unknown":
        return
    detail = ev.get("detail") or {}
    host = detail.get("sni") or detail.get("qname")
    cat, sanct = config.match_domain(host)
    now = _now_iso()
    user = ev.get("user", "")
    rows = db.q("SELECT * FROM apps WHERE name=?", (app,))
    if rows:
        a = rows[0]
        users = set(json.loads(a["users"] or "[]")); users.add(user)
        eff_sanct = a["sanctioned"] if a["overridden"] else (1 if sanct else 0)
        db.execute(
            "UPDATE apps SET category=?, last_seen=?, event_count=event_count+1, users=?, sanctioned=? WHERE name=?",
            (cat or a["category"], now, json.dumps(sorted(users)), eff_sanct, app))
    else:
        db.execute(
            "INSERT INTO apps(name,category,sanctioned,overridden,first_seen,last_seen,event_count,users) "
            "VALUES(?,?,?,0,?,?,1,?)",
            (app, cat, 1 if sanct else 0, now, now, json.dumps([user] if user else [])))


def ingest_event(ev: dict):
    """Store one event, update inventory, raise/merge an alert. Returns a summary dict."""
    tier, action, severity, weight, reason = classify(ev)
    detail = ev.get("detail") or {}
    recv = _now_iso()
    ev_action = ev.get("action") or action

    event_id = db.execute(
        "INSERT INTO events(ts,received_ts,src,host,user,kind,app,tier,action,severity,weight,score,reason,detail) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ev.get("ts"), recv, ev.get("src"), ev.get("host"), ev.get("user"), ev.get("kind"),
         ev.get("app") or "unknown", tier, action, severity, weight, float(ev.get("score") or 0),
         reason, json.dumps(detail)))

    _update_apps(ev)

    alert = None
    if SEV_RANK.get(severity, 0) >= SEV_RANK["medium"]:
        alert = _raise_alert(ev, tier, action, severity, reason, detail, recv)

    hub.publish("event", {"id": event_id, "ts": ev.get("ts"), "severity": severity,
                          "kind": ev.get("kind"), "host": ev.get("host"), "user": ev.get("user")})
    return {"event_id": event_id, "severity": severity, "tier": tier, "alert": alert}


def _raise_alert(ev, tier, action, severity, reason, detail, recv):
    key = _dedup_key(ev, tier)
    window = int(config.get("dedup_window_seconds", 300))
    existing = db.q(
        "SELECT * FROM alerts WHERE dedup_key=? AND status!='resolved' "
        "AND (strftime('%s','now') - strftime('%s', last_ts)) < ? ORDER BY id DESC LIMIT 1",
        (key, window))
    if existing:
        a = existing[0]
        db.execute("UPDATE alerts SET count=count+1, last_ts=?, reason=?, detail=?, updated_ts=? WHERE id=?",
                   (recv, reason, json.dumps(detail), recv, a["id"]))
        row = db.q("SELECT * FROM alerts WHERE id=?", (a["id"],))[0]
        hub.publish("alert_update", _alert_public(row))
        return row["id"]

    aid = db.execute(
        "INSERT INTO alerts(dedup_key,first_ts,last_ts,host,user,app,kind,tier,action,severity,reason,count,detail,status,updated_ts) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?, 'open', ?)",
        (key, recv, recv, ev.get("host"), ev.get("user"), ev.get("app") or "unknown",
         ev.get("kind"), tier, action, severity, reason, json.dumps(detail), recv))
    row = db.q("SELECT * FROM alerts WHERE id=?", (aid,))[0]
    hub.publish("alert", _alert_public(row))
    return aid


def _alert_public(row: dict):
    d = dict(row)
    try:
        d["detail"] = json.loads(d.get("detail") or "{}")
    except Exception:
        d["detail"] = {}
    return d


# ---------------- read models for the API ----------------
def user_risk(window_hours=None):
    wh = window_hours or int(config.get("risk_window_hours", 24))
    rows = db.q(
        "SELECT user, SUM(weight) AS risk, COUNT(*) AS events, MAX(severity) AS worst, MAX(ts) AS last_ts "
        "FROM events WHERE weight>0 AND (strftime('%s','now') - strftime('%s', received_ts)) < ? "
        "GROUP BY user ORDER BY risk DESC", (wh * 3600,))
    for r in rows:
        r["risk"] = min(int(r["risk"] or 0), 100)
    return rows


def scrub_old():
    """Delete events past retention. Returns rows removed."""
    hrs = int(config.get("retention_hours", 72))
    with db._lock:
        conn = db.get_conn()
        cur = conn.execute(
            "DELETE FROM events WHERE (strftime('%s','now') - strftime('%s', received_ts)) > ?",
            (hrs * 3600,))
        conn.commit()
        return cur.rowcount

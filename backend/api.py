"""Analyst-facing API + sensor ingest, mounted by app.py."""
from __future__ import annotations
import asyncio, json
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse

from config import config
import db, engine
from hub import hub
from models import Event, TriageUpdate, SanctionUpdate

router = APIRouter()


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------- ingest (sensors -> here) ----------------
@router.post("/ingest")
async def ingest(request: Request):
    """Accept newline-delimited JSON, one event per line."""
    raw = await request.body()
    text = raw.decode("utf-8", "replace")
    accepted, skipped = 0, 0
    errors = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = Event.model_validate_json(line)
            await asyncio.to_thread(engine.ingest_event, ev.model_dump())
            accepted += 1
        except Exception as e:
            skipped += 1
            if len(errors) < 5:
                errors.append(str(e))
    return JSONResponse({"accepted": accepted, "skipped": skipped, "errors": errors},
                        status_code=202)


# ---------------- analyst reads ----------------
@router.get("/api/stats")
async def stats():
    def _work():
        wh = int(config.get("risk_window_hours", 24))
        win = wh * 3600
        open_alerts = db.q("SELECT severity, COUNT(*) c FROM alerts WHERE status='open' GROUP BY severity")
        sev = {r["severity"]: r["c"] for r in open_alerts}
        total_open = sum(sev.values())
        worst = next((s for s in ("critical", "high", "medium", "low") if sev.get(s)), None)
        ev_window = db.q(
            "SELECT COUNT(*) c FROM events WHERE (strftime('%s','now') - strftime('%s',received_ts)) < ?",
            (win,))[0]["c"]
        ev_min = db.q(
            "SELECT COUNT(*) c FROM events WHERE (strftime('%s','now') - strftime('%s',received_ts)) < 60")[0]["c"]
        users = engine.user_risk(wh)
        at_risk = sum(1 for u in users if u["risk"] >= 30)
        apps = db.q("SELECT COUNT(*) c, SUM(CASE WHEN sanctioned=0 THEN 1 ELSE 0 END) shadow FROM apps")[0]
        return {
            "open_alerts": total_open,
            "by_severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
            "worst_severity": worst,
            "events_window": ev_window,
            "events_per_min": ev_min,
            "users_at_risk": at_risk,
            "apps_total": apps["c"] or 0,
            "apps_shadow": apps["shadow"] or 0,
            "window_hours": wh,
        }
    return await asyncio.to_thread(_work)


@router.get("/api/timeseries")
async def timeseries(hours: int = 24, buckets: int = 24):
    def _work():
        span = hours * 3600
        size = max(1, span // buckets)
        rows = db.q(
            "SELECT CAST((strftime('%s','now') - strftime('%s',received_ts)) / ? AS INT) AS b, "
            "severity, COUNT(*) c FROM events "
            "WHERE (strftime('%s','now') - strftime('%s',received_ts)) < ? GROUP BY b, severity",
            (size, span))
        grid = [{"low": 0, "medium": 0, "high": 0, "critical": 0} for _ in range(buckets)]
        for r in rows:
            b = r["b"]
            if 0 <= b < buckets:
                grid[buckets - 1 - b][r["severity"]] = r["c"]   # oldest -> newest
        labels = []
        for i in range(buckets):
            mins_ago = (buckets - 1 - i) * size // 60
            labels.append(f"-{mins_ago}m" if mins_ago else "now")
        return {"buckets": grid, "labels": labels, "bucket_seconds": size}
    return await asyncio.to_thread(_work)


@router.get("/api/alerts")
async def alerts(status: str = "open", limit: int = 100):
    def _work():
        if status == "all":
            rows = db.q("SELECT * FROM alerts ORDER BY last_ts DESC LIMIT ?", (limit,))
        else:
            rows = db.q("SELECT * FROM alerts WHERE status=? ORDER BY last_ts DESC LIMIT ?", (status, limit))
        return [engine._alert_public(r) for r in rows]
    return await asyncio.to_thread(_work)


@router.post("/api/alerts/{alert_id}/triage")
async def triage(alert_id: int, upd: TriageUpdate):
    if upd.status not in ("open", "ack", "resolved"):
        raise HTTPException(400, "status must be open, ack, or resolved")
    def _work():
        rows = db.q("SELECT id FROM alerts WHERE id=?", (alert_id,))
        if not rows:
            return None
        db.execute("UPDATE alerts SET status=?, note=COALESCE(?,note), updated_ts=? WHERE id=?",
                   (upd.status, upd.note, _now_iso(), alert_id))
        return engine._alert_public(db.q("SELECT * FROM alerts WHERE id=?", (alert_id,))[0])
    row = await asyncio.to_thread(_work)
    if row is None:
        raise HTTPException(404, "alert not found")
    hub.publish("alert_update", row)
    return row


@router.get("/api/apps")
async def apps():
    def _work():
        rows = db.q("SELECT * FROM apps ORDER BY event_count DESC")
        for r in rows:
            r["users"] = json.loads(r.get("users") or "[]")
            r["sanctioned"] = bool(r["sanctioned"])
            r["overridden"] = bool(r["overridden"])
        return rows
    return await asyncio.to_thread(_work)


@router.post("/api/apps/{name}/sanction")
async def set_sanction(name: str, upd: SanctionUpdate):
    def _work():
        rows = db.q("SELECT name FROM apps WHERE name=?", (name,))
        if not rows:
            return None
        db.execute("UPDATE apps SET sanctioned=?, overridden=1 WHERE name=?",
                   (1 if upd.sanctioned else 0, name))
        r = db.q("SELECT * FROM apps WHERE name=?", (name,))[0]
        r["users"] = json.loads(r.get("users") or "[]")
        r["sanctioned"] = bool(r["sanctioned"]); r["overridden"] = bool(r["overridden"])
        return r
    row = await asyncio.to_thread(_work)
    if row is None:
        raise HTTPException(404, "app not found")
    return row


@router.get("/api/users")
async def users():
    return await asyncio.to_thread(engine.user_risk)


@router.get("/api/users/{user}/events")
async def user_events(user: str, limit: int = 50):
    def _work():
        rows = db.q("SELECT * FROM events WHERE user=? ORDER BY id DESC LIMIT ?", (user, limit))
        for r in rows:
            try:
                r["detail"] = json.loads(r.get("detail") or "{}")
            except Exception:
                r["detail"] = {}
        return rows
    return await asyncio.to_thread(_work)


@router.get("/policy")
async def policy():
    """Agent-facing policy view."""
    return config.agent_view()


# ---------------- live stream (SSE) ----------------
@router.get("/api/stream")
async def stream(request: Request):
    queue = hub.subscribe()

    async def gen():
        try:
            yield b": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15)
                    payload = json.dumps(msg["data"])
                    yield f"event: {msg['type']}\ndata: {payload}\n\n".encode()
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"
        finally:
            hub.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

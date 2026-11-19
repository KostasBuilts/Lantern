"""SQLite storage (WAL). One module-level connection guarded by a lock."""
from __future__ import annotations
import json, os, sqlite3, threading, time

DB_PATH = os.environ.get("LANTERN_DB", os.path.join(os.path.dirname(__file__), "..", "lantern.db"))

_conn: sqlite3.Connection | None = None
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, received_ts TEXT NOT NULL,
  src TEXT, host TEXT, user TEXT, kind TEXT, app TEXT,
  tier TEXT, action TEXT, severity TEXT, weight INTEGER DEFAULT 0,
  score REAL DEFAULT 0, reason TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_user ON events(user, ts);
CREATE INDEX IF NOT EXISTS ix_events_host ON events(host, ts);
CREATE INDEX IF NOT EXISTS ix_events_recv ON events(received_ts);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dedup_key TEXT, first_ts TEXT, last_ts TEXT,
  host TEXT, user TEXT, app TEXT, kind TEXT,
  tier TEXT, action TEXT, severity TEXT, reason TEXT,
  count INTEGER DEFAULT 1, detail TEXT,
  status TEXT DEFAULT 'open',        -- open | ack | resolved
  note TEXT, updated_ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts(dedup_key, status);

CREATE TABLE IF NOT EXISTS apps (
  name TEXT PRIMARY KEY, category TEXT,
  sanctioned INTEGER DEFAULT 0,       -- effective (indicator or analyst override)
  overridden INTEGER DEFAULT 0,       -- analyst set it manually
  first_seen TEXT, last_seen TEXT, event_count INTEGER DEFAULT 0,
  users TEXT                           -- JSON list of distinct users seen
);
"""


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                _conn.row_factory = sqlite3.Row
                _conn.execute("PRAGMA journal_mode=WAL;")
                _conn.execute("PRAGMA synchronous=NORMAL;")
                _conn.executescript(SCHEMA)
                _conn.commit()
    return _conn


def q(sql, params=()):
    with _lock:
        cur = get_conn().execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    return rows


def execute(sql, params=()):
    with _lock:
        conn = get_conn()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid


def reset():
    """Wipe all data (used by the simulator's --reset and by tests)."""
    with _lock:
        conn = get_conn()
        conn.executescript("DELETE FROM events; DELETE FROM alerts; DELETE FROM apps;")
        conn.commit()


def close():
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None

// SQLite storage (Node 22 built-in node:sqlite). One writer; WAL for concurrent reads.
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const DB_PATH = process.env.LANTERN_DB || join(here, "lantern.db");

export const db = new DatabaseSync(DB_PATH);

export function initDb() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS events (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      ts        TEXT NOT NULL,
      src       TEXT NOT NULL,
      host      TEXT NOT NULL,
      user      TEXT NOT NULL,
      kind      TEXT NOT NULL,
      app       TEXT,
      score     REAL DEFAULT 0,
      tier      TEXT,
      action    TEXT,
      cls       TEXT,                 -- event class (shadow_domain, local_ai, ...)
      weight    REAL DEFAULT 0,       -- risk weight contributed
      detail    TEXT,                 -- JSON string
      created   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS ix_events_user ON events(user, ts);
    CREATE INDEX IF NOT EXISTS ix_events_host ON events(host, ts);
    CREATE INDEX IF NOT EXISTS ix_events_ts   ON events(ts);

    CREATE TABLE IF NOT EXISTS apps (
      name        TEXT PRIMARY KEY,
      category    TEXT,
      sanctioned  INTEGER DEFAULT 0,
      first_seen  TEXT,
      last_seen   TEXT,
      event_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      ts        TEXT NOT NULL,
      host      TEXT,
      user      TEXT,
      tier      TEXT,
      action    TEXT,
      severity  TEXT,                 -- good|warning|serious|critical
      reason    TEXT,
      app       TEXT,
      event_id  INTEGER,
      ack       INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);

    CREATE TABLE IF NOT EXISTS docs_index (
      doc_id       TEXT PRIMARY KEY,
      fingerprints TEXT               -- JSON array
    );
  `);
}

// Prepared statements (built after initDb).
let S;
export function prepare() {
  S = {
    insertEvent: db.prepare(`INSERT INTO events (ts,src,host,user,kind,app,score,tier,action,cls,weight,detail)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`),
    upsertApp: db.prepare(`
      INSERT INTO apps (name,category,sanctioned,first_seen,last_seen,event_count)
      VALUES (@name,@category,@sanctioned,@ts,@ts,1)
      ON CONFLICT(name) DO UPDATE SET
        last_seen=@ts, event_count=event_count+1,
        category=COALESCE(apps.category,@category),
        sanctioned=@sanctioned`),
    insertAlert: db.prepare(`INSERT INTO alerts (ts,host,user,tier,action,severity,reason,app,event_id)
                             VALUES (?,?,?,?,?,?,?,?,?)`),
  };
  return S;
}
export function stmts() { return S; }

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DATA_DIR = path.join(process.cwd(), "data");

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function initDb() {
  ensureDataDir();
  const dbPath = path.join(DATA_DIR, "sv-monitor.sqlite");
  const db = new Database(dbPath);

  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      entityId TEXT,
      dedupeKey TEXT,
      message TEXT NOT NULL,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_type_dedupe_createdAt
      ON alerts(type, dedupeKey, createdAt);

    CREATE TABLE IF NOT EXISTS fs_fingerprints (
      path TEXT PRIMARY KEY,
      hash TEXT,
      mtimeMs REAL,
      size INTEGER,
      mode INTEGER,
      uid INTEGER,
      gid INTEGER,
      lastSeenAt TEXT
    );
  `);

  return db;
}

function createAlertStore(db) {
  const insertAlertStmt = db.prepare(`
    INSERT INTO alerts (createdAt, type, severity, entityId, dedupeKey, message, metadata)
    VALUES (@createdAt, @type, @severity, @entityId, @dedupeKey, @message, @metadata)
  `);

  const listAlertsStmt = db.prepare(`
    SELECT id, createdAt, type, severity, entityId, dedupeKey, message, metadata
    FROM alerts
    ORDER BY id DESC
    LIMIT @limit
  `);

  const lastAlertStmt = db.prepare(`
    SELECT id, createdAt
    FROM alerts
    WHERE type = @type AND dedupeKey = @dedupeKey
    ORDER BY id DESC
    LIMIT 1
  `);

  const getFingerprintStmt = db.prepare(`
    SELECT path, hash, mtimeMs, size, mode, uid, gid, lastSeenAt
    FROM fs_fingerprints
    WHERE path = @path
    LIMIT 1
  `);

  const upsertFingerprintStmt = db.prepare(`
    INSERT INTO fs_fingerprints (path, hash, mtimeMs, size, mode, uid, gid, lastSeenAt)
    VALUES (@path, @hash, @mtimeMs, @size, @mode, @uid, @gid, @lastSeenAt)
    ON CONFLICT(path) DO UPDATE SET
      hash = excluded.hash,
      mtimeMs = excluded.mtimeMs,
      size = excluded.size,
      mode = excluded.mode,
      uid = excluded.uid,
      gid = excluded.gid,
      lastSeenAt = excluded.lastSeenAt
  `);

  return {
    shouldDedupe({ type, dedupeKey, cooldownMs }) {
      if (!dedupeKey) return false;
      const row = lastAlertStmt.get({ type, dedupeKey });
      if (!row) return false;
      const lastAt = new Date(row.createdAt).getTime();
      if (Number.isNaN(lastAt)) return false;
      return Date.now() - lastAt < cooldownMs;
    },
    insertAlert({ type, severity, entityId, dedupeKey, message, metadata }) {
      insertAlertStmt.run({
        createdAt: new Date().toISOString(),
        type,
        severity,
        entityId: entityId ?? null,
        dedupeKey: dedupeKey ?? null,
        message: message ?? "",
        metadata: metadata ? JSON.stringify(metadata) : null,
      });
    },
    listAlerts(limit) {
      const rows = listAlertsStmt.all({ limit: limit ?? 200 });
      return rows.map((r) => ({
        id: r.id,
        createdAt: r.createdAt,
        type: r.type,
        severity: r.severity,
        entityId: r.entityId,
        dedupeKey: r.dedupeKey,
        message: r.message,
        metadata: r.metadata ? JSON.parse(r.metadata) : null,
      }));
    },
    getFingerprint(filePath) {
      return getFingerprintStmt.get({ path: filePath });
    },
    upsertFingerprint(fp) {
      upsertFingerprintStmt.run({
        path: fp.path,
        hash: fp.hash ?? null,
        mtimeMs: fp.mtimeMs ?? null,
        size: fp.size ?? null,
        mode: fp.mode ?? null,
        uid: fp.uid ?? null,
        gid: fp.gid ?? null,
        lastSeenAt: new Date().toISOString(),
      });
    },
  };
}

module.exports = { initDb, createAlertStore };


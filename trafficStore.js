const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DATA_DIR = path.join(process.cwd(), "data");

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function initTrafficTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS traffic_samples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      containerId TEXT NOT NULL,
      containerName TEXT,
      rxRateBytesPerSec REAL NOT NULL,
      txRateBytesPerSec REAL NOT NULL,
      rxBytesDelta INTEGER NOT NULL,
      txBytesDelta INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_traffic_container_time
      ON traffic_samples(containerId, createdAt);

    CREATE TABLE IF NOT EXISTS quarantine_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      containerId TEXT NOT NULL,
      containerName TEXT,
      decision TEXT NOT NULL,
      reason TEXT,
      networksDisconnected TEXT,
      releaseAt TEXT
    );
  `);
}

function createTrafficStore(db) {
  const insertStmt = db.prepare(`
    INSERT INTO traffic_samples (createdAt, containerId, containerName, rxRateBytesPerSec, txRateBytesPerSec, rxBytesDelta, txBytesDelta)
    VALUES (@createdAt, @containerId, @containerName, @rxRate, @txRate, @rxBytesDelta, @txBytesDelta)
  `);

  const getBaselineAggStmt = db.prepare(`
    SELECT
      AVG(rxRateBytesPerSec) as avgRx,
      MAX(rxRateBytesPerSec) as maxRx,
      AVG(txRateBytesPerSec) as avgTx,
      MAX(txRateBytesPerSec) as maxTx,
      COUNT(*) as samples
    FROM traffic_samples
    WHERE containerId = @containerId
      AND createdAt >= @fromAt
  `);

  const pruneStmt = db.prepare(`
    DELETE FROM traffic_samples
    WHERE createdAt < @olderThan
  `);

  const listRecentTrafficStmt = db.prepare(`
    SELECT createdAt, rxRateBytesPerSec, txRateBytesPerSec, rxBytesDelta, txBytesDelta
    FROM traffic_samples
    WHERE containerId = @containerId
    ORDER BY id DESC
    LIMIT @limit
  `);

  const insertQuarantineActionStmt = db.prepare(`
    INSERT INTO quarantine_actions (createdAt, containerId, containerName, decision, reason, networksDisconnected, releaseAt)
    VALUES (@createdAt, @containerId, @containerName, @decision, @reason, @networksDisconnected, @releaseAt)
  `);

  const markReleasedStmt = db.prepare(`
    UPDATE quarantine_actions
    SET decision = 'released'
    WHERE id = @id
  `);

  return {
    insertSample({ containerId, containerName, rxRateBytesPerSec, txRateBytesPerSec, rxBytesDelta, txBytesDelta }) {
      insertStmt.run({
        createdAt: new Date().toISOString(),
        containerId,
        containerName: containerName ?? null,
        rxRate: rxRateBytesPerSec,
        txRate: txRateBytesPerSec,
        rxBytesDelta: rxBytesDelta ?? 0,
        txBytesDelta: txBytesDelta ?? 0,
      });
    },
    getBaselineAgg({ containerId, fromAt }) {
      return getBaselineAggStmt.get({ containerId, fromAt });
    },
    prune({ olderThan }) {
      pruneStmt.run({ olderThan });
    },
    listRecentSamples({ containerId, limit }) {
      const rows = listRecentTrafficStmt.all({ containerId, limit: limit ?? 200 });
      // Devuelve en orden ascendente para render
      return rows
        .reverse()
        .map((r) => ({
          at: r.createdAt,
          rxRateBytesPerSec: r.rxRateBytesPerSec,
          txRateBytesPerSec: r.txRateBytesPerSec,
          rxBytesDelta: r.rxBytesDelta,
          txBytesDelta: r.txBytesDelta,
        }));
    },
    insertQuarantineAction({ containerId, containerName, decision, reason, networksDisconnected, releaseAt }) {
      insertQuarantineActionStmt.run({
        createdAt: new Date().toISOString(),
        containerId,
        containerName: containerName ?? null,
        decision,
        reason: reason ?? null,
        networksDisconnected: JSON.stringify(networksDisconnected ?? []),
        releaseAt: releaseAt ?? null,
      });
    },
    async reconnectQuarantine({ docker, containerId, networksDisconnected, containerName }) {
      const ids = networksDisconnected ?? [];
      for (const netId of ids) {
        try {
          const net = docker.getNetwork(netId);
          await net.connect({ container: containerId, aliases: [containerName].filter(Boolean) });
        } catch {
          // Falla silenciosa; el admin lo revisa.
        }
      }
    },
    pruneOldSamples({ olderThan }) {
      pruneStmt.run({ olderThan });
    },
    listRecentQuarantineActions({ containerId, limit }) {
      const stmt = db.prepare(`
        SELECT id, createdAt, containerId, containerName, decision, reason, releaseAt, networksDisconnected
        FROM quarantine_actions
        WHERE containerId = @containerId
        ORDER BY id DESC
        LIMIT @limit
      `);
      const rows = stmt.all({ containerId, limit: limit ?? 10 });
      return rows.map((r) => ({
        id: r.id,
        createdAt: r.createdAt,
        decision: r.decision,
        reason: r.reason,
        releaseAt: r.releaseAt,
        networksDisconnected: r.networksDisconnected ? JSON.parse(r.networksDisconnected) : [],
      }));
    },
  };
}

module.exports = { initTrafficTables, createTrafficStore };


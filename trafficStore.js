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

    CREATE TABLE IF NOT EXISTS container_resource_samples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      containerId TEXT NOT NULL,
      containerName TEXT,
      cpuPercent REAL,
      memUsageBytes INTEGER,
      memLimitBytes INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_resource_container_time
      ON container_resource_samples(containerId, createdAt);

    CREATE TABLE IF NOT EXISTS ai_traffic_analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      containerId TEXT NOT NULL,
      containerName TEXT,
      baselineAvgRx REAL,
      baselineMaxRx REAL,
      latestRxRateBytesPerSec REAL,
      latestTxRateBytesPerSec REAL,
      rxBytesDelta INTEGER,
      txBytesDelta INTEGER,
      attack INTEGER NOT NULL,
      confidence REAL,
      reason TEXT,
      logsTail TEXT,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_ai_traffic_container_time
      ON ai_traffic_analyses(containerId, createdAt);

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

    CREATE TABLE IF NOT EXISTS docker_audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdAt TEXT NOT NULL,
      containerId TEXT,
      containerName TEXT,
      action TEXT,
      type TEXT,
      scope TEXT,
      status TEXT,
      actor TEXT,
      message TEXT,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_docker_audit_events_createdAt
      ON docker_audit_events(createdAt);
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

  const insertResourceSampleStmt = db.prepare(`
    INSERT INTO container_resource_samples (
      createdAt, containerId, containerName, cpuPercent, memUsageBytes, memLimitBytes
    ) VALUES (
      @createdAt, @containerId, @containerName, @cpuPercent, @memUsageBytes, @memLimitBytes
    )
  `);

  const listRecentResourceSamplesStmt = db.prepare(`
    SELECT createdAt, cpuPercent, memUsageBytes, memLimitBytes
    FROM container_resource_samples
    WHERE containerId = @containerId
    ORDER BY id DESC
    LIMIT @limit
  `);

  const pruneResourceSamplesStmt = db.prepare(`
    DELETE FROM container_resource_samples
    WHERE createdAt < @olderThan
  `);

  const insertAiAnalysisStmt = db.prepare(`
    INSERT INTO ai_traffic_analyses (
      createdAt, containerId, containerName,
      baselineAvgRx, baselineMaxRx,
      latestRxRateBytesPerSec, latestTxRateBytesPerSec,
      rxBytesDelta, txBytesDelta,
      attack, confidence, reason, logsTail, metadata
    ) VALUES (
      @createdAt, @containerId, @containerName,
      @baselineAvgRx, @baselineMaxRx,
      @latestRxRateBytesPerSec, @latestTxRateBytesPerSec,
      @rxBytesDelta, @txBytesDelta,
      @attack, @confidence, @reason, @logsTail, @metadata
    )
  `);

  const listRecentAiAnalysesStmt = db.prepare(`
    SELECT
      id, createdAt,
      containerId, containerName,
      baselineAvgRx, baselineMaxRx,
      latestRxRateBytesPerSec, latestTxRateBytesPerSec,
      rxBytesDelta, txBytesDelta,
      attack, confidence, reason,
      logsTail,
      metadata
    FROM ai_traffic_analyses
    WHERE containerId = @containerId
    ORDER BY id DESC
    LIMIT @limit
  `);

  const listRecentTrafficStmt = db.prepare(`
    SELECT createdAt, rxRateBytesPerSec, txRateBytesPerSec, rxBytesDelta, txBytesDelta
    FROM traffic_samples
    WHERE containerId = @containerId
    ORDER BY id DESC
    LIMIT @limit
  `);

  const insertDockerAuditEventStmt = db.prepare(`
    INSERT INTO docker_audit_events (
      createdAt, containerId, containerName,
      action, type, scope, status, actor, message, metadata
    ) VALUES (
      @createdAt, @containerId, @containerName,
      @action, @type, @scope, @status, @actor, @message, @metadata
    )
  `);

  const listRecentDockerAuditEventsStmt = db.prepare(`
    SELECT id, createdAt, containerId, containerName, action, type, scope, status, actor, message, metadata
    FROM docker_audit_events
    ORDER BY id DESC
    LIMIT @limit
  `);

  const pruneDockerAuditEventsStmt = db.prepare(`
    DELETE FROM docker_audit_events
    WHERE createdAt < @olderThan
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
    insertResourceSample({ containerId, containerName, cpuPercent, memUsageBytes, memLimitBytes }) {
      insertResourceSampleStmt.run({
        createdAt: new Date().toISOString(),
        containerId,
        containerName: containerName ?? null,
        cpuPercent: cpuPercent ?? null,
        memUsageBytes: memUsageBytes ?? null,
        memLimitBytes: memLimitBytes ?? null,
      });
    },
    listRecentResourceSamples({ containerId, limit }) {
      const rows = listRecentResourceSamplesStmt.all({ containerId, limit: limit ?? 200 });
      return rows
        .reverse()
        .map((r) => ({
          at: r.createdAt,
          cpuPercent: r.cpuPercent ?? null,
          memUsageBytes: r.memUsageBytes ?? null,
          memLimitBytes: r.memLimitBytes ?? null,
        }));
    },
    pruneOldResourceSamples({ olderThan }) {
      pruneResourceSamplesStmt.run({ olderThan });
    },
    insertAiTrafficAnalysis({
      containerId,
      containerName,
      baselineAvgRx,
      baselineMaxRx,
      latestRxRateBytesPerSec,
      latestTxRateBytesPerSec,
      rxBytesDelta,
      txBytesDelta,
      attack,
      confidence,
      reason,
      logsTail,
      metadata,
    }) {
      insertAiAnalysisStmt.run({
        createdAt: new Date().toISOString(),
        containerId,
        containerName: containerName ?? null,
        baselineAvgRx: baselineAvgRx ?? null,
        baselineMaxRx: baselineMaxRx ?? null,
        latestRxRateBytesPerSec: latestRxRateBytesPerSec ?? null,
        latestTxRateBytesPerSec: latestTxRateBytesPerSec ?? null,
        rxBytesDelta: rxBytesDelta ?? null,
        txBytesDelta: txBytesDelta ?? null,
        attack: attack ? 1 : 0,
        confidence: confidence ?? null,
        reason: reason ?? null,
        logsTail: logsTail ?? null,
        metadata: metadata ? JSON.stringify(metadata) : null,
      });
    },
    listRecentAiAnalyses({ containerId, limit }) {
      const rows = listRecentAiAnalysesStmt.all({ containerId, limit: limit ?? 20 });
      return rows.map((r) => ({
        id: r.id,
        createdAt: r.createdAt,
        containerId: r.containerId,
        containerName: r.containerName,
        baselineAvgRx: r.baselineAvgRx,
        baselineMaxRx: r.baselineMaxRx,
        latestRxRateBytesPerSec: r.latestRxRateBytesPerSec,
        latestTxRateBytesPerSec: r.latestTxRateBytesPerSec,
        rxBytesDelta: r.rxBytesDelta,
        txBytesDelta: r.txBytesDelta,
        attack: r.attack === 1,
        confidence: r.confidence,
        reason: r.reason,
        logsTail: r.logsTail,
        metadata: r.metadata ? JSON.parse(r.metadata) : null,
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
    insertDockerAuditEvent({
      createdAt,
      containerId,
      containerName,
      action,
      type,
      scope,
      status,
      actor,
      message,
      metadata,
    }) {
      insertDockerAuditEventStmt.run({
        createdAt: createdAt ?? new Date().toISOString(),
        containerId: containerId ?? null,
        containerName: containerName ?? null,
        action: action ?? null,
        type: type ?? null,
        scope: scope ?? null,
        status: status ?? null,
        actor: actor ?? null,
        message: message ?? null,
        metadata: metadata ? JSON.stringify(metadata) : null,
      });
    },
    listRecentDockerAuditEvents({ limit }) {
      const rows = listRecentDockerAuditEventsStmt.all({ limit: limit ?? 50 });
      return rows
        .map((r) => ({
          id: r.id,
          createdAt: r.createdAt,
          containerId: r.containerId,
          containerName: r.containerName,
          action: r.action,
          type: r.type,
          scope: r.scope,
          status: r.status,
          actor: r.actor,
          message: r.message,
          metadata: r.metadata ? JSON.parse(r.metadata) : null,
        }))
        .reverse();
    },
    pruneOldDockerAuditEvents({ olderThan }) {
      pruneDockerAuditEventsStmt.run({ olderThan });
    },
  };
}

module.exports = { initTrafficTables, createTrafficStore };


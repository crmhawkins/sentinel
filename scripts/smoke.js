/**
 * Pruebas sin Docker: config + SQLite (trafficStore) + lectura de eventos.
 * Ejecutar desde la raíz: node scripts/smoke.js
 */
const path = require("path");
process.chdir(path.join(__dirname, ".."));

const { loadConfig } = require("../config");
const { initDb, createAlertStore } = require("../alertStore");
const { initTrafficTables, createTrafficStore } = require("../trafficStore");

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

async function main() {
  const cfg = loadConfig();
  assert(typeof cfg.listenPort === "number", "config.listenPort");

  const db = initDb();
  createAlertStore(db);
  initTrafficTables(db);
  const trafficStore = createTrafficStore(db);

  const tag = `smoke-${Date.now()}`;
  trafficStore.insertDockerAuditEvent({
    createdAt: new Date().toISOString(),
    containerId: tag,
    containerName: "smoke",
    action: "test",
    type: "container",
    scope: "local",
    status: "ok",
    actor: null,
    message: "smoke-test",
    metadata: { tag },
  });

  const recent = trafficStore.listRecentDockerAuditEvents({ limit: 5 });
  assert(recent.some((e) => e.containerId === tag), "debe existir el evento insertado");

  trafficStore.insertSample({
    containerId: tag,
    containerName: "smoke",
    rxRateBytesPerSec: 1,
    txRateBytesPerSec: 1,
    rxBytesDelta: 1,
    txBytesDelta: 1,
  });
  const samples = trafficStore.listRecentSamples({ containerId: tag, limit: 3 });
  assert(samples.length >= 1, "traffic sample");

  trafficStore.insertResourceSample({
    containerId: tag,
    containerName: "smoke",
    cpuPercent: 1.5,
    memUsageBytes: 1000,
    memLimitBytes: 2000,
  });
  const resSamples = trafficStore.listRecentResourceSamples({ containerId: tag, limit: 3 });
  assert(resSamples.length >= 1, "resource sample");

  console.log("smoke: OK (config + SQLite trafficStore)");
}

main().catch((e) => {
  console.error("smoke: FAIL", e.message);
  process.exit(1);
});

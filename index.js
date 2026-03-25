const { loadConfig } = require("./config");
const { initDb, createAlertStore } = require("./alertStore");
const { createAlertEngine } = require("./alertEngine");
const { createWebServer } = require("./server");
const { createDockerMonitor } = require("./dockerMonitor");
const { createFsMonitor } = require("./fsMonitor");
const { initTrafficTables, createTrafficStore } = require("./trafficStore");
const { buildWatchPathsForCoolifySites } = require("./siteFilesystem");
const Docker = require("dockerode");
const pino = require("pino");

const logger = pino({ name: "sv-monitor", level: process.env.LOG_LEVEL || "info" });

async function main() {
  const config = loadConfig();

  const db = initDb();
  const alertStore = createAlertStore(db);
  initTrafficTables(db);
  const trafficStore = createTrafficStore(db);

  const state = {
    containers: [],
    spikes: [],
    fileEvents: [],
    trafficByContainerId: {},
  };

  function getAndSetState(patch) {
    if (patch && typeof patch === "object") Object.assign(state, patch);
    return state;
  }

  const web = createWebServer({
    config,
    getState: () => state,
    alertStore,
    trafficStore,
  });

  web.server.listen(config.listenPort, () => {
    logger.info({ port: config.listenPort }, "Panel web escuchando");
  });

  const cooldownMsDefault = config.alerts?.dedupeCooldownMs ?? 5 * 60_000;
  const alertEngine = createAlertEngine({
    alertStore,
    io: web.io,
    cooldownMsDefault,
  });

  // Monitor Docker (tráfico/uptime)
  const dockerSocketPath =
    process.env.DOCKER_SOCKET_PATH ||
    (process.platform === "win32" ? "\\\\.\\pipe\\dockerDesktopLinuxEngine" : "/var/run/docker.sock");

  // Permite monitorizar un Docker remoto si configuras DOCKER_HOST=tcp://IP:2375 (sin TLS).
  // Si DOCKER_HOST está definido, ignoramos socketPath.
  let dockerOptions = { socketPath: dockerSocketPath };
  try {
    const dockerHost = process.env.DOCKER_HOST;
    if (dockerHost) {
      // Ejemplo: tcp://192.168.1.10:2375
      const u = new URL(dockerHost);
      const protocol = u.protocol.replace(":", "");
      dockerOptions = { host: u.hostname, port: Number(u.port), protocol };
    }
  } catch {
    // Si no se puede parsear DOCKER_HOST, nos quedamos con socketPath.
  }

  const dockerMonitor = createDockerMonitor({
    alertEngine,
    trafficStore,
    dockerOptions,
    pollIntervalMs: config.docker?.pollIntervalMs ?? 5000,
    networkSpikeCfg: config.docker?.networkSpike ?? {},
    trafficCfg: config.traffic ?? {},
    quarantineCfg: config.quarantine ?? {},
    aiCfg: config.ai ?? {},
    getAndSetState,
    config,
  });

  // Monitor filesystem (integridad básica)
  let fsMonitor = null;

  // Arrancamos inmediatamente el monitor Docker.
  dockerMonitor.start();

  // Construimos watchPaths (si no hay) de forma asíncrona.
  (async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    while (true) {
      try {
        let watchPaths = config.filesystem?.watchPaths || [];
        if (watchPaths.length === 0) {
          const dockerForFs = new Docker(dockerOptions);
          watchPaths = await buildWatchPathsForCoolifySites({ docker: dockerForFs, config });
        }

        if (watchPaths.length > 0) {
          fsMonitor = createFsMonitor({
            alertEngine,
            alertStore,
            watchPaths,
            scanIntervalMs: config.filesystem.scanIntervalMs,
            maxFileSizeBytes: config.filesystem.maxFileSizeBytes,
            hashAlgorithm: config.filesystem.hashAlgorithm,
            getAndSetState,
            alertOnFirstSeen: false,
            ignoreGlobs: config.filesystem.ignoreGlobs ?? [],
            profiles: config.filesystem.profiles ?? {},
          });
          fsMonitor.start();
          logger.info({ watchPaths: watchPaths.length }, "fsMonitor iniciado");
          break;
        }

        logger.warn("No se encontraron rutas para monitorizar en filesystem (watchPaths vacío). Reintentando...");
      } catch (e) {
        logger.warn({ err: e?.message ?? String(e) }, "Error inicializando fsMonitor (se reintentará)");
      }

      await sleep(60_000);
    }
  })();

  process.on("SIGINT", () => {
    logger.info("Cerrando...");
    try {
      dockerMonitor.stop?.();
    } catch {}
    try {
      fsMonitor?.stop?.();
    } catch {}
    try {
      web.io?.close?.();
    } catch {}
    process.exit(0);
  });

  logger.info(
    {
      dockerSocketPath,
      dockerHost: process.env.DOCKER_HOST || null,
      listenPort: config.listenPort,
    },
    "SV Monitor inicializado"
  );
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error("Fatal:", e?.message ?? String(e));
  process.exit(1);
});


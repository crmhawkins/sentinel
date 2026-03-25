const Docker = require("dockerode");

function safeJsonParse(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function createDockerEventsMonitor({ trafficStore, dockerOptions, getAndSetState, config }) {
  const docker = new Docker(dockerOptions);

  let running = false;
  let timer = null;

  const dockerEventsCfg = config?.docker?.events ?? {};
  const sinceSeconds = dockerEventsCfg.sinceSeconds ?? 60;
  const pruneEveryMs = dockerEventsCfg.pruneEveryMs ?? 5 * 60_000;
  const retentionHours = dockerEventsCfg.retentionHours ?? 24;

  async function pruneLoop() {
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      try {
        const olderThan = new Date(Date.now() - retentionHours * 60 * 60_000).toISOString();
        trafficStore?.pruneOldDockerAuditEvents({ olderThan });
      } catch {
        // ignore
      }
    }, pruneEveryMs);
  }

  async function connectAndStream() {
    const since = Math.floor(Date.now() / 1000) - sinceSeconds;
    const filters = { type: ["container", "network", "image"] };

    const stream = await docker.getEvents({ since, filters });
    stream.setEncoding("utf8");

    let buf = "";
    stream.on("data", (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        const ev = safeJsonParse(line);
        if (!ev) continue;
        handleEvent(ev).catch(() => {});
      }
    });

    stream.on("end", () => {
      if (!running) return;
      setTimeout(() => connectAndStream().catch(() => {}), 2000);
    });

    stream.on("error", () => {
      if (!running) return;
      setTimeout(() => connectAndStream().catch(() => {}), 5000);
    });
  }

  async function handleEvent(ev) {
    const state = getAndSetState();
    const containers = state.containers || [];
    const containerId = ev?.id || ev?.ID || null;
    const containerName = containers.find((c) => c?.id === containerId)?.name ?? null;

    const createdAt = ev?.time ? new Date(Number(ev.time) * 1000).toISOString() : new Date().toISOString();
    const action = ev?.Action ?? ev?.action ?? null;
    const type = ev?.Type ?? ev?.type ?? null;
    const scope = ev?.scope ?? null;
    const status = ev?.status ?? ev?.Status ?? null;
    const actor = ev?.Actor ? JSON.stringify(ev.Actor) : null;
    const message = `${type ?? "event"}:${action ?? "unknown"}`;

    trafficStore?.insertDockerAuditEvent({
      createdAt,
      containerId,
      containerName,
      action,
      type,
      scope,
      status,
      actor,
      message,
      metadata: ev,
    });

    // Actualiza panel con eventos recientes (limit cap).
    state.dockerEvents = state.dockerEvents || [];
    state.dockerEvents.unshift({
      createdAt,
      containerId,
      containerName,
      action,
      type,
      status,
      actor,
      message,
    });
    state.dockerEvents = state.dockerEvents.slice(0, 200);
  }

  function start() {
    if (running) return;
    running = true;
    connectAndStream().catch(() => {});
    pruneLoop().catch(() => {});
  }

  function stop() {
    running = false;
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { start, stop };
}

module.exports = { createDockerEventsMonitor };


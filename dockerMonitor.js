const Docker = require("dockerode");

function safeName(name) {
  // dockerode names often look like "/mi-contenedor"
  return (name || "").replace(/^\//, "");
}

function nowMs() {
  return Date.now();
}

function createRingBuffer(maxSize) {
  const arr = [];
  return {
    push(v) {
      arr.push(v);
      if (arr.length > maxSize) arr.shift();
    },
    values() {
      return arr.slice();
    },
    sum() {
      return arr.reduce((a, b) => a + b, 0);
    },
    get length() {
      return arr.length;
    },
  };
}

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr, m) {
  if (arr.length < 2) return 0;
  const variance = arr.reduce((acc, x) => acc + Math.pow(x - m, 2), 0) / (arr.length - 1);
  return Math.sqrt(variance);
}

function computeCpuPercent(stats) {
  const cpu = stats?.cpu_stats;
  const precpu = stats?.precpu_stats;
  if (!cpu || !precpu) return null;

  const cpuTotal = cpu?.cpu_usage?.total_usage;
  const prevCpuTotal = precpu?.cpu_usage?.total_usage;
  const systemTotal = cpu?.system_cpu_usage;
  const prevSystemTotal = precpu?.system_cpu_usage;
  if (![cpuTotal, prevCpuTotal, systemTotal, prevSystemTotal].every((v) => Number.isFinite(Number(v)))) return null;

  const cpuDelta = Number(cpuTotal) - Number(prevCpuTotal);
  const systemDelta = Number(systemTotal) - Number(prevSystemTotal);
  if (systemDelta <= 0) return null;

  const onlineCpus = Number(cpu?.online_cpus ?? (cpu?.cpu_usage?.percpu_usage?.length || 0));
  if (!Number.isFinite(onlineCpus) || onlineCpus <= 0) return null;

  return (cpuDelta / systemDelta) * onlineCpus * 100;
}

function hasAnyLabel(labelObj, substrings) {
  if (!labelObj) return false;
  const entries = Object.entries(labelObj);
  return entries.some(([k, v]) => {
    const combo = `${k}:${v}`;
    return substrings.some((s) => combo.toLowerCase().includes(s.toLowerCase()));
  });
}

function getExposedPortsFromInspect(inspect) {
  const ports = new Set();
  const exposed = inspect?.Config?.ExposedPorts || {};
  for (const key of Object.keys(exposed)) {
    const port = Number(String(key).split("/")[0]);
    if (Number.isFinite(port)) ports.add(port);
  }
  // NetworkSettings.Ports can also indicate bound ports, but we focus on exposed config.
  return [...ports];
}

function isLikelyWebSiteContainer({ name, inspect, config }) {
  const lcName = (name || "").toLowerCase();
  const includes = config?.docker?.sites?.nameIncludes ?? ["coolify", "app", "site", "web"];
  const exposedMin = config?.docker?.sites?.minExposedPort ?? [80, 443];

  const byName = includes.some((s) => lcName.includes(String(s).toLowerCase()));
  const byLabels = hasAnyLabel(inspect?.Config?.Labels, ["coolify", "traefik", "nginx", "caddy", "label"]);

  const exposedPorts = getExposedPortsFromInspect(inspect);
  const byPorts = exposedPorts.some((p) => exposedMin.includes(p));

  return Boolean(byName || byLabels || byPorts);
}

async function readDockerLogsTail(docker, containerId, tail) {
  const container = docker.getContainer(containerId);
  const stream = await container.logs({
    follow: false,
    stdout: true,
    stderr: true,
    tail: tail ?? 200,
    timestamps: true,
  });

  return new Promise((resolve, reject) => {
    let data = "";
    stream.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    stream.on("end", () => resolve(data));
    stream.on("error", (e) => reject(e));
  });
}

function createDockerMonitor({
  alertEngine,
  trafficStore,
  dockerOptions,
  pollIntervalMs,
  networkSpikeCfg,
  trafficCfg,
  quarantineCfg,
  aiCfg,
  getAndSetState,
  config,
  logger,
}) {
  const docker = new Docker(dockerOptions);

  const historySize = networkSpikeCfg?.historySize ?? 30;
  const zScoreThreshold = networkSpikeCfg?.zScoreThreshold ?? 3.5;
  const minStdBytesPerSec = networkSpikeCfg?.minStdBytesPerSec ?? 50 * 1024;

  const trafficBaselineWindowHours = trafficCfg?.baselineWindowHours ?? 24;
  const suspectMultiplierOverAvg = trafficCfg?.suspectMultiplierOverAvg ?? 40;
  const suspectMultiplierOverPeak = trafficCfg?.suspectMultiplierOverPeak ?? 10;
  const quarantineMultiplierOverAvg = trafficCfg?.quarantineMultiplierOverAvg ?? 300;
  const sampleWindowSecForRate = trafficCfg?.sampleWindowSecForRate ?? 60;
  const quarantineCooldownMs = trafficCfg?.quarantineCooldownMs ?? 30 * 60_000;
  const recentTrafficLimit = trafficCfg?.recentTrafficLimit ?? 200;

  const quarantineEnabled = quarantineCfg?.enabled ?? true;
  const publicNetworkNameRegex = quarantineCfg?.publicNetworkNameRegex ?? "(traefik|coolify|proxy|public|edge|web)";
  const releaseAfterMs = quarantineCfg?.releaseAfterMs ?? 60 * 60_000;

  // prev totals => delta rates
  const prevNet = new Map(); // key: `${containerId}:${iface}` => { ts, rx, tx }
  // baseline rates history for z-score (interface-level)
  const baselineHist = new Map(); // key: `${containerId}:${iface}:${dir}` => RingBuffer

  // Rolling window for container-level average rate
  const windowPolls = Math.max(3, Math.round((sampleWindowSecForRate * 1000) / pollIntervalMs));
  const windowByContainerId = new Map(); // id => { rxBuf, txBuf }
  const lastDecisionAt = new Map(); // id => ts

  let running = false;
  let timer = null;

  async function classifyAndMaybeQuarantine({ containerId, containerName, baseline, latestWindow, latestPoll, logsTail }) {
    const aiEnabled = !!aiCfg?.enabled;
    const apiKey = process.env[aiCfg?.apiKeyEnv] || null;
    const aiModel = aiCfg?.model || "";

    // Si la IA no está configurada, priorizamos disponibilidad pero marcamos razón.
    if (aiEnabled && apiKey) {
      const { analyzeTrafficWithAi } = require("./aiClient");
      return await analyzeTrafficWithAi({
        aiBaseUrl: aiCfg.baseUrl,
        aiModel,
        apiKey,
        timeoutMs: aiCfg.timeoutMs ?? 60_000,
        containerName,
        containerId,
        baseline,
        latest: latestWindow,
        logsTail,
      });
    }

    return { attack: true, confidence: 0.2, reason: "IA no configurada; aplicando cuarentena por umbral" };
  }

  async function pollOnce() {
    const state = getAndSetState();
    const latestContainers = [];

    // Para baseline "down" y "recovered"
    const prevContainersById = new Map((state.containers || []).map((c) => [c.id, c]));

    let listOk = false;
    let seenCount = 0;

    try {
      const list = await docker.listContainers({ all: true });
      listOk = true;
      const seenIds = new Set();

      for (const c of list) {
      const id = c.Id;
      const name = c.Names?.[0] ? safeName(c.Names[0]) : id.slice(0, 12);
      if (!name) continue;
      if (name.toLowerCase().includes("sv-monitor")) continue;

      seenIds.add(id);
      const isRunning = c.State === "running";

      let inspect = null;
      try {
        inspect = await docker.getContainer(id).inspect();
      } catch {
        // ignore
      }

      const stateObj = inspect?.State;
      const health = stateObj?.Health?.Status ?? "unknown";

      let startedAtMs = null;
      if (stateObj?.StartedAt) {
        const parsed = Date.parse(stateObj.StartedAt);
        if (!Number.isNaN(parsed)) startedAtMs = parsed;
      }
      const uptimeSec = startedAtMs ? Math.floor((nowMs() - startedAtMs) / 1000) : null;

      latestContainers.push({
        id,
        name,
        image: c.Image,
        isRunning,
        health,
        uptimeSec,
        lastUpdatedAt: new Date().toISOString(),
      });

      // DOWN alert
      const lastKnown = prevContainersById.get(id);
      if (lastKnown && lastKnown.isRunning && !isRunning) {
        await alertEngine.raiseAlert({
          type: "container_down",
          severity: "critical",
          entityId: name,
          message: `El contenedor ${name} se ha detenido.`,
          dedupeKey: `container_down:${id}`,
          metadata: { id, name },
        });
      }

      // HEALTH recovered
      if (
        lastKnown &&
        lastKnown.isRunning &&
        isRunning &&
        lastKnown.health !== "healthy" &&
        health === "healthy"
      ) {
        await alertEngine.raiseAlert({
          type: "container_recovered",
          severity: "info",
          entityId: name,
          message: `El contenedor ${name} ha vuelto a estar healthy.`,
          dedupeKey: `container_recovered:${id}`,
          metadata: { id, name },
        });
      }

      if (!isRunning) continue;

      const isSite = isLikelyWebSiteContainer({ name, inspect, config });
      // Traffic analysis only for likely websites; still compute interface spikes for all.

      let stats = null;
      try {
        stats = await docker.getContainer(id).stats({ stream: false });
      } catch {
        continue;
      }

      const networks = stats?.networks ?? null;
      if (!networks) continue;

      const t = nowMs();
      let totalRxBytesDelta = 0;
      let totalTxBytesDelta = 0;
      let totalRxRate = 0;
      let totalTxRate = 0;

      // Interface-level zscore spikes (optional UI)
      for (const [iface, net] of Object.entries(networks)) {
        const rx = Number(net?.rx_bytes ?? 0);
        const tx = Number(net?.tx_bytes ?? 0);
        if (!Number.isFinite(rx) || !Number.isFinite(tx)) continue;

        const prevKey = `${id}:${iface}`;
        const prev = prevNet.get(prevKey);
        prevNet.set(prevKey, { ts: t, rx, tx });
        if (!prev) continue;

        const dtSec = (t - prev.ts) / 1000;
        if (dtSec <= 0.01) continue;

        const rxDelta = Math.max(0, rx - prev.rx);
        const txDelta = Math.max(0, tx - prev.tx);

        const rxRate = rxDelta / dtSec;
        const txRate = txDelta / dtSec;

        totalRxBytesDelta += rxDelta;
        totalTxBytesDelta += txDelta;
        totalRxRate += rxRate;
        totalTxRate += txRate;

        // z-score per interface
        const ifaceKeyRx = `${id}:${iface}:rx`;
        const ifaceKeyTx = `${id}:${iface}:tx`;
        if (!baselineHist.has(ifaceKeyRx)) baselineHist.set(ifaceKeyRx, createRingBuffer(historySize));
        if (!baselineHist.has(ifaceKeyTx)) baselineHist.set(ifaceKeyTx, createRingBuffer(historySize));

        const histRx = baselineHist.get(ifaceKeyRx);
        const histTx = baselineHist.get(ifaceKeyTx);

        const mRx = mean(histRx.values());
        const sRx = stddev(histRx.values(), mRx);
        const mTx = mean(histTx.values());
        const sTx = stddev(histTx.values(), mTx);

        const shouldAlertRx = histRx.length >= Math.min(10, historySize - 1) && sRx >= minStdBytesPerSec;
        const shouldAlertTx = histTx.length >= Math.min(10, historySize - 1) && sTx >= minStdBytesPerSec;

        if (shouldAlertRx && rxRate > mRx + zScoreThreshold * sRx) {
          const spike = {
            at: new Date().toISOString(),
            type: "traffic_spike",
            entityId: name,
            containerId: id,
            iface,
            direction: "rx",
            rateBytesPerSec: rxRate,
            baselineMean: mRx,
            baselineStd: sRx,
          };
          state.spikes = state.spikes || [];
          state.spikes.unshift(spike);
          state.spikes.splice(200);
          await alertEngine.raiseAlert({
            type: "traffic_spike",
            severity: "warning",
            entityId: name,
            dedupeKey: `traffic_spike:${id}:${iface}:rx`,
            message: `Pico de tráfico RX en ${name} (${iface})`,
            metadata: spike,
            cooldownMs: 60_000,
          });
        }

        if (shouldAlertTx && txRate > mTx + zScoreThreshold * sTx) {
          const spike = {
            at: new Date().toISOString(),
            type: "traffic_spike",
            entityId: name,
            containerId: id,
            iface,
            direction: "tx",
            rateBytesPerSec: txRate,
            baselineMean: mTx,
            baselineStd: sTx,
          };
          state.spikes = state.spikes || [];
          state.spikes.unshift(spike);
          state.spikes.splice(200);
          await alertEngine.raiseAlert({
            type: "traffic_spike",
            severity: "warning",
            entityId: name,
            dedupeKey: `traffic_spike:${id}:${iface}:tx`,
            message: `Pico de tráfico TX en ${name} (${iface})`,
            metadata: spike,
            cooldownMs: 60_000,
          });
        }

        histRx.push(rxRate);
        histTx.push(txRate);
      }

      // Rolling window (container-level)
      if (isSite) {
        if (!windowByContainerId.has(id)) {
          windowByContainerId.set(id, {
            rxBuf: createRingBuffer(windowPolls),
            txBuf: createRingBuffer(windowPolls),
          });
        }
        const win = windowByContainerId.get(id);
        win.rxBuf.push(totalRxBytesDelta);
        win.txBuf.push(totalTxBytesDelta);

        const windowSec = sampleWindowSecForRate;
        const windowRxBytes = win.rxBuf.sum();
        const windowTxBytes = win.txBuf.sum();
        const latestWindowRxRate = windowRxBytes / windowSec;
        const latestWindowTxRate = windowTxBytes / windowSec;

        // Recursos (CPU/Mem) para correlacionar con picos y decisiones de seguridad.
        if (trafficStore) {
          try {
            trafficStore.insertResourceSample({
              containerId: id,
              containerName: name,
              cpuPercent: computeCpuPercent(stats),
              memUsageBytes: stats?.memory_stats?.usage ?? null,
              memLimitBytes: stats?.memory_stats?.limit ?? null,
            });
          } catch {
            // ignore
          }
        }

        // Persist samples (para panel/baseline 24h)
        if (trafficStore) {
          try {
            trafficStore.insertSample({
              containerId: id,
              containerName: name,
              rxRateBytesPerSec: totalRxRate,
              txRateBytesPerSec: totalTxRate,
              rxBytesDelta: totalRxBytesDelta,
              txBytesDelta: totalTxBytesDelta,
            });
          } catch {
            // ignore
          }
        }

        // Cleanup retention
        if (trafficStore && trafficCfg?.sampleRetentionHours) {
          const olderThan = new Date(Date.now() - trafficCfg.sampleRetentionHours * 60 * 60_000).toISOString();
          try {
            trafficStore.pruneOldSamples({ olderThan });
            trafficStore.pruneOldResourceSamples({ olderThan });
          } catch {
            // ignore
          }
        }

        const baselineFromAt = new Date(Date.now() - trafficBaselineWindowHours * 60 * 60_000).toISOString();
        const baselineAgg = trafficStore?.getBaselineAgg({ containerId: id, fromAt: baselineFromAt }) || null;
        const baselineAvg = baselineAgg?.avgRx ?? null;
        const baselineMax = baselineAgg?.maxRx ?? null;
        const samplesCount = baselineAgg?.samples ?? 0;

        // Necesitamos suficiente histórico para comparar.
        if (samplesCount < 5 || !Number.isFinite(baselineAvg) || baselineAvg <= 0) {
          state.trafficByContainerId[id] = {
            latestRxRateBytesPerSec: latestWindowRxRate,
            baselineAvgRx: baselineAvg,
            baselineMaxRx: baselineMax,
            decision: "warming",
            at: new Date().toISOString(),
          };
          continue;
        }

        const overAvg = latestWindowRxRate > baselineAvg * suspectMultiplierOverAvg;
        const overPeak = Number.isFinite(baselineMax) && latestWindowRxRate > baselineMax * suspectMultiplierOverPeak;
        const suspicious = overAvg || overPeak;

        // Actualizamos estado siempre
        state.trafficByContainerId[id] = {
          latestRxRateBytesPerSec: latestWindowRxRate,
          baselineAvgRx: baselineAvg,
          baselineMaxRx: baselineMax,
          decision: suspicious ? "suspicious" : "ok",
          at: new Date().toISOString(),
        };

        if (!suspicious) continue;

        // Rate-limit de decisiones de cuarentena/sospecha
        const lastAt = lastDecisionAt.get(id) ?? 0;
        if (Date.now() - lastAt < 10_000) continue; // evita spam por múltiples interfaces/polls
        lastDecisionAt.set(id, Date.now());

        await alertEngine.raiseAlert({
          type: "traffic_suspicious",
          severity: "warning",
          entityId: name,
          dedupeKey: `traffic_suspicious:${id}`,
          cooldownMs: 10 * 60_000,
          message: `Tráfico sospechoso en ${name}: rx approx ${Math.round(latestWindowRxRate / (1024 * 1024))} MB/s (baseline 24h avg=${Math.round(baselineAvg / (1024 * 1024))} MB/s, max=${Math.round((baselineMax ?? 0) / (1024 * 1024))} MB/s).`,
          metadata: {
            containerId: id,
            latestWindowRxRateBytesPerSec: latestWindowRxRate,
            baselineAvgRxBytesPerSec: baselineAvg,
            baselineMaxRxBytesPerSec: baselineMax,
            rxBytesWindow: windowRxBytes,
            windowTxBytes,
          },
        });

        const shouldQuarantine = quarantineEnabled && latestWindowRxRate > baselineAvg * quarantineMultiplierOverAvg;
        if (!shouldQuarantine) continue;

        // Quarantine cooldown guard
        const lastQAt = state.trafficByContainerId[id]?.quarantinedAt ?? 0;
        if (Date.now() - lastQAt < quarantineCooldownMs) continue;

        await alertEngine.raiseAlert({
          type: "traffic_quarantine_pending",
          severity: "critical",
          entityId: name,
          dedupeKey: `traffic_quarantine_pending:${id}`,
          cooldownMs: quarantineCooldownMs,
          message: `Umbral crítico alcanzado en ${name}. Analizando con IA y aplicando cuarentena si procede.`,
          metadata: {
            containerId: id,
            latestWindowRxRateBytesPerSec: latestWindowRxRate,
            baselineAvgRxBytesPerSec: baselineAvg,
            baselineMaxRxBytesPerSec: baselineMax,
          },
        });

        // IA analiza con logs
        let logsTail = "";
        try {
          logsTail = await readDockerLogsTail(docker, id, 200);
        } catch {
          logsTail = "";
        }

        const decision = await classifyAndMaybeQuarantine({
          containerId: id,
          containerName: name,
          baseline: { avgRx: baselineAvg, maxRx: baselineMax },
          latestWindow: {
            rxRateBytesPerSec: latestWindowRxRate,
            txRateBytesPerSec: latestWindowTxRate,
            rxBytesDelta: totalRxBytesDelta,
            txBytesDelta: totalTxBytesDelta,
          },
          latestPoll: {
            rxRateBytesPerSec: totalRxRate,
            txRateBytesPerSec: totalTxRate,
            rxBytesDelta: totalRxBytesDelta,
            txBytesDelta: totalTxBytesDelta,
          },
          logsTail,
        });

        const attack = !!decision?.attack;

        // Guardamos la evidencia/decisión de la IA para auditoría.
        if (trafficStore) {
          try {
            trafficStore.insertAiTrafficAnalysis({
              containerId: id,
              containerName: name,
              baselineAvgRx: baselineAvg,
              baselineMaxRx: baselineMax,
              latestRxRateBytesPerSec: latestWindowRxRate,
              latestTxRateBytesPerSec: latestWindowTxRate,
              rxBytesDelta: totalRxBytesDelta,
              txBytesDelta: totalTxBytesDelta,
              attack,
              confidence: decision?.confidence ?? null,
              reason: decision?.reason ?? null,
              logsTail,
              metadata: { latestPoll: { rxRateBytesPerSec: totalRxRate, txRateBytesPerSec: totalTxRate }, decision },
            });
          } catch {
            // ignore
          }
        }

        if (!attack) {
          state.trafficByContainerId[id] = {
            ...state.trafficByContainerId[id],
            decision: "legit",
            analysis: decision,
            quarantinedAt: 0,
            at: new Date().toISOString(),
          };
          await alertEngine.raiseAlert({
            type: "traffic_legitimate",
            severity: "info",
            entityId: name,
            dedupeKey: `traffic_legitimate:${id}`,
            cooldownMs: 30 * 60_000,
            message: `El pico de tráfico en ${name} parece legítimo (IA: confidence=${decision?.confidence ?? 0}).`,
            metadata: { decision },
          });
          continue;
        }

        // Aplica cuarentena
        if (trafficStore) {
          const { quarantineContainer } = require("./quarantineService");
          const q = await quarantineContainer({
            docker,
            containerId: id,
            containerName: name,
            publicNetworkNameRegex,
            releaseAfterMs: releaseAfterMs,
            trafficStore,
            trafficDecisionReason: decision?.reason ?? "",
            trafficDecisionText: "quarantined",
          });

          state.trafficByContainerId[id] = {
            ...state.trafficByContainerId[id],
            decision: "quarantined",
            analysis: decision,
            quarantinedAt: Date.now(),
            quarantine: q,
            at: new Date().toISOString(),
          };

          await alertEngine.raiseAlert({
            type: "traffic_quarantined",
            severity: "critical",
            entityId: name,
            dedupeKey: `traffic_quarantined:${id}`,
            cooldownMs: quarantineCooldownMs,
            message: `Cuarentena aplicada a ${name} por tráfico crítico.`,
            metadata: { decision, quarantine: q },
          });
        }
      }
    }

      seenCount = seenIds.size;
    } finally {
      // Si el bucle de tráfico/IA/cuarentena lanza, igual publicamos la lista ya recopilada.
      if (listOk) {
        getAndSetState({ containers: latestContainers });
      }
    }

    return { seen: seenCount };
  }

  function start() {
    if (running) return;
    running = true;
    const onErr = (e) => {
      const msg = e?.message ?? String(e);
      if (logger) logger.warn({ err: msg }, "dockerMonitor: pollOnce falló (¿socket Docker o permisos?)");
      else console.error("dockerMonitor: pollOnce falló", msg);
    };
    pollOnce().catch(onErr);
    timer = setInterval(() => {
      pollOnce().catch(onErr);
    }, pollIntervalMs);
  }

  function stop() {
    running = false;
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { start, stop };
}

module.exports = { createDockerMonitor };


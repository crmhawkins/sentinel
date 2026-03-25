const pino = require("pino");

function getName(network) {
  return network?.Name || network?.name || "";
}

function normalizeRegexStr(s) {
  return typeof s === "string" ? s.trim() : "";
}

async function quarantineContainer({
  docker,
  containerId,
  containerName,
  publicNetworkNameRegex,
  releaseAfterMs,
  trafficDecisionReason,
  trafficDecisionText,
  trafficStore,
  cooldownGuard,
}) {
  const logger = pino({ name: "quarantine-service", level: process.env.LOG_LEVEL || "info" });

  const regexStr = normalizeRegexStr(publicNetworkNameRegex);
  const networkRegex = regexStr ? new RegExp(regexStr, "i") : null;

  const inspect = await docker.getContainer(containerId).inspect();
  const connectedNetworks = inspect?.NetworkSettings?.Networks || {};

  const listNetworks = await docker.listNetworks();
  const networksById = new Map(listNetworks.map((n) => [n.Id, n]));
  const networksByName = new Map(listNetworks.map((n) => [n.Name, n]));

  const toDisconnect = [];
  for (const [netName, netObj] of Object.entries(connectedNetworks)) {
    const networkId = netObj?.NetworkID;
    const network = networksByName.get(netName) || (networkId ? networksById.get(networkId) : null);
    const candidateName = getName(network) || netName;
    if (!networkId) continue;
    if (networkRegex && !networkRegex.test(candidateName)) continue;
    toDisconnect.push({ networkId, netName: candidateName });
  }

  if (!toDisconnect.length) {
    logger.warn({ containerId }, "No networks matched quarantine regex; skipping disconnect.");
    return { quarantined: false, networksDisconnected: [] };
  }

  // Disconnect from selected networks
  for (const n of toDisconnect) {
    const network = docker.getNetwork(n.networkId);
    try {
      await network.disconnect({ container: containerId, force: true });
    } catch (e) {
      logger.warn({ containerId, networkId: n.networkId, err: e?.message }, "Disconnect failed (continuing)");
    }
  }

  // Record action
  const releaseAt = new Date(Date.now() + (releaseAfterMs ?? 60 * 60_000)).toISOString();
  if (trafficStore?.insertQuarantineAction) {
    trafficStore.insertQuarantineAction({
      containerId,
      containerName,
      decision: trafficDecisionText,
      reason: trafficDecisionReason ?? "",
      networksDisconnected: toDisconnect.map((x) => x.networkId),
      releaseAt,
    });
  }

  // We optionally re-connect later via a simple timer.
  // (Para versiones grandes, conviene un scheduler persistente.)
  if (releaseAfterMs && releaseAfterMs > 0 && trafficStore?.reconnectQuarantine) {
    setTimeout(() => {
      trafficStore.reconnectQuarantine({
        docker,
        containerId,
        networksDisconnected: toDisconnect.map((x) => x.networkId),
        containerName,
      }).catch(() => {});
    }, releaseAfterMs);
  }

  return { quarantined: true, networksDisconnected: toDisconnect.map((x) => x.networkId), releaseAt };
}

module.exports = { quarantineContainer };


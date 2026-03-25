const path = require("path");
const fs = require("fs");

function normalize(p) {
  return path.resolve(p);
}

function addIfExists(list, p) {
  try {
    if (fs.existsSync(p)) list.push(p);
  } catch {
    // ignore
  }
}

function destLooksLikeWebRoot(dest) {
  const d = String(dest || "").toLowerCase();
  return (
    d.includes("/var/www") ||
    d.includes("/www") ||
    d.endsWith("/html") ||
    d.endsWith("/htdocs") ||
    d.endsWith("/app") ||
    d.includes("/usr/src/app")
  );
}

function computeCandidateSubdirs({ dest, profiles }) {
  const d = String(dest || "").toLowerCase();
  const result = new Set();

  const laravelPaths = profiles?.laravel || [];
  const wordpressPaths = profiles?.wordpress || [];
  const nodePaths = profiles?.node || [];

  if (d.includes("wp-content") || d.includes("wordpress")) {
    for (const s of wordpressPaths) result.add(s);
  }

  if (d.includes("wp-") || d.includes("wordpress")) {
    for (const s of wordpressPaths) result.add(s);
  }

  if (d.includes("/var/www") || d.includes("/html") || d.endsWith("/app") || d.includes("/usr/src/app")) {
    // Si parece root, añadimos varios subdirs típicos.
    for (const s of laravelPaths) result.add(s);
    for (const s of wordpressPaths) result.add(s);
    for (const s of nodePaths) result.add(s);
  }

  // También: si el mount destination coincide con un subdir conocido, lo incluimos tal cual.
  for (const s of [...laravelPaths, ...wordpressPaths, ...nodePaths]) {
    if (d.includes(String(s).toLowerCase())) result.add(s);
  }

  return [...result];
}

async function buildWatchPathsForCoolifySites({ docker, config }) {
  const watchPaths = [];
  const sitesCfg = config?.docker?.sites ?? {};
  const includes = sitesCfg.nameIncludes ?? ["coolify", "app", "site", "web"];
  const minExposedPort = sitesCfg.minExposedPort ?? [80, 443];

  const containers = await docker.listContainers({ all: true });
  for (const c of containers) {
    if (c.State !== "running") continue;
    const id = c.Id;
    const name = c.Names?.[0] ? String(c.Names[0]).replace(/^\//, "") : id.slice(0, 12);
    if (!name) continue;
    if (name.toLowerCase().includes("sv-monitor")) continue;

    const inspect = await docker.getContainer(id).inspect().catch(() => null);
    if (!inspect) continue;

    const lcName = name.toLowerCase();
    const exposedPorts = [];
    const exposed = inspect?.Config?.ExposedPorts || {};
    for (const key of Object.keys(exposed)) {
      const port = Number(String(key).split("/")[0]);
      if (Number.isFinite(port)) exposedPorts.push(port);
    }

    const byName = includes.some((s) => lcName.includes(String(s).toLowerCase()));
    const byPorts = exposedPorts.some((p) => minExposedPort.includes(p));
    const byLabel = inspect?.Config?.Labels
      ? Object.entries(inspect.Config.Labels).some(([k, v]) => `${k}:${v}`.toLowerCase().includes("coolify"))
      : false;

    const isSite = Boolean(byName || byPorts || byLabel);
    if (!isSite) continue;

    const mounts = inspect?.Mounts || [];
    for (const m of mounts) {
      const src = m?.Source;
      const dest = m?.Destination;
      if (!src || !dest) continue;

      if (!destLooksLikeWebRoot(dest) && !String(dest).toLowerCase().includes("wp-content") && !String(dest).toLowerCase().includes("app")) {
        // Si no parece relevante, no lo añadimos para no disparar watchers.
        continue;
      }

      const subdirs = computeCandidateSubdirs({ dest, profiles: config?.filesystem?.profiles });
      if (!subdirs.length) {
        addIfExists(watchPaths, normalize(src));
        continue;
      }
      for (const sd of subdirs) {
        const candidate = normalize(path.join(src, sd));
        addIfExists(watchPaths, candidate);
      }
      // A veces el root completo también sirve:
      if (destLooksLikeWebRoot(dest)) addIfExists(watchPaths, normalize(src));
    }
  }

  // Deduplicamos
  const uniq = [...new Set(watchPaths.map((p) => normalize(p)))];
  return uniq;
}

module.exports = { buildWatchPathsForCoolifySites };


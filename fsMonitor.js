const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const chokidar = require("chokidar");

function normalizePath(p) {
  // Normalizamos para reducir duplicados entre Windows/Linux
  return path.resolve(p);
}

function safeNumber(v) {
  if (typeof v !== "number") return null;
  if (!Number.isFinite(v)) return null;
  return v;
}

function statToFingerprint(stat, hash) {
  return {
    hash: hash ?? null,
    mtimeMs: stat?.mtimeMs ?? null,
    size: stat?.size ?? null,
    mode: safeNumber(stat?.mode),
    uid: safeNumber(stat?.uid),
    gid: safeNumber(stat?.gid),
  };
}

async function hashFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function createFsMonitor({
  alertEngine,
  alertStore,
  watchPaths,
  scanIntervalMs,
  maxFileSizeBytes,
  hashAlgorithm,
  getAndSetState,
  alertOnFirstSeen,
  ignoreGlobs,
  profiles,
}) {
  const normalizedWatch = watchPaths.map(normalizePath);

  const watcher = chokidar.watch(normalizedWatch, {
    persistent: true,
    // Solo alertamos por cambios posteriores al arranque del monitor.
    ignoreInitial: true,
    awaitWriteFinish: {
      stabilityThreshold: 800,
      pollInterval: 100,
    },
    ignored: ignoreGlobs && ignoreGlobs.length ? ignoreGlobs : undefined,
  });

  let timer = null;

  async function processFileEvent(filePath, eventType) {
    const fullPath = normalizePath(filePath);

    // Solo procesamos rutas que estén bajo watchPaths
    const underWatch = normalizedWatch.some((wp) => fullPath.startsWith(wp));
    if (!underWatch) return;

    let stat = null;
    try {
      stat = await fs.promises.lstat(fullPath);
    } catch {
      return; // archivo borrado o inaccesible
    }

    // Saltar directorios
    if (stat.isDirectory()) return;

    const prev = alertStore.getFingerprint(fullPath);
    const current = {};

    current.mtimeMs = stat.mtimeMs ?? null;
    current.size = stat.size ?? null;
    current.mode = stat.mode ?? null;
    current.uid = stat.uid ?? null;
    current.gid = stat.gid ?? null;

    let hash = null;
    const sizeOk = typeof stat.size === "number" && stat.size >= 0 && stat.size <= maxFileSizeBytes;
    if (sizeOk && hashAlgorithm === "sha256") {
      // Nota: hash para ficheros pequeños. Para grandes, solo comparamos metadata (mtime/size/perms).
      try {
        hash = await hashFileSha256(fullPath);
      } catch {
        hash = null;
      }
    }
    current.hash = hash;

    const hadPrev = !!prev;

    const shouldAlertNew = eventType === "add";

    // Permisos
    const permissionChanged =
      hadPrev &&
      ((prev.mode ?? null) !== (current.mode ?? null) ||
        (prev.uid ?? null) !== (current.uid ?? null) ||
        (prev.gid ?? null) !== (current.gid ?? null));

    // Modificación (hash si existe; si no, fallback mtime/size)
    let contentChanged = false;
    if (hadPrev) {
      if (prev.hash && current.hash) {
        contentChanged = prev.hash !== current.hash;
      } else {
        contentChanged =
          (prev.mtimeMs ?? null) !== (current.mtimeMs ?? null) || (prev.size ?? null) !== (current.size ?? null);
      }
    }
    if (!hadPrev) contentChanged = true;

    // Actualizamos baseline SIEMPRE
    alertStore.upsertFingerprint({
      path: fullPath,
      hash: current.hash,
      mtimeMs: current.mtimeMs,
      size: current.size,
      mode: current.mode,
      uid: current.uid,
      gid: current.gid,
    });

    // Emisión al panel (eventos recientes)
    const { fileEvents } = getAndSetState();
    fileEvents.unshift({
      at: new Date().toISOString(),
      path: fullPath,
      eventType,
      size: current.size,
      mode: current.mode,
      uid: current.uid,
      gid: current.gid,
      hash: current.hash,
    });
    fileEvents.splice(200);

    // Alertas
    if (shouldAlertNew) {
      await alertEngine.raiseAlert({
        type: "file_created",
        severity: "warning",
        entityId: fullPath,
        dedupeKey: `file_created:${fullPath}`,
        cooldownMs: 5 * 60_000,
        message: `Se creó un archivo nuevo: ${fullPath}`,
        metadata: { path: fullPath, size: current.size, mode: current.mode, uid: current.uid, gid: current.gid },
      });
      return;
    }

    if (permissionChanged) {
      await alertEngine.raiseAlert({
        type: "file_permissions_changed",
        severity: "critical",
        entityId: fullPath,
        dedupeKey: `file_permissions_changed:${fullPath}`,
        cooldownMs: 5 * 60_000,
        message: `Cambios de permisos detectados en: ${fullPath}`,
        metadata: { path: fullPath, prev: { mode: prev.mode, uid: prev.uid, gid: prev.gid }, curr: { mode: current.mode, uid: current.uid, gid: current.gid } },
      });
      return;
    }

    if (eventType === "change" && contentChanged) {
      await alertEngine.raiseAlert({
        type: "file_modified",
        severity: "warning",
        entityId: fullPath,
        dedupeKey: `file_modified:${fullPath}`,
        cooldownMs: 2 * 60_000,
        message: `Se modificó un archivo: ${fullPath}`,
        metadata: { path: fullPath, prev: { mtimeMs: prev.mtimeMs, size: prev.size, hash: prev.hash }, curr: { mtimeMs: current.mtimeMs, size: current.size, hash: current.hash } },
      });
      return;
    }
  }

  function start() {
    // chokidar ya escucha; lo dejamos también con un timer placeholder para futuros scans si quieres.
    if (timer) return;
    timer = setInterval(() => {
      // Escaneo periódico (por ahora vacío): mantener hook por si luego hacemos bootstrap.
    }, scanIntervalMs);

    watcher.on("add", (p) => processFileEvent(p, "add").catch(() => {}));
    watcher.on("change", (p) => processFileEvent(p, "change").catch(() => {}));
    watcher.on("addDir", () => {});
    watcher.on("unlink", (p) => {
      // Por simplicidad no generamos alertas de borrado en esta primera versión.
      const { fileEvents } = getAndSetState();
      fileEvents.unshift({ at: new Date().toISOString(), path: normalizePath(p), eventType: "unlink" });
      fileEvents.splice(200);
    });
  }

  function stop() {
    try {
      watcher.close();
    } catch {}
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { start, stop };
}

module.exports = { createFsMonitor };


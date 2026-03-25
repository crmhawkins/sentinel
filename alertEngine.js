const pino = require("pino");

function createAlertEngine({ alertStore, io, cooldownMsDefault }) {
  const logger = pino({ name: "alert-engine", level: process.env.LOG_LEVEL || "info" });

  async function raiseAlert(params) {
    const {
      type,
      severity,
      entityId,
      dedupeKey,
      message,
      metadata,
      cooldownMs,
    } = params;

    const finalCooldownMs = cooldownMs ?? cooldownMsDefault;
    const finalDedupeKey = dedupeKey ?? (entityId ? `${type}:${entityId}` : null);

    if (alertStore.shouldDedupe({ type, dedupeKey: finalDedupeKey, cooldownMs: finalCooldownMs })) {
      logger.debug(
        { type, severity, entityId, dedupeKey: finalDedupeKey, cooldownMs: finalCooldownMs },
        "Alerta deduplicada"
      );
      return { deduped: true };
    }

    alertStore.insertAlert({
      type,
      severity: severity ?? "warning",
      entityId: entityId ?? null,
      dedupeKey: finalDedupeKey ?? null,
      message: message ?? "",
      metadata,
    });

    const alert = {
      type,
      severity: severity ?? "warning",
      entityId: entityId ?? null,
      dedupeKey: finalDedupeKey ?? null,
      message: message ?? "",
      metadata: metadata ?? null,
      createdAt: new Date().toISOString(),
    };

    if (io) {
      io.emit("alert", alert);
    }

    return { deduped: false, alert };
  }

  return { raiseAlert };
}

module.exports = { createAlertEngine };


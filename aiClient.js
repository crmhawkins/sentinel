function safeJsonParse(text) {
  if (!text || typeof text !== "string") return null;
  // Intentamos extraer el primer objeto JSON encontrado.
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  const candidate = text.slice(start, end + 1);
  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
}

async function analyzeTrafficWithAi({
  aiBaseUrl,
  aiModel,
  apiKey,
  timeoutMs,
  containerName,
  containerId,
  baseline,
  latest,
  logsTail,
}) {
  const prompt = `
Eres un analista de seguridad. Debes decidir si un aumento brusco de tráfico es:
1) ataque (scanning, DDoS, fuerza bruta, explotación, etc.)
o
2) tráfico legítimo (picos de usuarios reales, eventos, backups, monitorización, etc.)

Devuelve SOLO JSON válido con el esquema:
{
  "attack": boolean,
  "confidence": number, 
  "reason": string
}

Datos (resumen):
containerName: ${containerName || ""}
containerId: ${containerId || ""}

Baseline 24h (rx):
- avgRxBytesPerSec: ${baseline?.avgRx ?? null}
- maxRxBytesPerSec: ${baseline?.maxRx ?? null}

Último intervalo (rx):
- rxRateBytesPerSec: ${latest?.rxRateBytesPerSec ?? null}
- rxBytesDelta: ${latest?.rxBytesDelta ?? null}
- txRateBytesPerSec: ${latest?.txRateBytesPerSec ?? null}
- txBytesDelta: ${latest?.txBytesDelta ?? null}

Métricas extra:
${JSON.stringify({ baseline, latest }).slice(0, 1200)}

Logs recientes del contenedor (tail):
${(logsTail || "").slice(0, 6000)}
`.trim();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? 60_000);
  try {
    const res = await fetch(aiBaseUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
      body: JSON.stringify({
        prompt,
        modelo: aiModel,
      }),
      signal: controller.signal,
    });
    const data = await res.json();
    // Esperamos que el modelo devuelva data.respuesta con JSON o data.message.content.
    const maybeText = data?.respuesta ?? data?.message?.content ?? data?.message?.text ?? JSON.stringify(data);
    const parsed = safeJsonParse(maybeText);
    if (!parsed) {
      // Por seguridad: si no podemos interpretar el resultado, tratamos como sospechoso.
      return { attack: true, confidence: 0.4, reason: "No se pudo parsear respuesta JSON de la IA (fallback a cuarentena)" };
    }
    return {
      attack: !!parsed.attack,
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : Number(parsed.confidence ?? 0),
      reason: parsed.reason ? String(parsed.reason) : "",
    };
  } catch (e) {
    // Por seguridad: error en la IA => cuarentena conservadora
    return { attack: true, confidence: 0.3, reason: `Error IA: ${e?.message ?? String(e)}` };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { analyzeTrafficWithAi };


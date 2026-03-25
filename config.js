const fs = require("fs");
const path = require("path");
const { z } = require("zod");

const ConfigSchema = z.object({
  listenPort: z.number().int().positive().default(80),
  auth: z.object({
    adminTokenEnv: z.string().default("ADMIN_TOKEN"),
  }).default({}),
  docker: z.object({
    pollIntervalMs: z.number().int().positive().default(5000),
    networkSpike: z.object({
      historySize: z.number().int().positive().default(30),
      zScoreThreshold: z.number().default(3.5),
      minStdBytesPerSec: z.number().default(50 * 1024), // evita falsos positivos cuando hay poco tráfico
    }).default({}),
    sites: z.object({
      minExposedPort: z.array(z.number().int().positive()).default([80, 443]),
      nameIncludes: z.array(z.string()).default(["coolify", "app", "site", "web"]),
    }).default({}),
  }).default({}),
  filesystem: z.object({
    watchPaths: z.array(z.string()).default([]),
    scanIntervalMs: z.number().int().positive().default(60_000),
    maxFileSizeBytes: z.number().int().positive().default(5 * 1024 * 1024),
    hashAlgorithm: z.enum(["sha256"]).default("sha256"),
    ignoreGlobs: z.array(z.string()).default([]),
    profiles: z
      .object({
        laravel: z.array(z.string()).default(["storage", "public", "bootstrap", "config"]),
        wordpress: z.array(z.string()).default(["wp-content", "wp-includes", "wp-admin", "wp-config.php"]),
        node: z.array(z.string()).default(["src", "public"]),
      })
      .default({}),
  }).default({}),
  alerts: z.object({
    dedupeCooldownMs: z.number().int().positive().default(5 * 60_000),
    recentLimit: z.number().int().positive().default(200),
  }).default({}),
  ai: z.object({
    baseUrl: z.string().default("https://aiapi.hawkins.es/chat/chat"),
    model: z.string().default(""),
    apiKeyEnv: z.string().default("AI_API_KEY"),
    timeoutMs: z.number().int().positive().default(60_000),
    enabled: z.boolean().default(true),
  }).default({}),
  traffic: z.object({
    baselineWindowHours: z.number().int().positive().default(24),
    sampleWindowSecForRate: z.number().int().positive().default(60),
    suspectMultiplierOverAvg: z.number().default(40),
    suspectMultiplierOverPeak: z.number().default(10),
    quarantineMultiplierOverAvg: z.number().default(300),
    quarantineCooldownMs: z.number().int().positive().default(30 * 60_000),
    sampleRetentionHours: z.number().int().positive().default(48),
    recentTrafficLimit: z.number().int().positive().default(200),
  }).default({}),
  quarantine: z.object({
    enabled: z.boolean().default(true),
    publicNetworkNameRegex: z.string().default("(traefik|coolify|proxy|public|edge|web)"),
    releaseAfterMs: z.number().int().positive().default(60 * 60_000),
  }).default({}),
});

function loadConfig() {
  const configPath = path.join(process.cwd(), "config.json");
  let raw = {};
  if (fs.existsSync(configPath)) {
    raw = JSON.parse(fs.readFileSync(configPath, "utf8"));
  }

  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    console.error("Config inválida. Detalles:", parsed.error.flatten());
    process.exit(1);
  }

  const cfg = parsed.data;
  cfg.auth = cfg.auth ?? {};

  // Si no hay ADMIN_TOKEN, el panel quedará sin autenticar (para entorno local).
  return cfg;
}

module.exports = { loadConfig };


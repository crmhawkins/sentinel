const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const { Server: SocketIOServer } = require("socket.io");

function renderPanelHtml({ adminToken }) {
  // HTML embebido para mantener el proyecto simple.
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>SV Monitor</title>
    <style>
      body { font-family: Arial, Helvetica, sans-serif; margin: 16px; background: #0b1220; color: #e6edf3; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .card { background: #111b2e; border: 1px solid #223049; border-radius: 10px; padding: 12px; }
      h1 { font-size: 18px; margin: 0 0 8px; }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #223049; font-size: 13px; }
      th { color: #9fb3d1; font-weight: 600; }
      .pill { padding: 2px 8px; border-radius: 999px; font-size: 12px; border: 1px solid #223049; display: inline-block; }
      .ok { background: rgba(46, 204, 113, 0.12); border-color: rgba(46, 204, 113, 0.35); }
      .bad { background: rgba(231, 76, 60, 0.12); border-color: rgba(231, 76, 60, 0.35); }
      .warn { background: rgba(241, 196, 15, 0.12); border-color: rgba(241, 196, 15, 0.35); }
      .muted { color: #9fb3d1; font-size: 12px; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .alert { border-left: 4px solid #223049; padding: 6px 8px; margin: 6px 0; background: rgba(255,255,255,0.03); }
      .crit { border-left-color: rgba(231, 76, 60, 0.9); }
      .info { border-left-color: rgba(52, 152, 219, 0.9); }
      .warnA { border-left-color: rgba(241, 196, 15, 0.9); }
    </style>
  </head>
  <body>
    <h1>SV Monitor</h1>
    <div class="muted">Se actualiza cada 5s. Alertas en tiempo real vía WebSocket.</div>
    <div id="apiBanner" class="card" style="margin-top: 10px; display: none; border-color: rgba(231, 76, 60, 0.6); background: rgba(231, 76, 60, 0.12);"></div>

    <div class="grid" style="margin-top: 12px;">
      <div class="card">
        <h1>Contenedores</h1>
        <div id="containersMeta" class="muted" style="margin-bottom: 8px;"></div>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Estado</th>
              <th>Health</th>
              <th>Uptime</th>
            </tr>
          </thead>
          <tbody id="containersTbody"></tbody>
        </table>
      </div>

      <div class="card">
        <h1>Picos de tráfico (últimos)</h1>
        <table>
          <thead>
            <tr>
              <th>Hora</th>
              <th>Contenedor</th>
              <th>Interfaz</th>
              <th>Dir</th>
              <th>Rate</th>
            </tr>
          </thead>
          <tbody id="spikesTbody"></tbody>
        </table>
      </div>
    </div>

    <div class="grid" style="margin-top: 12px;">
      <div class="card">
        <h1>Eventos de filesystem</h1>
        <div class="muted">Add/change/unlink recientes (según configuración)</div>
        <div id="fileEvents" style="margin-top: 10px;"></div>
      </div>
      <div class="card">
        <h1>Alertas</h1>
        <div id="alerts"></div>
      </div>
    </div>

    <div class="grid" style="margin-top: 12px;">
      <div class="card" style="grid-column: 1 / span 2;">
        <h1>Tráfico (baseline 24h)</h1>
        <div class="muted">Se guarda en SQLite y se usa para detectar picos.</div>
        <table style="margin-top: 8px;">
          <thead>
            <tr>
              <th>Contenedor</th>
              <th>Rx rate</th>
              <th>Avg 24h</th>
              <th>Max 24h</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody id="trafficTbody"></tbody>
        </table>
        <div style="margin-top: 10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
          <div class="muted">Ver muestras:</div>
          <select id="trafficSelect" style="background:#0b1220; color:#e6edf3; border:1px solid #223049; border-radius:8px; padding:6px 10px;">
          </select>
          <div id="trafficSamplesMeta" class="muted"></div>
        </div>
        <div id="trafficSamples" style="margin-top: 10px;"></div>

        <div style="margin-top: 16px;">
          <div class="muted" style="margin-bottom: 8px;">Análisis IA (últimos)</div>
          <div id="aiAnalyses"></div>
        </div>
      </div>
    </div>

    <div class="grid" style="margin-top: 12px;">
      <div class="card" style="grid-column: 1 / span 2;">
        <h1>Auditoría Docker (events)</h1>
        <div class="muted">start/stop/restart/exec/network/image... recientes</div>
        <div id="dockerEvents" style="margin-top: 10px;"></div>
      </div>
    </div>

    <script>
      const state = { containers: [], spikes: [], fileEvents: [], alerts: [], traffic: {}, trafficSamples: [], trafficSelectedId: null, dockerEvents: [], aiAnalyses: [] };

      function bytesPerSec(v) {
        if (!Number.isFinite(v)) return "-";
        const units = ["B/s","KB/s","MB/s","GB/s"];
        let i = 0;
        let x = v;
        while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
        return x.toFixed(1) + " " + units[i];
      }

      function pill(text, kind) {
        return '<span class="pill ' + kind + '">' + text + '</span>';
      }

      function formatUptime(s) {
        if (s === null || s === undefined) return "-";
        const sec = Math.max(0, s);
        const h = Math.floor(sec / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const r = sec % 60;
        if (h > 0) return h + "h " + m + "m";
        if (m > 0) return m + "m " + r + "s";
        return r + "s";
      }

      function renderContainers() {
        const meta = document.getElementById("containersMeta");
        meta.textContent = "Actualizados: " + (state.containers.length || 0) + " contenedores";

        const tbody = document.getElementById("containersTbody");
        tbody.innerHTML = "";
        for (const c of state.containers) {
          const isOk = c.isRunning ? true : false;
          const statusPill = isOk ? pill("RUNNING", "ok") : pill("DOWN", "bad");
          const health = c.health ? c.health : "unknown";
          const healthPill = health === "healthy" ? pill("healthy", "ok") : (health === "unhealthy" ? pill("unhealthy", "bad") : pill(health, "warn"));
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td class='mono'>" + c.name + "</td>" +
            "<td>" + statusPill + "</td>" +
            "<td>" + healthPill + "</td>" +
            "<td>" + formatUptime(c.uptimeSec) + "</td>";
          tbody.appendChild(tr);
        }
      }

      function renderSpikes() {
        const tbody = document.getElementById("spikesTbody");
        tbody.innerHTML = "";
        for (const s of state.spikes) {
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td class='mono'>" + (s.at || "-") + "</td>" +
            "<td class='mono'>" + s.entityId + "</td>" +
            "<td class='mono'>" + s.iface + "</td>" +
            "<td>" + s.direction + "</td>" +
            "<td class='mono'>" + bytesPerSec(s.rateBytesPerSec) + "</td>";
          tbody.appendChild(tr);
        }
      }

      function renderFileEvents() {
        const el = document.getElementById("fileEvents");
        el.innerHTML = "";
        const list = state.fileEvents || [];
        if (!list.length) {
          el.innerHTML = "<div class='muted'>Sin eventos todavía.</div>";
          return;
        }
        for (const ev of list.slice(0, 10)) {
          const div = document.createElement("div");
          div.className = "alert";
          div.innerHTML =
            "<div class='mono muted'>" + ev.at + " • " + ev.eventType + "</div>" +
            "<div class='mono'>" + ev.path + "</div>";
          el.appendChild(div);
        }
      }

      function severityClass(sev) {
        if (sev === "critical") return "crit";
        if (sev === "info") return "info";
        if (sev === "warning") return "warnA";
        return "";
      }

      function renderAlerts() {
        const el = document.getElementById("alerts");
        el.innerHTML = "";
        const list = state.alerts || [];
        if (!list.length) {
          el.innerHTML = "<div class='muted'>Sin alertas.</div>";
          return;
        }
        for (const a of list) {
          const div = document.createElement("div");
          div.className = "alert " + severityClass(a.severity);
          div.innerHTML =
            "<div class='mono muted'>" + a.createdAt + " • " + a.type + " • " + (a.severity || "") + "</div>" +
            "<div class='mono'>" + (a.entityId ? (a.entityId + ": ") : "") + (a.message || "") + "</div>";
          el.appendChild(div);
        }
      }

      function renderDockerEvents() {
        const el = document.getElementById("dockerEvents");
        el.innerHTML = "";
        const list = state.dockerEvents || [];
        if (!list.length) {
          el.innerHTML = "<div class='muted'>Sin eventos todavía.</div>";
          return;
        }
        for (const ev of list.slice(0, 25)) {
          const div = document.createElement("div");
          div.className = "alert";
          div.innerHTML =
            "<div class='mono muted'>" + (ev.createdAt || "-") + " • " + (ev.action || "") + " • " + (ev.type || "") + "</div>" +
            "<div class='mono'>" + (ev.containerName ? (ev.containerName + ": ") : "") + (ev.containerId || "") + "</div>";
          el.appendChild(div);
        }
      }

      function renderTraffic() {
        const tbody = document.getElementById("trafficTbody");
        tbody.innerHTML = "";
        const list = state.containers || [];
        for (const c of list) {
          const tid = c.id;
          const t = state.traffic[tid];
          const rxNow = t?.latestRxRateBytesPerSec;
          const avg = t?.baselineAvgRx;
          const max = t?.baselineMaxRx;

          let status = "";
          if (t?.decision === "quarantined") status = pill("QUARANTENA", "bad");
          else if (t?.decision === "suspicious") status = pill("SOSPECHOSO", "warnA");
          else status = pill("OK", "ok");

          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td class='mono'>" + c.name + "</td>" +
            "<td class='mono'>" + bytesPerSec(rxNow ?? NaN) + "</td>" +
            "<td class='mono'>" + bytesPerSec(avg ?? NaN) + "</td>" +
            "<td class='mono'>" + bytesPerSec(max ?? NaN) + "</td>" +
            "<td>" + status + "</td>";
          tbody.appendChild(tr);
        }
      }

      function renderTrafficSelect() {
        const sel = document.getElementById("trafficSelect");
        sel.innerHTML = "";
        const list = state.containers || [];
        for (const c of list) {
          if (!c?.id) continue;
          const opt = document.createElement("option");
          opt.value = c.id;
          opt.textContent = c.name;
          if (state.trafficSelectedId && state.trafficSelectedId === c.id) opt.selected = true;
          sel.appendChild(opt);
        }

        if (!state.trafficSelectedId && list[0]?.id) {
          state.trafficSelectedId = list[0].id;
          const opt0 = Array.from(sel.options).find((o) => o.value === state.trafficSelectedId);
          if (opt0) opt0.selected = true;
        }
      }

      function bytesPerSecOrDash(v) {
        return bytesPerSec(v);
      }

      function renderTrafficSamples() {
        const el = document.getElementById("trafficSamples");
        const meta = document.getElementById("trafficSamplesMeta");
        el.innerHTML = "";
        const list = state.trafficSamples || [];
        meta.textContent = list.length ? ("muestras: " + list.length) : "";
        if (!list.length) {
          el.innerHTML = "<div class='muted'>Sin muestras.</div>";
          return;
        }
        // Mostramos las últimas 20 (tabla simple)
        const show = list.slice(Math.max(0, list.length - 20));
        const tbl = document.createElement("table");
        tbl.style.width = "100%";
        tbl.style.borderCollapse = "collapse";
        tbl.innerHTML = "<thead><tr><th>Hora</th><th>Rx rate</th><th>Tx rate</th></tr></thead>";
        const body = document.createElement("tbody");
        for (const s of show) {
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td class='mono'>" + s.at + "</td>" +
            "<td class='mono'>" + bytesPerSecOrDash(s.rxRateBytesPerSec) + "</td>" +
            "<td class='mono'>" + bytesPerSecOrDash(s.txRateBytesPerSec) + "</td>";
          body.appendChild(tr);
        }
        tbl.appendChild(body);
        el.appendChild(tbl);
      }

      function renderAiAnalyses() {
        const el = document.getElementById("aiAnalyses");
        el.innerHTML = "";
        const list = state.aiAnalyses || [];
        if (!list.length) {
          el.innerHTML = "<div class='muted'>Sin análisis de IA todavía.</div>";
          return;
        }
        for (const a of list.slice(0, 5)) {
          const div = document.createElement("div");
          div.className = "alert";
          const attackTxt = a.attack ? "ATAQUE" : "LEGITIMO";
          const cls = a.attack ? "crit" : "ok";
          div.style.borderLeftColor = a.attack ? "rgba(231, 76, 60, 0.9)" : "rgba(46, 204, 113, 0.35)";
          div.innerHTML =
            "<div class='mono muted'>" + (a.createdAt || "-") + " • " + attackTxt + " • conf=" + (a.confidence ?? "-") + "</div>" +
            "<div class='mono'>" + (a.reason || "") + "</div>";
          el.appendChild(div);
        }
      }

      function fetchJson(url, token) {
        return fetch(url, {
          headers: token ? { "Authorization": "Bearer " + token } : {},
        }).then(async (r) => {
          let data = {};
          try {
            data = await r.json();
          } catch {
            data = {};
          }
          if (!r.ok) {
            const err = new Error(data.error || ("HTTP " + r.status));
            err.status = r.status;
            err.data = data;
            throw err;
          }
          return data;
        });
      }

      function showApiBanner(msg) {
        const el = document.getElementById("apiBanner");
        if (!el) return;
        if (!msg) {
          el.style.display = "none";
          el.innerHTML = "";
          return;
        }
        el.style.display = "block";
        el.innerHTML = "<strong>Error API</strong><div class='mono' style='margin-top:6px'>" + msg + "</div>";
      }

      async function refreshAll() {
        const token = window.__ADMIN_TOKEN__ || null;
        try {
          const [containers, spikes, fileEvents, alerts, trafficSummary, dockerEvents] = await Promise.all([
            fetchJson("/api/containers", token),
            fetchJson("/api/spikes", token),
            fetchJson("/api/fileEvents", token),
            fetchJson("/api/alerts", token),
            fetchJson("/api/trafficSummary", token),
            fetchJson("/api/dockerAuditEvents", token),
          ]);
          state.containers = containers.containers || [];
          state.spikes = spikes.spikes || [];
          state.fileEvents = fileEvents.fileEvents || [];
          state.alerts = alerts.alerts || [];
          state.traffic = trafficSummary?.trafficByContainerId || {};
          renderContainers();
          renderSpikes();
          renderFileEvents();
          renderAlerts();
          renderTraffic();
          state.dockerEvents = dockerEvents?.events || [];
          renderDockerEvents();
          renderTrafficSelect();
          if (state.trafficSelectedId) loadTrafficSamples(state.trafficSelectedId, token);
          if (state.trafficSelectedId) loadAiAnalyses(state.trafficSelectedId, token);
          showApiBanner("");
        } catch (e) {
          console.error(e);
          const st = e && e.status;
          let hint = (e && e.message) ? String(e.message) : String(e);
          if (st === 401) {
            hint = "401 unauthorized: en Coolify quita la variable ADMIN_TOKEN o pon el mismo valor que en Environment Variables. Sin el token correcto el panel no puede leer /api/containers.";
          }
          showApiBanner(hint);
        }
      }

      async function loadTrafficSamples(containerId, token) {
        if (!containerId) return;
        try {
          const url = "/api/trafficSamples?containerId=" + encodeURIComponent(containerId) + "&limit=200";
          const res = await fetchJson(url, token);
          state.trafficSamples = res?.samples || [];
          renderTrafficSamples();
        } catch (e) {
          console.error(e);
        }
      }

      async function loadAiAnalyses(containerId, token) {
        if (!containerId) return;
        try {
          const url = "/api/aiTrafficAnalyses?containerId=" + encodeURIComponent(containerId) + "&limit=10";
          const res = await fetchJson(url, token);
          state.aiAnalyses = res?.analyses || [];
          renderAiAnalyses();
        } catch (e) {
          console.error(e);
        }
      }

      // WebSocket opcional (si falla el script o el certificado TLS, el panel sigue con polling)
      (function attachSocketWhenReady() {
        const s = document.createElement("script");
        s.src = "/socket.io/socket.io.js";
        s.onload = function () {
          try {
            if (typeof io === "undefined") return;
            const socket = io({ transports: ["websocket", "polling"] });
            socket.on("alert", (a) => {
              state.alerts.unshift(a);
              state.alerts = state.alerts.slice(0, 100);
              renderAlerts();
            });
          } catch (e) {
            console.warn("Socket.IO no conectado:", e);
          }
        };
        s.onerror = function () {
          console.warn("socket.io.js no cargado (TLS/cert o red); alertas solo vía polling cada 5s.");
        };
        document.head.appendChild(s);
      })();

      // Refresh periódico
      refreshAll();
      setInterval(refreshAll, 5000);

      // Cambios del selector
      document.getElementById("trafficSelect").addEventListener("change", (e) => {
        state.trafficSelectedId = e.target.value;
        const token = window.__ADMIN_TOKEN__ || null;
        loadTrafficSamples(state.trafficSelectedId, token);
        loadAiAnalyses(state.trafficSelectedId, token);
      });
    </script>

    <script>
      // Inserta token desde servidor si está activada la auth (opcional).
      window.__ADMIN_TOKEN__ = ${adminToken ? JSON.stringify(adminToken) : "null"};
    </script>
  </body>
</html>`;
}

function createWebServer({ config, getState, alertStore, trafficStore }) {
  const app = express();
  // Panel con HTML y scripts inline: CSP debe permitirlo. COOP estricto en HTTP da avisos en consola.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          connectSrc: ["'self'", "ws:", "wss:"],
          imgSrc: ["'self'", "data:"],
          fontSrc: ["'self'"],
        },
      },
      crossOriginOpenerPolicy: false,
      originAgentCluster: false,
    })
  );
  app.use(cors());

  const server = http.createServer(app);
  const io = new SocketIOServer(server, {
    cors: { origin: "*" },
  });

  const adminToken = process.env[config?.auth?.adminTokenEnv] || null;
  function requireAuth(req, res, next) {
    if (!adminToken) return next();
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : header;
    if (!token || token !== adminToken) return res.status(401).json({ error: "unauthorized" });
    next();
  }

  app.get("/", (req, res) => {
    // No incluimos el token en el HTML por defecto (seguridad). Para entornos locales puedes ajustar.
    res.send(renderPanelHtml({ adminToken }));
  });

  app.get("/api/health", (req, res) => {
    res.json({ ok: true, at: new Date().toISOString() });
  });

  app.get("/api/containers", requireAuth, (req, res) => {
    const state = getState();
    res.json({ containers: state.containers || [] });
  });

  app.get("/api/spikes", requireAuth, (req, res) => {
    const state = getState();
    res.json({ spikes: state.spikes || [] });
  });

  app.get("/api/fileEvents", requireAuth, (req, res) => {
    const state = getState();
    res.json({ fileEvents: state.fileEvents || [] });
  });

  app.get("/api/alerts", requireAuth, (req, res) => {
    res.json({ alerts: alertStore.listAlerts(config?.alerts?.recentLimit ?? 200) });
  });

  app.get("/api/trafficSummary", requireAuth, (req, res) => {
    // El monitor de Docker ya calcula y cachea las decisiones.
    const state = getState();
    res.json({ trafficByContainerId: state.trafficByContainerId || {} });
  });

  app.get("/api/trafficSamples", requireAuth, (req, res) => {
    const containerId = String(req.query.containerId || "");
    const limit = Number(req.query.limit || 200);
    if (!containerId) return res.status(400).json({ error: "containerId requerido" });
    const samples = trafficStore?.listRecentSamples({ containerId, limit: Number.isFinite(limit) ? limit : 200 }) || [];
    res.json({ samples });
  });

  app.get("/api/dockerAuditEvents", requireAuth, (req, res) => {
    const limit = Number(req.query.limit || 50);
    const events =
      trafficStore?.listRecentDockerAuditEvents({ limit: Number.isFinite(limit) ? limit : 50 }) || [];
    res.json({ events });
  });

  app.get("/api/resourceSamples", requireAuth, (req, res) => {
    const containerId = String(req.query.containerId || "");
    const limit = Number(req.query.limit || 200);
    if (!containerId) return res.status(400).json({ error: "containerId requerido" });
    const samples =
      trafficStore?.listRecentResourceSamples({
        containerId,
        limit: Number.isFinite(limit) ? limit : 200,
      }) || [];
    res.json({ samples });
  });

  app.get("/api/aiTrafficAnalyses", requireAuth, (req, res) => {
    const containerId = String(req.query.containerId || "");
    const limit = Number(req.query.limit || 10);
    if (!containerId) return res.status(400).json({ error: "containerId requerido" });
    const analyses =
      trafficStore?.listRecentAiAnalyses({
        containerId,
        limit: Number.isFinite(limit) ? limit : 10,
      }) || [];
    res.json({ analyses });
  });

  io.on("connection", () => {
    // No hacemos handshake complejo; el cliente refresca por polling.
  });

  return { app, server, io };
}

module.exports = { createWebServer };


/**
 * Arranca index.js en un puerto alto y comprueba /api/health (sin Docker necesario para el HTTP).
 */
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

const root = path.join(__dirname, "..");
const port = Number(process.env.SMOKE_HTTP_PORT) || 39876;
const env = { ...process.env, LISTEN_PORT: String(port) };
const child = spawn(process.execPath, ["index.js"], { cwd: root, env, stdio: "inherit" });

function waitHealth() {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 25_000;
    const tryOnce = () => {
      const req = http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        let data = "";
        res.on("data", (c) => {
          data += c;
        });
        res.on("end", () => {
          if (res.statusCode === 200) {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          } else if (Date.now() < deadline) {
            setTimeout(tryOnce, 400);
          } else {
            reject(new Error(`bad status ${res.statusCode}`));
          }
        });
      });
      req.on("error", () => {
        if (Date.now() < deadline) setTimeout(tryOnce, 400);
        else reject(new Error("timeout esperando /api/health"));
      });
    };
    tryOnce();
  });
}

waitHealth()
  .then((j) => {
    console.log("smoke-http: OK", JSON.stringify(j));
    child.kill("SIGTERM");
    setTimeout(() => process.exit(0), 800);
  })
  .catch((e) => {
    console.error("smoke-http: FAIL", e.message);
    try {
      child.kill("SIGTERM");
    } catch {}
    process.exit(1);
  });

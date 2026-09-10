import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DIST_DIR = path.join(__dirname, "dist");
const PORT = 5173;
const BACKEND_TARGET = { host: "127.0.0.1", port: 8000 };

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

const server = http.createServer((req, res) => {
  // 1. Proxy /api requests to FastAPI backend
  if (req.url.startsWith("/api/")) {
    const options = {
      hostname: BACKEND_TARGET.host,
      port: BACKEND_TARGET.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: `${BACKEND_TARGET.host}:${BACKEND_TARGET.port}` },
    };

    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on("error", (err) => {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ detail: `Backend proxy error: ${err.message}` }));
    });

    req.pipe(proxyReq);
    return;
  }

  // 2. Serve static files from dist/
  let reqPath = req.url.split("?")[0];
  if (reqPath === "/") reqPath = "/index.html";

  let filePath = path.join(DIST_DIR, reqPath);

  // SPA fallback
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(DIST_DIR, "index.html");
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || "application/octet-stream";

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("500 Internal Server Error");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n  ➜  Local:   http://localhost:${PORT}/`);
  console.log(`  ➜  Proxy:   /api -> http://${BACKEND_TARGET.host}:${BACKEND_TARGET.port}\n`);
});

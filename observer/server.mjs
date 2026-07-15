import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertObserverSnapshotSafe,
  buildGithubSnapshot,
  buildLocalSnapshot,
  parseRepositorySlug,
  stableFingerprint
} from "./core.mjs";

const OBSERVER_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(OBSERVER_DIR, "..");
const PUBLIC_DIR = path.join(OBSERVER_DIR, "public");
const HOST = process.env.GENESIS_OBSERVER_HOST ?? "127.0.0.1";
const PORT = boundedInteger(process.env.GENESIS_OBSERVER_PORT, 4317, 1, 65535);
const STATE_FILE = path.resolve(
  ROOT,
  process.env.GENESIS_STATE_FILE ?? "conformance/associative_memory_projection_vectors.json"
);
const TOKEN = process.env.GITHUB_TOKEN?.trim() || null;
const GITHUB_MODE = TOKEN ? "authenticated" : "public";
const GITHUB_INTERVAL_MS = boundedInteger(
  process.env.GENESIS_GITHUB_POLL_MS,
  TOKEN ? 20_000 : 300_000,
  TOKEN ? 15_000 : 60_000,
  3_600_000
);
const KEEPALIVE_MS = 20_000;
const MAX_CLIENTS = 32;

function boundedInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function detectRepository() {
  const configured = parseRepositorySlug(process.env.GENESIS_GITHUB_REPO ?? "");
  if (configured) return configured;
  try {
    const remote = execFileSync("git", ["remote", "get-url", "origin"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    return parseRepositorySlug(remote);
  } catch {
    return null;
  }
}

const repository = detectRepository();
const state = {
  local: emptyLocalSnapshot(),
  github: buildGithubSnapshot(
    { error: repository ? "GitHub todavía no consultado." : "No se pudo detectar el repositorio." },
    { repository, mode: GITHUB_MODE }
  ),
  server: {
    started_at: new Date().toISOString(),
    host: HOST,
    port: PORT,
    state_file: path.relative(ROOT, STATE_FILE).replaceAll("\\", "/"),
    github_poll_ms: GITHUB_INTERVAL_MS
  }
};
const clients = new Set();
const githubCache = new Map();
let lastCombinedFingerprint = null;
let fileWatchDebounce = null;
let shuttingDown = false;

function emptyLocalSnapshot() {
  return buildLocalSnapshot({}, {
    sourcePath: path.relative(ROOT, STATE_FILE).replaceAll("\\", "/")
  });
}

function combinedSnapshot() {
  const snapshot = {
    observed_at: new Date().toISOString(),
    server: state.server,
    local: state.local,
    github: state.github,
    truth_boundary: {
      memory_authority: "append_only_chain",
      projection_role: "rebuildable_read_model",
      observer_role: "read_only_non_normative"
    }
  };
  assertObserverSnapshotSafe(snapshot);
  return snapshot;
}

function sendSnapshot(force = false) {
  const snapshot = combinedSnapshot();
  const fingerprint = stableFingerprint({ local: snapshot.local, github: snapshot.github });
  if (!force && fingerprint === lastCombinedFingerprint) return;
  lastCombinedFingerprint = fingerprint;
  const frame = `event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`;
  for (const response of clients) response.write(frame);
}

function readLocalState() {
  try {
    const document = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    state.local = buildLocalSnapshot(document, {
      sourcePath: path.relative(ROOT, STATE_FILE).replaceAll("\\", "/")
    });
  } catch (error) {
    state.local = {
      ...emptyLocalSnapshot(),
      error: `No se pudo leer el estado local: ${error.message}`
    };
  }
  sendSnapshot();
}

function watchLocalState() {
  const directory = path.dirname(STATE_FILE);
  const filename = path.basename(STATE_FILE);
  try {
    fs.watch(directory, { persistent: true }, (_event, changed) => {
      if (changed && changed !== filename) return;
      clearTimeout(fileWatchDebounce);
      fileWatchDebounce = setTimeout(readLocalState, 180);
    });
  } catch (error) {
    state.local = { ...state.local, watch_error: error.message };
  }
}

function githubHeaders(etag) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "genesis-ultra-live-observer"
  };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  if (etag) headers["If-None-Match"] = etag;
  return headers;
}

async function fetchGithubEndpoint(key, pathname) {
  const cached = githubCache.get(key);
  const response = await fetch(`https://api.github.com${pathname}`, {
    headers: githubHeaders(cached?.etag),
    signal: AbortSignal.timeout(12_000)
  });
  if (response.status === 304 && cached) return cached.data;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub ${response.status}: ${body.slice(0, 180)}`);
  }
  const data = await response.json();
  githubCache.set(key, { etag: response.headers.get("etag"), data });
  return data;
}

async function refreshGithub() {
  if (!repository) {
    state.github = buildGithubSnapshot(
      { error: "Configura GENESIS_GITHUB_REPO=owner/repo o ejecuta dentro de un clon Git." },
      { repository: null, mode: GITHUB_MODE }
    );
    sendSnapshot();
    return;
  }

  const encodedRepo = repository.split("/").map(encodeURIComponent).join("/");
  try {
    const [repoData, commits, pulls, runs] = await Promise.all([
      fetchGithubEndpoint("repository", `/repos/${encodedRepo}`),
      fetchGithubEndpoint("commits", `/repos/${encodedRepo}/commits?per_page=10`),
      fetchGithubEndpoint("pulls", `/repos/${encodedRepo}/pulls?state=all&sort=updated&direction=desc&per_page=10`),
      fetchGithubEndpoint("runs", `/repos/${encodedRepo}/actions/runs?per_page=10`)
    ]);
    state.github = buildGithubSnapshot(
      { repository: repoData, commits, pulls, runs },
      { repository, mode: GITHUB_MODE }
    );
  } catch (error) {
    state.github = buildGithubSnapshot(
      {
        repository: githubCache.get("repository")?.data,
        commits: githubCache.get("commits")?.data,
        pulls: githubCache.get("pulls")?.data,
        runs: githubCache.get("runs")?.data,
        error: error.message
      },
      { repository, mode: GITHUB_MODE }
    );
  }
  sendSnapshot();
}

const CONTENT_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".json", "application/json; charset=utf-8"]
]);

function securityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
}

function json(response, status, body) {
  securityHeaders(response);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(body));
}

function serveStatic(requestPath, response, headOnly) {
  const relative = requestPath === "/" ? "index.html" : requestPath.replace(/^\/+/, "");
  const resolved = path.resolve(PUBLIC_DIR, relative);
  if (resolved !== PUBLIC_DIR && !resolved.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    json(response, 403, { error: "forbidden" });
    return;
  }
  fs.readFile(resolved, (error, data) => {
    if (error || !fs.statSync(resolved).isFile()) {
      json(response, 404, { error: "not_found" });
      return;
    }
    securityHeaders(response);
    response.writeHead(200, {
      "Content-Type": CONTENT_TYPES.get(path.extname(resolved)) ?? "application/octet-stream",
      "Cache-Control": "no-cache"
    });
    response.end(headOnly ? undefined : data);
  });
}

const server = http.createServer((request, response) => {
  const method = request.method ?? "GET";
  if (!new Set(["GET", "HEAD"]).has(method)) {
    json(response, 405, { error: "read_only_observer" });
    return;
  }

  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  if (url.pathname === "/api/health") {
    json(response, 200, {
      ok: true,
      role: "read_only_non_normative",
      clients: clients.size,
      repository,
      source: state.local.source
    });
    return;
  }
  if (url.pathname === "/api/snapshot") {
    json(response, 200, combinedSnapshot());
    return;
  }
  if (url.pathname === "/api/events") {
    if (method === "HEAD") {
      response.writeHead(405).end();
      return;
    }
    if (clients.size >= MAX_CLIENTS) {
      json(response, 503, { error: "too_many_observer_clients" });
      return;
    }
    securityHeaders(response);
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive"
    });
    response.write("retry: 3000\n\n");
    clients.add(response);
    response.write(`event: snapshot\ndata: ${JSON.stringify(combinedSnapshot())}\n\n`);
    request.on("close", () => clients.delete(response));
    return;
  }
  serveStatic(url.pathname, response, method === "HEAD");
});

const keepalive = setInterval(() => {
  for (const response of clients) response.write(": keepalive\n\n");
}, KEEPALIVE_MS);
const githubTimer = setInterval(refreshGithub, GITHUB_INTERVAL_MS);

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(keepalive);
  clearInterval(githubTimer);
  clearTimeout(fileWatchDebounce);
  for (const response of clients) response.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 2_000).unref();
  console.log(`\nGenesis Observatory detenido por ${signal}.`);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

readLocalState();
watchLocalState();
await refreshGithub();
server.listen(PORT, HOST, () => {
  console.log(`Genesis Live Observatory: http://${HOST}:${PORT}`);
  console.log(`Estado local: ${path.relative(ROOT, STATE_FILE)}`);
  console.log(`GitHub: ${repository ?? "no configurado"} (${GITHUB_MODE}, ${GITHUB_INTERVAL_MS} ms)`);
  console.log("Rol: observador local de solo lectura; no es memoria ni autoridad.");
});

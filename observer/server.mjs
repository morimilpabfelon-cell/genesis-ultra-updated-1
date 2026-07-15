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
  buildProjectSnapshot,
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
const SYSTEM_MAP_FILE = path.join(OBSERVER_DIR, "system-map.json");
const REQUIRED_FILE = path.join(ROOT, "conformance/required_artifacts.json");
const MANIFEST_FILE = path.join(ROOT, "conformance/draft_manifest.json");
const CHECKLIST_FILE = path.join(ROOT, "docs/V0_1_COMPLETION_CHECKLIST.md");
const TOKEN = process.env.GITHUB_TOKEN?.trim() || null;
const GITHUB_MODE = TOKEN ? "authenticated" : "public";
const GITHUB_INTERVAL_MS = boundedInteger(
  process.env.GENESIS_GITHUB_POLL_MS,
  TOKEN ? 20_000 : 300_000,
  TOKEN ? 15_000 : 60_000,
  3_600_000
);
const PROJECT_INTERVAL_MS = boundedInteger(
  process.env.GENESIS_PROJECT_POLL_MS,
  3_000,
  1_000,
  60_000
);
const KEEPALIVE_MS = 20_000;
const MAX_CLIENTS = 32;

function boundedInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function gitText(args, fallback = null) {
  try {
    return execFileSync("git", args, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return fallback;
  }
}

function detectRepository() {
  const configured = parseRepositorySlug(process.env.GENESIS_GITHUB_REPO ?? "");
  if (configured) return configured;
  return parseRepositorySlug(gitText(["remote", "get-url", "origin"], "") ?? "");
}

function gitChangedFiles(statusText) {
  if (!statusText) return [];
  return statusText.split(/\r?\n/).filter(Boolean).map((line) => {
    const raw = line.slice(3).trim();
    return raw.includes(" -> ") ? raw.split(" -> ").at(-1) : raw;
  }).filter(Boolean);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function gitSnapshot() {
  const status = gitText(["status", "--porcelain", "--untracked-files=all"], "") ?? "";
  const latest = gitText(["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"], "") ?? "";
  return {
    branch: gitText(["rev-parse", "--abbrev-ref", "HEAD"]),
    commit: gitText(["rev-parse", "HEAD"]),
    commit_time: gitText(["show", "-s", "--format=%cI", "HEAD"]),
    dirty: status.length > 0,
    changed_files: gitChangedFiles(status),
    latest_commit_files: latest.split(/\r?\n/).filter(Boolean)
  };
}

const repository = detectRepository();
const state = {
  local: emptyLocalSnapshot(),
  project: emptyProjectSnapshot(),
  github: buildGithubSnapshot(
    { error: repository ? "GitHub todavía no consultado." : "No se pudo detectar el repositorio." },
    { repository, mode: GITHUB_MODE }
  ),
  server: {
    started_at: new Date().toISOString(),
    host: HOST,
    port: PORT,
    state_file: path.relative(ROOT, STATE_FILE).replaceAll("\\", "/"),
    github_poll_ms: GITHUB_INTERVAL_MS,
    project_poll_ms: PROJECT_INTERVAL_MS
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

function emptyProjectSnapshot() {
  return buildProjectSnapshot({
    catalog: { components: [], layers: [], flow: [] },
    requiredArtifacts: { required: [] },
    manifest: {},
    checklistText: "",
    runtimeSubsystems: {},
    git: {}
  });
}

function combinedSnapshot() {
  const snapshot = {
    observed_at: new Date().toISOString(),
    server: state.server,
    local: state.local,
    project: state.project,
    github: state.github,
    truth_boundary: {
      memory_authority: "append_only_chain",
      projection_role: "rebuildable_read_model",
      observer_role: "read_only_non_normative",
      maturity_role: "evidence_summary_not_consciousness"
    }
  };
  assertObserverSnapshotSafe(snapshot);
  return snapshot;
}

function sendSnapshot(force = false) {
  const snapshot = combinedSnapshot();
  const fingerprint = stableFingerprint({
    local: snapshot.local,
    project: snapshot.project,
    github: snapshot.github
  });
  if (!force && fingerprint === lastCombinedFingerprint) return;
  lastCombinedFingerprint = fingerprint;
  const frame = `event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`;
  for (const response of clients) response.write(frame);
}

function readLocalState() {
  try {
    const document = readJson(STATE_FILE);
    state.local = buildLocalSnapshot(document, {
      sourcePath: path.relative(ROOT, STATE_FILE).replaceAll("\\", "/")
    });
  } catch (error) {
    state.local = {
      ...emptyLocalSnapshot(),
      error: `No se pudo leer el estado local: ${error.message}`
    };
  }
  readProjectState();
}

function readProjectState() {
  try {
    state.project = buildProjectSnapshot({
      catalog: readJson(SYSTEM_MAP_FILE),
      requiredArtifacts: readJson(REQUIRED_FILE),
      manifest: readJson(MANIFEST_FILE),
      checklistText: fs.readFileSync(CHECKLIST_FILE, "utf8"),
      runtimeSubsystems: state.local.runtime.subsystems,
      git: gitSnapshot()
    });
  } catch (error) {
    state.project = {
      ...emptyProjectSnapshot(),
      error: `No se pudo construir el mapa del proyecto: ${error.message}`
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

    const latestSha = commits?.[0]?.sha;
    const latestPullNumber = pulls?.[0]?.number;
    const [latestCommit, latestPullFiles] = await Promise.all([
      latestSha
        ? fetchGithubEndpoint(`commit:${latestSha}`, `/repos/${encodedRepo}/commits/${encodeURIComponent(latestSha)}`)
        : Promise.resolve(null),
      latestPullNumber
        ? fetchGithubEndpoint(`pull-files:${latestPullNumber}`, `/repos/${encodedRepo}/pulls/${latestPullNumber}/files?per_page=100`)
        : Promise.resolve([])
    ]);

    state.github = buildGithubSnapshot(
      {
        repository: repoData,
        commits,
        pulls,
        runs,
        latest_commit: latestCommit,
        latest_pull_number: latestPullNumber,
        latest_pull_files: latestPullFiles
      },
      { repository, mode: GITHUB_MODE }
    );
  } catch (error) {
    state.github = buildGithubSnapshot(
      {
        repository: githubCache.get("repository")?.data,
        commits: githubCache.get("commits")?.data,
        pulls: githubCache.get("pulls")?.data,
        runs: githubCache.get("runs")?.data,
        latest_commit: [...githubCache.entries()].find(([key]) => key.startsWith("commit:"))?.[1]?.data,
        latest_pull_files: [...githubCache.entries()].find(([key]) => key.startsWith("pull-files:"))?.[1]?.data,
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
    if (error) {
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
      source: state.local.source,
      project: {
        branch: state.project.repository.branch,
        commit: state.project.repository.commit,
        maturity_score: state.project.progress.maturity_score
      }
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
const projectTimer = setInterval(readProjectState, PROJECT_INTERVAL_MS);

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(keepalive);
  clearInterval(githubTimer);
  clearInterval(projectTimer);
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
  console.log(`Genesis Complete Observatory: http://${HOST}:${PORT}`);
  console.log(`Estado local: ${path.relative(ROOT, STATE_FILE)}`);
  console.log(`Proyecto: ${state.project.repository.branch ?? "sin rama"} @ ${state.project.repository.commit?.slice(0, 12) ?? "sin commit"}`);
  console.log(`GitHub: ${repository ?? "no configurado"} (${GITHUB_MODE}, ${GITHUB_INTERVAL_MS} ms)`);
  console.log("Rol: observador local de solo lectura; no es memoria, autoridad ni consciencia.");
});

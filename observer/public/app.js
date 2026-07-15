const elements = Object.fromEntries([
  "liveBadge", "sourceBadge", "githubBadge", "eventCount", "latestEvent", "nodeCount",
  "nodeKinds", "edgeCount", "derivations", "chainStatus", "chainRange", "ciStatus",
  "ciRun", "lastUpdate", "repositoryName", "brainGraph", "viewport", "edgesLayer",
  "nodesLayer", "graphEmpty", "detailContent", "memoryTimeline", "githubActivity",
  "githubError", "instanceId", "projectionId", "nodeSearch", "resetGraph"
].map((id) => [id, document.getElementById(id)]));

const state = {
  snapshot: null,
  positions: new Map(),
  selected: null,
  transform: { x: 0, y: 0, scale: 1 },
  dragging: null,
  panning: null,
  fingerprint: null
};

const NODE_COLORS = {
  observation: "var(--observation)",
  concept: "var(--concept)",
  decision: "var(--decision)",
  body: "var(--body)",
  time_anchor: "#f4a261",
  memory_event: "#8fa0b8",
  unknown: "var(--unknown)"
};

function short(value, length = 12) {
  if (value === null || value === undefined || value === "") return "—";
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function relativeTime(value) {
  if (!value) return "sin fecha";
  const delta = Date.now() - Date.parse(value);
  if (!Number.isFinite(delta)) return value;
  const seconds = Math.round(delta / 1000);
  if (Math.abs(seconds) < 60) return `hace ${Math.abs(seconds)} s`;
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return `hace ${Math.abs(minutes)} min`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return `hace ${Math.abs(hours)} h`;
  return new Intl.DateTimeFormat("es-PE", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function setBadge(element, text, status = "neutral") {
  element.textContent = text;
  element.className = `badge ${status}`;
}

function entriesSummary(record) {
  const entries = Object.entries(record ?? {});
  return entries.length ? entries.map(([key, value]) => `${key}: ${value}`).join(" · ") : "—";
}

function updateMetrics(snapshot) {
  const local = snapshot.local;
  const github = snapshot.github;
  const latestRun = github.workflow_runs?.[0];
  elements.eventCount.textContent = local.memory.count;
  elements.latestEvent.textContent = local.memory.latest
    ? `${local.memory.latest.event_type} · #${local.memory.latest.sequence}`
    : "Sin eventos";
  elements.nodeCount.textContent = local.projection.node_count;
  elements.nodeKinds.textContent = entriesSummary(local.projection.node_kinds);
  elements.edgeCount.textContent = local.projection.edge_count;
  elements.derivations.textContent = entriesSummary(local.projection.derivations);
  elements.chainStatus.textContent = local.memory.integrity.status === "valid" ? "Íntegra" : local.memory.integrity.status;
  elements.chainStatus.style.color = local.memory.integrity.status === "valid" ? "var(--good)" : "var(--warn)";
  elements.chainRange.textContent = local.memory.integrity.checkedEvents
    ? `${local.memory.integrity.firstSequence} → ${local.memory.integrity.lastSequence}`
    : "Sin frontera";
  elements.ciStatus.textContent = latestRun?.conclusion ?? latestRun?.status ?? "Sin datos";
  elements.ciStatus.style.color = latestRun?.conclusion === "success" ? "var(--good)" : latestRun ? "var(--warn)" : "";
  elements.ciRun.textContent = latestRun ? `${latestRun.name} #${latestRun.run_number ?? "—"}` : "Sin ejecuciones";
  elements.lastUpdate.textContent = new Intl.DateTimeFormat("es-PE", { timeStyle: "medium" }).format(new Date(snapshot.observed_at));
  elements.repositoryName.textContent = github.repository ?? "Repositorio no detectado";
  elements.instanceId.textContent = `Instancia: ${local.identity.instance_id ?? "—"}`;
  elements.projectionId.textContent = `Proyección: ${short(local.projection.projection_id, 30)}`;

  setBadge(elements.sourceBadge,
    local.source.mode === "runtime" ? "Runtime local" : "Fixture de conformidad",
    local.source.mode === "runtime" ? "good" : "pending");
  setBadge(elements.githubBadge,
    github.connection.error ? "GitHub degradado" : `GitHub ${github.connection.mode}`,
    github.connection.error ? "bad" : "good");
}

function renderTimeline(events) {
  if (!events.length) {
    elements.memoryTimeline.innerHTML = '<li class="empty-state">Sin eventos.</li>';
    return;
  }
  elements.memoryTimeline.innerHTML = events.slice().reverse().map((event) => `
    <li>
      <span class="sequence">${escapeHtml(event.sequence)}</span>
      <strong>${escapeHtml(event.event_type)}</strong>
      <div class="meta">
        <span>${escapeHtml(event.actor)}</span>
        <span>${escapeHtml(relativeTime(event.observed_at))}</span>
        <span class="code">${escapeHtml(short(event.event_hash, 22))}</span>
      </div>
    </li>`).join("");
}

function githubItems(github) {
  const commits = (github.commits ?? []).map((item) => ({
    type: "commit", title: item.message, when: item.authored_at, meta: `${item.author} · ${short(item.sha, 8)}`, url: item.url
  }));
  const pulls = (github.pulls ?? []).map((item) => ({
    type: "pull request", title: `#${item.number} ${item.title}`, when: item.updated_at,
    meta: `${item.state}${item.draft ? " · draft" : ""} · ${item.author}`, url: item.url
  }));
  const runs = (github.workflow_runs ?? []).map((item) => ({
    type: "workflow", title: `${item.name} #${item.run_number ?? "—"}`,
    when: item.updated_at, meta: `${item.status}${item.conclusion ? ` · ${item.conclusion}` : ""} · ${item.branch ?? "—"}`, url: item.url
  }));
  return [...commits, ...pulls, ...runs]
    .sort((left, right) => Date.parse(right.when ?? 0) - Date.parse(left.when ?? 0))
    .slice(0, 18);
}

function renderGithub(github) {
  elements.githubError.hidden = !github.connection.error;
  elements.githubError.textContent = github.connection.error ?? "";
  const items = githubItems(github);
  elements.githubActivity.innerHTML = items.length ? items.map((item) => `
    <li>
      <span class="activity-type">${escapeHtml(item.type)}</span><br>
      <strong>${item.url ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">${escapeHtml(item.title)}</a>` : escapeHtml(item.title)}</strong>
      <div class="meta"><span>${escapeHtml(item.meta)}</span><span>${escapeHtml(relativeTime(item.when))}</span></div>
    </li>`).join("") : '<li class="empty-state">Sin actividad disponible.</li>';
}

function hashUnit(value, offset = 0) {
  let hash = 2166136261 + offset;
  for (const char of String(value)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return ((hash >>> 0) % 10_000) / 10_000;
}

function initializePositions(nodes, width, height) {
  const centerX = width / 2;
  const centerY = height / 2;
  for (const node of nodes) {
    if (state.positions.has(node.node_id)) continue;
    const angle = hashUnit(node.node_id) * Math.PI * 2;
    const radius = 70 + hashUnit(node.node_id, 71) * Math.min(width, height) * .28;
    state.positions.set(node.node_id, {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
      vx: 0,
      vy: 0
    });
  }
  const valid = new Set(nodes.map((node) => node.node_id));
  for (const id of state.positions.keys()) if (!valid.has(id)) state.positions.delete(id);
}

function simulate(nodes, edges, width, height, iterations = 100) {
  initializePositions(nodes, width, height);
  const byId = new Map(nodes.map((node) => [node.node_id, state.positions.get(node.node_id)]));
  for (let step = 0; step < iterations; step += 1) {
    for (let i = 0; i < nodes.length; i += 1) {
      const left = byId.get(nodes[i].node_id);
      for (let j = i + 1; j < nodes.length; j += 1) {
        const right = byId.get(nodes[j].node_id);
        let dx = right.x - left.x;
        let dy = right.y - left.y;
        const distance2 = Math.max(dx * dx + dy * dy, 100);
        const force = Math.min(9500 / distance2, .85);
        const distance = Math.sqrt(distance2);
        dx /= distance; dy /= distance;
        left.vx -= dx * force; left.vy -= dy * force;
        right.vx += dx * force; right.vy += dy * force;
      }
    }
    for (const edge of edges) {
      const source = byId.get(edge.source_node_id);
      const target = byId.get(edge.target_node_id);
      if (!source || !target) continue;
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const distance = Math.max(Math.hypot(dx, dy), 1);
      const desired = edge.derivation === "confirmed" ? 125 : 165;
      const force = (distance - desired) * .0045;
      source.vx += (dx / distance) * force; source.vy += (dy / distance) * force;
      target.vx -= (dx / distance) * force; target.vy -= (dy / distance) * force;
    }
    for (const node of nodes) {
      const point = byId.get(node.node_id);
      point.vx += (width / 2 - point.x) * .0008;
      point.vy += (height / 2 - point.y) * .0008;
      point.vx *= .86; point.vy *= .86;
      point.x = Math.max(35, Math.min(width - 35, point.x + point.vx));
      point.y = Math.max(35, Math.min(height - 35, point.y + point.vy));
    }
  }
}

function nodeRadius(node) {
  const refs = node.source_event_refs?.length ?? 0;
  return Math.min(28, 15 + refs * 2.5);
}

function renderGraph(local, changed) {
  const nodes = local.projection.nodes ?? [];
  const edges = local.projection.edges ?? [];
  elements.graphEmpty.hidden = nodes.length > 0;
  elements.brainGraph.style.display = nodes.length ? "block" : "none";
  if (!nodes.length) return;

  const width = elements.brainGraph.clientWidth || 900;
  const height = elements.brainGraph.clientHeight || 570;
  elements.brainGraph.setAttribute("viewBox", `0 0 ${width} ${height}`);
  simulate(nodes, edges, width, height, Math.min(140, 45 + nodes.length * 2));

  elements.edgesLayer.replaceChildren(...edges.map((edge) => {
    const source = state.positions.get(edge.source_node_id);
    const target = state.positions.get(edge.target_node_id);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", source?.x ?? 0); line.setAttribute("y1", source?.y ?? 0);
    line.setAttribute("x2", target?.x ?? 0); line.setAttribute("y2", target?.y ?? 0);
    line.setAttribute("class", `edge ${edge.derivation ?? "unknown"}`);
    line.dataset.search = `${edge.relation} ${edge.derivation} ${edge.edge_id}`.toLowerCase();
    line.addEventListener("click", () => showDetail("edge", edge));
    return line;
  }));

  elements.nodesLayer.replaceChildren(...nodes.map((node) => {
    const point = state.positions.get(node.node_id);
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    group.setAttribute("transform", `translate(${point.x} ${point.y})`);
    group.setAttribute("class", `node${changed ? " changed" : ""}`);
    group.dataset.search = `${node.node_kind} ${node.node_id} ${node.subject_digest}`.toLowerCase();
    group.dataset.nodeId = node.node_id;
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("r", nodeRadius(node));
    circle.setAttribute("fill", NODE_COLORS[node.node_kind] ?? NODE_COLORS.unknown);
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("y", nodeRadius(node) + 16);
    label.textContent = node.node_kind;
    group.append(circle, label);
    group.addEventListener("click", (event) => { event.stopPropagation(); showDetail("node", node); });
    return group;
  }));
  applyTransform();
  applySearch();
}

function showDetail(kind, item) {
  state.selected = { kind, id: item.node_id ?? item.edge_id };
  for (const node of elements.nodesLayer.querySelectorAll(".node")) {
    node.classList.toggle("selected", node.dataset.nodeId === state.selected.id);
  }
  const rows = kind === "node" ? [
    ["Tipo", item.node_kind], ["Node ID", item.node_id], ["Digest", item.subject_digest],
    ["Eventos fuente", item.source_event_refs?.join("\n")]
  ] : [
    ["Relación", item.relation], ["Derivación", item.derivation],
    ["Confianza", item.confidence_basis_points === null ? null : `${item.confidence_basis_points / 100}%`],
    ["Edge ID", item.edge_id], ["Origen", item.source_node_id], ["Destino", item.target_node_id],
    ["Eventos fuente", item.source_event_refs?.join("\n")], ["Confirmación", item.confirmation_event_ref]
  ];
  elements.detailContent.innerHTML = `<dl>${rows.map(([key, value]) => `
    <dt>${escapeHtml(key)}</dt><dd class="${String(value ?? "").length > 25 ? "code" : ""}">${escapeHtml(value ?? "—")}</dd>`).join("")}</dl>`;
}

function applyTransform() {
  const { x, y, scale } = state.transform;
  elements.viewport.setAttribute("transform", `translate(${x} ${y}) scale(${scale})`);
}

function applySearch() {
  const query = elements.nodeSearch.value.trim().toLowerCase();
  for (const element of elements.brainGraph.querySelectorAll(".node, .edge")) {
    element.classList.toggle("hidden", Boolean(query) && !element.dataset.search.includes(query));
  }
}

function resetGraph() {
  state.transform = { x: 0, y: 0, scale: 1 };
  state.positions.clear();
  if (state.snapshot) renderGraph(state.snapshot.local, false);
}

function render(snapshot) {
  const changed = state.fingerprint !== null && state.fingerprint !== snapshot.local.fingerprint;
  state.snapshot = snapshot;
  state.fingerprint = snapshot.local.fingerprint;
  updateMetrics(snapshot);
  renderTimeline(snapshot.local.memory.events ?? []);
  renderGithub(snapshot.github);
  renderGraph(snapshot.local, changed);
}

function connect() {
  const source = new EventSource("/api/events");
  source.addEventListener("open", () => setBadge(elements.liveBadge, "En vivo", "good"));
  source.addEventListener("snapshot", (event) => {
    try { render(JSON.parse(event.data)); }
    catch (error) { setBadge(elements.liveBadge, `Datos inválidos: ${error.message}`, "bad"); }
  });
  source.addEventListener("error", () => setBadge(elements.liveBadge, "Reconectando", "pending"));
}

elements.nodeSearch.addEventListener("input", applySearch);
elements.resetGraph.addEventListener("click", resetGraph);
elements.brainGraph.addEventListener("wheel", (event) => {
  event.preventDefault();
  const next = Math.min(2.8, Math.max(.45, state.transform.scale * (event.deltaY > 0 ? .9 : 1.1)));
  state.transform.scale = next;
  applyTransform();
}, { passive: false });
elements.brainGraph.addEventListener("pointerdown", (event) => {
  if (event.target.closest?.(".node")) return;
  state.panning = { x: event.clientX, y: event.clientY, startX: state.transform.x, startY: state.transform.y };
  elements.brainGraph.setPointerCapture(event.pointerId);
});
elements.brainGraph.addEventListener("pointermove", (event) => {
  if (!state.panning) return;
  state.transform.x = state.panning.startX + event.clientX - state.panning.x;
  state.transform.y = state.panning.startY + event.clientY - state.panning.y;
  applyTransform();
});
elements.brainGraph.addEventListener("pointerup", () => { state.panning = null; });
window.addEventListener("resize", () => { if (state.snapshot) renderGraph(state.snapshot.local, false); });

connect();

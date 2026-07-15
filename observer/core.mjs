import crypto from "node:crypto";

const GITHUB_HOSTS = new Set(["github.com", "www.github.com"]);
const FORBIDDEN_PUBLIC_FIELDS = new Set([
  "raw_content",
  "payload",
  "embedding",
  "token",
  "credential",
  "private_key",
  "secret"
]);
const MATURITY_WEIGHTS = {
  verified: 100,
  live_tool: 100,
  simulated: 70,
  partial: 45,
  specified: 25,
  pending: 0
};

export function parseRepositorySlug(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const input = value.trim();

  const scpMatch = input.match(/^git@github\.com:([^/\s]+)\/([^/\s]+?)(?:\.git)?$/i);
  if (scpMatch) return `${scpMatch[1]}/${scpMatch[2]}`;

  try {
    const url = new URL(input);
    if (!GITHUB_HOSTS.has(url.hostname.toLowerCase())) return null;
    const parts = url.pathname.replace(/^\/+|\/+$/g, "").split("/");
    if (parts.length < 2) return null;
    return `${parts[0]}/${parts[1].replace(/\.git$/i, "")}`;
  } catch {
    const simpleMatch = input.match(/^([^/\s]+)\/([^/\s]+)$/);
    return simpleMatch ? `${simpleMatch[1]}/${simpleMatch[2].replace(/\.git$/i, "")}` : null;
  }
}

export function stableFingerprint(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function summarizeCounts(items, field) {
  const counts = {};
  for (const item of items) {
    const key = typeof item?.[field] === "string" ? item[field] : "unknown";
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function chainIntegrity(events) {
  if (events.length === 0) {
    return { status: "empty", continuous: null, checkedEvents: 0, firstSequence: null, lastSequence: null };
  }

  let continuous = true;
  for (let index = 0; index < events.length; index += 1) {
    const current = events[index];
    if (index === 0) {
      if (current.sequence === 0 && current.previous_event_hash !== "GENESIS") continuous = false;
      continue;
    }
    const previous = events[index - 1];
    if (
      current.sequence !== previous.sequence + 1
      || current.previous_event_hash !== previous.event_hash
    ) {
      continuous = false;
      break;
    }
  }

  return {
    status: continuous ? "valid" : "broken",
    continuous,
    checkedEvents: events.length,
    firstSequence: events[0]?.sequence ?? null,
    lastSequence: events.at(-1)?.sequence ?? null
  };
}

function safeEvent(event) {
  return {
    event_id: event?.event_id ?? null,
    sequence: event?.sequence ?? null,
    event_type: event?.event_type ?? "unknown",
    actor: event?.actor ?? "unknown",
    body_id: event?.body_id ?? null,
    instance_id: event?.instance_id ?? null,
    observed_at: event?.observed_at ?? null,
    privacy: event?.privacy ?? null,
    content_digest: event?.content_digest ?? null,
    event_hash: event?.event_hash ?? null,
    previous_event_hash: event?.previous_event_hash ?? null
  };
}

function safeNode(node) {
  return {
    node_id: node?.node_id ?? null,
    node_kind: node?.node_kind ?? "unknown",
    subject_digest: node?.subject_digest ?? null,
    source_event_refs: Array.isArray(node?.source_event_refs) ? [...node.source_event_refs] : []
  };
}

function safeEdge(edge) {
  return {
    edge_id: edge?.edge_id ?? null,
    source_node_id: edge?.source_node_id ?? null,
    target_node_id: edge?.target_node_id ?? null,
    relation: edge?.relation ?? "unknown",
    derivation: edge?.derivation ?? "unknown",
    confidence_basis_points: edge?.confidence_basis_points ?? null,
    source_event_refs: Array.isArray(edge?.source_event_refs) ? [...edge.source_event_refs] : [],
    confirmation_event_ref: edge?.confirmation_event_ref ?? null
  };
}

function safeMetricValue(value) {
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map(safeMetricValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !FORBIDDEN_PUBLIC_FIELDS.has(key))
        .slice(0, 50)
        .map(([key, child]) => [key, safeMetricValue(child)])
    );
  }
  return String(value);
}

function safeSubsystems(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).map(([id, subsystem]) => {
    const record = subsystem && typeof subsystem === "object" && !Array.isArray(subsystem)
      ? subsystem
      : { status: subsystem };
    return [id, {
      status: typeof record.status === "string" ? record.status : "unknown",
      active: Boolean(record.active),
      updated_at: typeof record.updated_at === "string" ? record.updated_at : null,
      metrics: safeMetricValue(record.metrics ?? {})
    }];
  }));
}

export function buildLocalSnapshot(document, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const sourcePath = options.sourcePath ?? null;
  const eventsInput = document?.source_memory_events ?? document?.memory_events ?? document?.events ?? [];
  const projection = document?.projection ?? document?.associative_projection ?? {};
  const nodesInput = projection?.nodes ?? document?.nodes ?? [];
  const edgesInput = projection?.edges ?? document?.edges ?? [];

  const events = Array.isArray(eventsInput) ? eventsInput.map(safeEvent) : [];
  const nodes = Array.isArray(nodesInput) ? nodesInput.map(safeNode) : [];
  const edges = Array.isArray(edgesInput) ? edgesInput.map(safeEdge) : [];
  const integrity = chainIntegrity(events);
  const instanceIds = [...new Set(events.map((event) => event.instance_id).filter(Boolean))];
  const sourceMode = document?.runtime === true || document?.source_mode === "runtime"
    ? "runtime"
    : "conformance_fixture";

  const snapshot = {
    observed_at: now,
    source: {
      mode: sourceMode,
      path: sourcePath,
      profile: document?.profile ?? projection?.projection_profile ?? null,
      status: document?.status ?? null
    },
    identity: {
      instance_id: projection?.instance_id ?? document?.identity?.instance_id ?? instanceIds[0] ?? null,
      companion_name: document?.identity?.companion_name ?? null,
      body_ids: [...new Set(events.map((event) => event.body_id).filter(Boolean))],
      active_body_id: document?.identity?.active_body_id ?? null,
      consistent_instance: instanceIds.length <= 1
    },
    runtime: {
      status: sourceMode === "runtime" ? (document?.runtime_status ?? "connected") : "fixture",
      heartbeat_at: document?.heartbeat_at ?? null,
      subsystems: safeSubsystems(document?.subsystems ?? document?.runtime_components)
    },
    memory: {
      count: events.length,
      latest: events.at(-1) ?? null,
      integrity,
      events
    },
    projection: {
      projection_id: projection?.projection_id ?? null,
      projection_digest: projection?.projection_digest ?? null,
      profile: projection?.projection_profile ?? null,
      coverage_status: projection?.coverage_status ?? null,
      source_event_count: projection?.source_event_count ?? events.length,
      node_count: nodes.length,
      edge_count: edges.length,
      node_kinds: summarizeCounts(nodes, "node_kind"),
      derivations: summarizeCounts(edges, "derivation"),
      nodes,
      edges
    }
  };

  snapshot.fingerprint = stableFingerprint(snapshot);
  return snapshot;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeChangedFile(file) {
  return {
    filename: file?.filename ?? null,
    status: file?.status ?? null,
    additions: Number.isInteger(file?.additions) ? file.additions : null,
    deletions: Number.isInteger(file?.deletions) ? file.deletions : null,
    changes: Number.isInteger(file?.changes) ? file.changes : null
  };
}

export function buildGithubSnapshot(payload, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const repository = options.repository ?? null;
  const mode = options.mode ?? "public";
  const repo = payload?.repository ?? {};
  const commits = asArray(payload?.commits).map((commit) => ({
    sha: commit?.sha ?? null,
    message: commit?.commit?.message?.split("\n", 1)[0] ?? "",
    author: commit?.commit?.author?.name ?? commit?.author?.login ?? "unknown",
    authored_at: commit?.commit?.author?.date ?? null,
    url: commit?.html_url ?? null
  }));
  const pulls = asArray(payload?.pulls).map((pull) => ({
    number: pull?.number ?? null,
    title: pull?.title ?? "",
    state: pull?.state ?? "unknown",
    draft: Boolean(pull?.draft),
    merged_at: pull?.merged_at ?? null,
    updated_at: pull?.updated_at ?? null,
    author: pull?.user?.login ?? "unknown",
    url: pull?.html_url ?? null
  }));
  const runs = asArray(payload?.runs?.workflow_runs ?? payload?.runs).map((run) => ({
    id: run?.id ?? null,
    name: run?.name ?? "workflow",
    status: run?.status ?? "unknown",
    conclusion: run?.conclusion ?? null,
    event: run?.event ?? null,
    branch: run?.head_branch ?? null,
    sha: run?.head_sha ?? null,
    run_number: run?.run_number ?? null,
    updated_at: run?.updated_at ?? null,
    url: run?.html_url ?? null
  }));

  const snapshot = {
    observed_at: now,
    repository,
    connection: {
      mode,
      authenticated: mode === "authenticated",
      error: payload?.error ?? null,
      rate: payload?.rate ?? null
    },
    repository_state: {
      default_branch: repo?.default_branch ?? null,
      open_issues: repo?.open_issues_count ?? null,
      pushed_at: repo?.pushed_at ?? null,
      updated_at: repo?.updated_at ?? null,
      url: repo?.html_url ?? (repository ? `https://github.com/${repository}` : null)
    },
    commits,
    pulls,
    workflow_runs: runs,
    latest_workflow: runs[0] ?? null,
    latest_commit_files: asArray(payload?.latest_commit?.files).map(safeChangedFile),
    latest_pull: {
      number: payload?.latest_pull_number ?? pulls[0]?.number ?? null,
      files: asArray(payload?.latest_pull_files).map(safeChangedFile)
    }
  };
  snapshot.fingerprint = stableFingerprint(snapshot);
  return snapshot;
}

function evidenceKind(relativePath) {
  if (relativePath.startsWith("spec/")) return "spec";
  if (relativePath.startsWith("schemas/")) return "schema";
  if (relativePath.startsWith("conformance/")) return "conformance";
  if (relativePath.startsWith(".github/workflows/")) return "workflow";
  if (relativePath.startsWith("docs/") || relativePath.endsWith("README.md")) return "documentation";
  if (relativePath.includes("/test/") || relativePath.includes(".test.")) return "test";
  if (relativePath.startsWith("tools/") || relativePath.startsWith("reference/") || relativePath.startsWith("observer/")) {
    return "implementation";
  }
  return "other";
}

function matchesComponent(relativePath, keywords) {
  const normalized = relativePath.toLowerCase();
  return asArray(keywords).some((keyword) => normalized.includes(String(keyword).toLowerCase()));
}

function safeCatalogComponent(component) {
  return {
    id: component?.id ?? "unknown",
    name: component?.name ?? component?.id ?? "Sin nombre",
    layer: component?.layer ?? "other",
    maturity: component?.maturity ?? "pending",
    description: component?.description ?? "",
    keywords: asArray(component?.keywords).map(String),
    required_evidence: asArray(component?.required_evidence).map(String)
  };
}

function checklistCounts(text) {
  const checked = (String(text ?? "").match(/^- \[x\]/gmi) ?? []).length;
  const pending = (String(text ?? "").match(/^- \[ \]/gmi) ?? []).length;
  return { checked, pending, total: checked + pending };
}

export function affectedComponents(paths, catalog) {
  const components = asArray(catalog?.components).map(safeCatalogComponent);
  const result = new Set();
  for (const relativePath of asArray(paths)) {
    for (const component of components) {
      if (matchesComponent(String(relativePath), component.keywords)) result.add(component.id);
    }
  }
  return [...result];
}

export function buildProjectSnapshot(input, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const catalog = input?.catalog ?? {};
  const required = asArray(input?.requiredArtifacts?.required).map(String);
  const manifest = input?.manifest ?? {};
  const runtimeSubsystems = input?.runtimeSubsystems ?? {};
  const git = input?.git ?? {};
  const layers = asArray(catalog?.layers).map((layer) => ({
    id: layer?.id ?? "other",
    name: layer?.name ?? layer?.id ?? "Otra"
  }));

  const components = asArray(catalog?.components).map(safeCatalogComponent).map((component) => {
    const files = required.filter((relativePath) => matchesComponent(relativePath, component.keywords));
    const evidence = summarizeCounts(files.map((relativePath) => ({ kind: evidenceKind(relativePath) })), "kind");
    const satisfied = component.required_evidence.filter((kind) => (evidence[kind] ?? 0) > 0);
    const evidenceCoverage = component.required_evidence.length
      ? Math.round((satisfied.length / component.required_evidence.length) * 100)
      : 0;
    const runtime = runtimeSubsystems?.[component.id] ?? null;
    return {
      ...component,
      files,
      file_count: files.length,
      evidence,
      evidence_coverage: evidenceCoverage,
      missing_evidence: component.required_evidence.filter((kind) => !satisfied.includes(kind)),
      maturity_score: MATURITY_WEIGHTS[component.maturity] ?? 0,
      runtime: runtime ? {
        status: runtime.status ?? "unknown",
        active: Boolean(runtime.active),
        updated_at: runtime.updated_at ?? null,
        metrics: safeMetricValue(runtime.metrics ?? {})
      } : {
        status: "not_connected",
        active: false,
        updated_at: null,
        metrics: {}
      }
    };
  });

  const maturity = summarizeCounts(components, "maturity");
  const averageScore = components.length
    ? Math.round(components.reduce((sum, component) => sum + component.maturity_score, 0) / components.length)
    : 0;
  const checklist = checklistCounts(input?.checklistText);
  const latestCommitFiles = asArray(git?.latest_commit_files).map(String);
  const changedFiles = asArray(git?.changed_files).map(String);

  const snapshot = {
    observed_at: now,
    catalog_version: catalog?.schema_version ?? null,
    progress: {
      maturity_score: averageScore,
      components: components.length,
      verified: (maturity.verified ?? 0) + (maturity.live_tool ?? 0),
      simulated: maturity.simulated ?? 0,
      partial: maturity.partial ?? 0,
      pending: (maturity.pending ?? 0) + (maturity.specified ?? 0),
      checklist,
      artifacts: {
        required: required.length,
        manifest_files: manifest?.file_count ?? null,
        root_digest: manifest?.root_digest ?? null,
        schemas: required.filter((path) => path.startsWith("schemas/")).length,
        specs: required.filter((path) => path.startsWith("spec/")).length,
        validators: required.filter((path) => /^tools\/validate_/.test(path)).length,
        tests: required.filter((path) => path.includes("/test/") || path.includes(".test.")).length
      }
    },
    repository: {
      branch: git?.branch ?? null,
      commit: git?.commit ?? null,
      commit_time: git?.commit_time ?? null,
      dirty: Boolean(git?.dirty),
      changed_files: changedFiles,
      latest_commit_files: latestCommitFiles,
      affected_by_worktree: affectedComponents(changedFiles, catalog),
      affected_by_latest_commit: affectedComponents(latestCommitFiles, catalog)
    },
    layers,
    components,
    flow: asArray(catalog?.flow).map(String)
  };
  snapshot.fingerprint = stableFingerprint(snapshot);
  return snapshot;
}

export function assertObserverSnapshotSafe(snapshot) {
  const violations = [];
  const visit = (value, trail) => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      const nextTrail = trail ? `${trail}.${key}` : key;
      if (FORBIDDEN_PUBLIC_FIELDS.has(key)) violations.push(nextTrail);
      visit(child, nextTrail);
    }
  };
  visit(snapshot, "");
  if (violations.length > 0) {
    throw new Error(`observer_snapshot_contains_forbidden_fields:${violations.join(",")}`);
  }
  return true;
}

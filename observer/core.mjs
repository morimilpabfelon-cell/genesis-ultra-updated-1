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
      instance_id: projection?.instance_id ?? instanceIds[0] ?? null,
      body_ids: [...new Set(events.map((event) => event.body_id).filter(Boolean))],
      consistent_instance: instanceIds.length <= 1
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
    latest_workflow: runs[0] ?? null
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

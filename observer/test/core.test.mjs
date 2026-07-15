import test from "node:test";
import assert from "node:assert/strict";
import {
  affectedComponents,
  assertObserverSnapshotSafe,
  buildGithubSnapshot,
  buildLocalSnapshot,
  buildProjectSnapshot,
  parseRepositorySlug
} from "../core.mjs";

const events = [
  {
    event_id: "evt_0",
    instance_id: "inst_1",
    body_id: "body_a",
    sequence: 0,
    previous_event_hash: "GENESIS",
    event_hash: "evsha256:first",
    event_type: "sense.vision.observation",
    actor: "body",
    content_digest: "sha256:aaa",
    observed_at: "2026-07-15T00:00:00Z",
    privacy: "private_local",
    raw_content: "must never leave the server"
  },
  {
    event_id: "evt_1",
    instance_id: "inst_1",
    body_id: "body_a",
    sequence: 1,
    previous_event_hash: "evsha256:first",
    event_hash: "evsha256:second",
    event_type: "knowledge.relation.proposed",
    actor: "instance",
    content_digest: "sha256:bbb",
    observed_at: "2026-07-15T00:00:01Z",
    privacy: "private_local"
  }
];

const projection = {
  instance_id: "inst_1",
  projection_id: "psha256:projection",
  projection_digest: "sha256:digest",
  projection_profile: "genesis.memory.associative.algorithm.v0.1",
  coverage_status: "complete",
  source_event_count: 2,
  nodes: [
    { node_id: "n0", node_kind: "observation", subject_digest: "sha256:aaa", source_event_refs: ["evt_0"] },
    { node_id: "n1", node_kind: "concept", subject_digest: "sha256:bbb", source_event_refs: ["evt_1"] }
  ],
  edges: [
    {
      edge_id: "e0",
      source_node_id: "n0",
      target_node_id: "n1",
      relation: "memory.next",
      derivation: "extracted",
      confidence_basis_points: 10000,
      source_event_refs: ["evt_0", "evt_1"],
      confirmation_event_ref: null
    }
  ]
};

const catalog = {
  schema_version: "genesis.observer.system-map.v0.1",
  layers: [{ id: "foundation", name: "Fundamentos" }],
  flow: ["identity", "reasoning"],
  components: [
    {
      id: "identity",
      name: "Identidad",
      layer: "foundation",
      maturity: "verified",
      description: "Identidad portable",
      keywords: ["identity", "seed"],
      required_evidence: ["spec", "schema", "conformance", "implementation"]
    },
    {
      id: "reasoning",
      name: "Razonamiento",
      layer: "foundation",
      maturity: "pending",
      description: "Motor futuro",
      keywords: ["reasoning"],
      required_evidence: ["spec", "schema", "conformance", "implementation"]
    }
  ]
};

test("parseRepositorySlug accepts HTTPS, SSH and owner/repo", () => {
  assert.equal(parseRepositorySlug("https://github.com/acme/genesis.git"), "acme/genesis");
  assert.equal(parseRepositorySlug("git@github.com:acme/genesis.git"), "acme/genesis");
  assert.equal(parseRepositorySlug("acme/genesis"), "acme/genesis");
  assert.equal(parseRepositorySlug("https://example.com/acme/genesis"), null);
});

test("buildLocalSnapshot exposes digests and topology but strips raw memory", () => {
  const snapshot = buildLocalSnapshot({
    profile: "genesis.memory.associative.projection.conformance.v0.1",
    status: "draft",
    source_memory_events: events,
    projection
  }, { now: "2026-07-15T00:01:00Z", sourcePath: "fixture.json" });

  assert.equal(snapshot.source.mode, "conformance_fixture");
  assert.equal(snapshot.memory.integrity.status, "valid");
  assert.equal(snapshot.memory.count, 2);
  assert.equal(snapshot.projection.node_count, 2);
  assert.equal(snapshot.projection.edge_count, 1);
  assert.equal(snapshot.memory.events[0].raw_content, undefined);
  assertObserverSnapshotSafe(snapshot);
});

test("buildLocalSnapshot detects a broken append-only chain", () => {
  const broken = structuredClone(events);
  broken[1].previous_event_hash = "evsha256:wrong";
  const snapshot = buildLocalSnapshot({ source_memory_events: broken, projection });
  assert.equal(snapshot.memory.integrity.status, "broken");
  assert.equal(snapshot.memory.integrity.continuous, false);
});

test("runtime subsystem metrics are sanitized before publication", () => {
  const snapshot = buildLocalSnapshot({
    runtime: true,
    source_memory_events: events,
    projection,
    subsystems: {
      senses: {
        status: "active",
        active: true,
        updated_at: "2026-07-15T00:02:00Z",
        metrics: { accepted: 2, token: "must disappear", nested: { secret: "hidden", safe: 1 } }
      }
    }
  });
  assert.equal(snapshot.runtime.subsystems.senses.active, true);
  assert.equal(snapshot.runtime.subsystems.senses.metrics.accepted, 2);
  assert.equal(snapshot.runtime.subsystems.senses.metrics.token, undefined);
  assert.equal(snapshot.runtime.subsystems.senses.metrics.nested.secret, undefined);
  assertObserverSnapshotSafe(snapshot);
});

test("buildGithubSnapshot normalizes repository activity and changed files", () => {
  const snapshot = buildGithubSnapshot({
    repository: { default_branch: "main", open_issues_count: 2, html_url: "https://github.com/acme/genesis" },
    commits: [{ sha: "abc", commit: { message: "Add observer\n\nBody", author: { name: "Eidon", date: "2026-07-15T00:00:00Z" } }, html_url: "https://github.com/acme/genesis/commit/abc" }],
    pulls: [{ number: 13, title: "Live observer", state: "open", draft: false, user: { login: "eidon" }, updated_at: "2026-07-15T00:00:00Z" }],
    runs: { workflow_runs: [{ id: 9, name: "Conformance", status: "completed", conclusion: "success", run_number: 26 }] },
    latest_commit: { files: [{ filename: "observer/app.js", status: "modified", additions: 4, deletions: 1, changes: 5 }] },
    latest_pull_number: 13,
    latest_pull_files: [{ filename: "observer/system-map.json", status: "added", additions: 10, deletions: 0, changes: 10 }]
  }, { repository: "acme/genesis", mode: "authenticated" });

  assert.equal(snapshot.repository_state.default_branch, "main");
  assert.equal(snapshot.commits[0].message, "Add observer");
  assert.equal(snapshot.pulls[0].number, 13);
  assert.equal(snapshot.latest_workflow.conclusion, "success");
  assert.equal(snapshot.connection.authenticated, true);
  assert.equal(snapshot.latest_commit_files[0].changes, 5);
  assert.equal(snapshot.latest_pull.files[0].filename, "observer/system-map.json");
});

test("buildProjectSnapshot maps evidence, progress, git impact and runtime", () => {
  const snapshot = buildProjectSnapshot({
    catalog,
    requiredArtifacts: {
      required: [
        "spec/INSTANCE_IDENTITY_AND_GROWTH.md",
        "schemas/instance_identity.schema.json",
        "conformance/instance_identity_vectors.json",
        "tools/validate_instance_identity.py"
      ]
    },
    manifest: { file_count: 4, root_digest: "sha256:root" },
    checklistText: "- [x] identidad\n- [ ] razonamiento\n",
    runtimeSubsystems: { identity: { status: "active", active: true, metrics: { bodies: 1 } } },
    git: {
      branch: "main",
      commit: "abc",
      dirty: true,
      changed_files: ["schemas/instance_identity.schema.json"],
      latest_commit_files: ["spec/INSTANCE_IDENTITY_AND_GROWTH.md"]
    }
  }, { now: "2026-07-15T00:03:00Z" });

  assert.equal(snapshot.progress.components, 2);
  assert.equal(snapshot.progress.verified, 1);
  assert.equal(snapshot.progress.pending, 1);
  assert.equal(snapshot.progress.checklist.checked, 1);
  assert.equal(snapshot.components[0].evidence_coverage, 100);
  assert.equal(snapshot.components[0].runtime.active, true);
  assert.deepEqual(snapshot.repository.affected_by_worktree, ["identity"]);
  assert.equal(snapshot.progress.artifacts.schemas, 1);
  assertObserverSnapshotSafe(snapshot);
});

test("affectedComponents maps paths without inventing unrelated organs", () => {
  assert.deepEqual(
    affectedComponents(["schemas/instance_identity.schema.json"], catalog),
    ["identity"]
  );
  assert.deepEqual(affectedComponents(["README.md"], catalog), []);
});

test("observer safety guard rejects forbidden fields", () => {
  assert.throws(
    () => assertObserverSnapshotSafe({ local: { token: "secret" } }),
    /observer_snapshot_contains_forbidden_fields/
  );
});

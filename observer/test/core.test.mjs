import test from "node:test";
import assert from "node:assert/strict";
import {
  assertObserverSnapshotSafe,
  buildGithubSnapshot,
  buildLocalSnapshot,
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

test("buildGithubSnapshot normalizes repository activity", () => {
  const snapshot = buildGithubSnapshot({
    repository: { default_branch: "main", open_issues_count: 2, html_url: "https://github.com/acme/genesis" },
    commits: [{ sha: "abc", commit: { message: "Add observer\n\nBody", author: { name: "Eidon", date: "2026-07-15T00:00:00Z" } }, html_url: "https://github.com/acme/genesis/commit/abc" }],
    pulls: [{ number: 13, title: "Live observer", state: "open", draft: false, user: { login: "eidon" }, updated_at: "2026-07-15T00:00:00Z" }],
    runs: { workflow_runs: [{ id: 9, name: "Conformance", status: "completed", conclusion: "success", run_number: 26 }] }
  }, { repository: "acme/genesis", mode: "authenticated" });

  assert.equal(snapshot.repository_state.default_branch, "main");
  assert.equal(snapshot.commits[0].message, "Add observer");
  assert.equal(snapshot.pulls[0].number, 13);
  assert.equal(snapshot.latest_workflow.conclusion, "success");
  assert.equal(snapshot.connection.authenticated, true);
});

test("observer safety guard rejects forbidden fields", () => {
  assert.throws(
    () => assertObserverSnapshotSafe({ local: { token: "secret" } }),
    /observer_snapshot_contains_forbidden_fields/
  );
});

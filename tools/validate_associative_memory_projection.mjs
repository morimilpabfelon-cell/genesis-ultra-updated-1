import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/associative_memory_projection_vectors.json"), "utf8")
);

const PROJECTION_FIELDS = new Set([
  "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
  "coverage_status", "source_first_sequence", "source_last_sequence", "source_event_count",
  "source_last_event_hash", "nodes", "edges", "projection_digest"
]);
const NODE_FIELDS = new Set(["node_id", "node_kind", "subject_digest", "source_event_refs"]);
const EDGE_FIELDS = new Set([
  "edge_id", "source_node_id", "target_node_id", "relation", "derivation",
  "confidence_basis_points", "source_event_refs", "confirmation_event_ref"
]);
const EVENT_REQUIRED_FIELDS = new Set([
  "schema_version", "hash_profile", "event_id", "instance_id", "body_id", "sequence",
  "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
  "observed_at", "provenance_digest", "privacy", "event_hash"
]);
const EVENT_ALLOWED_FIELDS = new Set([
  ...EVENT_REQUIRED_FIELDS, "content_ref", "provenance_ref", "signature"
]);
const IDENTITY_AUTHORITY_FIELDS = new Set([
  "companion_name", "guardian_id", "seed_id", "seed_root_hash", "identity_digest",
  "active_writer", "authority_epoch", "write_memory"
]);
const RAW_PLATFORM_FIELDS = new Set([
  "raw_content", "payload", "label", "embedding", "absolute_path", "platform_handle",
  "platform_account", "vendor", "token", "credential"
]);
const EXPECTED_DOMAINS = {
  memory_event: "genesis.memory.event.v0.1",
  node: "genesis.memory.associative.node.v0.1",
  edge: "genesis.memory.associative.edge.v0.1",
  projection_id: "genesis.memory.associative.projection.id.v0.1",
  projection: "genesis.memory.associative.projection.v0.1"
};
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const NODE_ID_PATTERN = /^nsha256:[a-f0-9]{64}$/;
const EDGE_ID_PATTERN = /^esha256:[a-f0-9]{64}$/;
const PROJECTION_ID_PATTERN = /^psha256:[a-f0-9]{64}$/;

class ConformanceError extends Error {}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function sortedUtf8(values) {
  return [...values].sort(compareUtf8);
}

function frame(value) {
  if (typeof value !== "string") throw new ConformanceError("field_must_be_string");
  if (value !== value.normalize("NFC")) throw new ConformanceError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}

function hashFields(domain, fields, prefix = "sha256:") {
  const preimage = Buffer.concat([frame(domain), ...fields.map((field) => frame(field))]);
  return `${prefix}${crypto.createHash("sha256").update(preimage).digest("hex")}`;
}

function exactFields(value, expected, label) {
  const actual = Object.keys(value);
  const additional = actual.filter((field) => !expected.has(field));
  if (additional.some((field) => IDENTITY_AUTHORITY_FIELDS.has(field))) {
    throw new ConformanceError("projection_contains_identity_authority");
  }
  if (additional.some((field) => RAW_PLATFORM_FIELDS.has(field))) {
    throw new ConformanceError("projection_contains_raw_or_platform_data");
  }
  if (actual.length !== expected.size || [...expected].some((field) => !actual.includes(field))) {
    throw new ConformanceError(`${label}_fields_invalid`);
  }
}

function computeMemoryEventHash(event) {
  return hashFields(EXPECTED_DOMAINS.memory_event, [
    event.schema_version, event.event_id, event.instance_id, event.body_id,
    String(event.sequence), event.previous_event_hash, event.event_type, event.actor,
    event.content_digest, event.content_type, event.observed_at, event.provenance_digest,
    event.privacy
  ], "evsha256:");
}

function computeNodeId(node) {
  const refs = sortedUtf8(node.source_event_refs);
  return hashFields(EXPECTED_DOMAINS.node, [
    node.node_kind, node.subject_digest, String(refs.length), ...refs
  ], "nsha256:");
}

function computeEdgeId(edge) {
  const refs = sortedUtf8(edge.source_event_refs);
  return hashFields(EXPECTED_DOMAINS.edge, [
    edge.source_node_id, edge.target_node_id, edge.relation, edge.derivation,
    String(edge.confidence_basis_points), String(refs.length), ...refs,
    edge.confirmation_event_ref === null ? "" : edge.confirmation_event_ref
  ], "esha256:");
}

function computeProjectionId(projection) {
  return hashFields(EXPECTED_DOMAINS.projection_id, [
    projection.schema_version, projection.instance_id, projection.projection_profile,
    projection.coverage_status, String(projection.source_first_sequence),
    String(projection.source_last_sequence), String(projection.source_event_count),
    projection.source_last_event_hash
  ], "psha256:");
}

function computeProjectionDigest(projection) {
  const nodeIds = sortedUtf8(projection.nodes.map((node) => node.node_id));
  const edgeIds = sortedUtf8(projection.edges.map((edge) => edge.edge_id));
  return hashFields(EXPECTED_DOMAINS.projection, [
    projection.schema_version, projection.hash_profile, projection.projection_id,
    projection.instance_id, projection.projection_profile, projection.coverage_status,
    String(projection.source_first_sequence), String(projection.source_last_sequence),
    String(projection.source_event_count), projection.source_last_event_hash,
    String(nodeIds.length), ...nodeIds, String(edgeIds.length), ...edgeIds
  ]);
}

function nodeKindForEvent(eventType) {
  if (eventType.startsWith("sense.")) return "observation";
  if (eventType === "knowledge.relation.confirmed") return "decision";
  if (eventType.startsWith("knowledge.")) return "concept";
  if (eventType.startsWith("body.")) return "body";
  if (eventType.startsWith("time.")) return "time_anchor";
  return "memory_event";
}

function buildProjection(events, coverageStatus) {
  const projection = {
    schema_version: "genesis.memory.associative.projection.v0.1",
    hash_profile: "genesis.hash.fields.v0.1",
    projection_id: "",
    instance_id: events[0].instance_id,
    projection_profile: "genesis.memory.associative.algorithm.v0.1",
    coverage_status: coverageStatus,
    source_first_sequence: events[0].sequence,
    source_last_sequence: events.at(-1).sequence,
    source_event_count: events.length,
    source_last_event_hash: events.at(-1).event_hash,
    nodes: [],
    edges: [],
    projection_digest: ""
  };
  projection.projection_id = computeProjectionId(projection);

  const nodesByEvent = new Map();
  for (const event of events) {
    const node = {
      node_id: "",
      node_kind: nodeKindForEvent(event.event_type),
      subject_digest: event.content_digest,
      source_event_refs: [event.event_id]
    };
    node.node_id = computeNodeId(node);
    nodesByEvent.set(event.event_id, node);
    projection.nodes.push(node);
  }
  projection.nodes.sort((left, right) => compareUtf8(left.node_id, right.node_id));

  function addEdge(sourceEvent, targetEvent, relation, derivation, confidence, confirmationRef) {
    const edge = {
      edge_id: "",
      source_node_id: nodesByEvent.get(sourceEvent.event_id).node_id,
      target_node_id: nodesByEvent.get(targetEvent.event_id).node_id,
      relation,
      derivation,
      confidence_basis_points: confidence,
      source_event_refs: sortedUtf8([sourceEvent.event_id, targetEvent.event_id]),
      confirmation_event_ref: confirmationRef
    };
    edge.edge_id = computeEdgeId(edge);
    projection.edges.push(edge);
  }

  for (let index = 1; index < events.length; index += 1) {
    addEdge(events[index - 1], events[index], "memory.next", "extracted", 10000, null);
  }
  for (let index = 2; index < events.length; index += 1) {
    addEdge(events[index - 2], events[index], "context.nearby", "inferred", 5000, null);
  }
  for (let index = 1; index < events.length; index += 1) {
    const current = events[index];
    const previous = events[index - 1];
    if (
      current.event_type === "knowledge.relation.confirmed"
      && previous.event_type === "knowledge.relation.proposed"
    ) {
      addEdge(
        current,
        previous,
        "knowledge.confirms",
        "confirmed",
        10000,
        current.event_id
      );
    }
  }
  projection.edges.sort((left, right) => compareUtf8(left.edge_id, right.edge_id));
  projection.projection_digest = computeProjectionDigest(projection);
  return projection;
}

function validateMemoryEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new ConformanceError("source_memory_events_invalid");
  }
  const eventIds = events.map((event) => event.event_id);
  if (new Set(eventIds).size !== eventIds.length) {
    throw new ConformanceError("duplicate_source_event_id");
  }
  for (const event of events) {
    const fields = Object.keys(event);
    if (
      [...EVENT_REQUIRED_FIELDS].some((field) => !fields.includes(field))
      || fields.some((field) => !EVENT_ALLOWED_FIELDS.has(field))
    ) {
      throw new ConformanceError("source_memory_event_fields_invalid");
    }
    if (event.schema_version !== "genesis.memory.event.v0.1") {
      throw new ConformanceError("source_memory_event_schema_invalid");
    }
    if (event.hash_profile !== "genesis.hash.fields.v0.1") {
      throw new ConformanceError("source_memory_event_hash_profile_invalid");
    }
  }
  const instanceId = events[0].instance_id;
  if (events.some((event) => event.instance_id !== instanceId)) {
    throw new ConformanceError("source_instance_id_mismatch");
  }
  for (const event of events) {
    if (computeMemoryEventHash(event) !== event.event_hash) {
      throw new ConformanceError("source_memory_event_hash_mismatch");
    }
  }
  events.forEach((event, index) => {
    if (index > 0) {
      const previous = events[index - 1];
      if (
        event.sequence !== previous.sequence + 1
        || event.previous_event_hash !== previous.event_hash
      ) {
        throw new ConformanceError("source_memory_chain_broken");
      }
    } else if (event.sequence === 0 && event.previous_event_hash !== "GENESIS") {
      throw new ConformanceError("source_memory_chain_broken");
    }
  });
  return { instanceId, eventById: new Map(events.map((event) => [event.event_id, event])) };
}

function validateProjection(projection, events) {
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    throw new ConformanceError("projection_invalid");
  }
  exactFields(projection, PROJECTION_FIELDS, "projection");
  if (projection.schema_version !== "genesis.memory.associative.projection.v0.1") {
    throw new ConformanceError("projection_schema_version_invalid");
  }
  if (projection.hash_profile !== "genesis.hash.fields.v0.1") {
    throw new ConformanceError("projection_hash_profile_invalid");
  }
  if (projection.projection_profile !== "genesis.memory.associative.algorithm.v0.1") {
    throw new ConformanceError("projection_profile_invalid");
  }
  if (!["complete", "partial"].includes(projection.coverage_status)) {
    throw new ConformanceError("coverage_status_invalid");
  }

  const { instanceId, eventById } = validateMemoryEvents(events);
  if (projection.instance_id !== instanceId) {
    throw new ConformanceError("projection_instance_id_mismatch");
  }
  if (
    projection.source_first_sequence !== events[0].sequence
    || projection.source_last_sequence !== events.at(-1).sequence
  ) {
    throw new ConformanceError("source_sequence_boundary_mismatch");
  }
  if (projection.source_event_count !== events.length) {
    throw new ConformanceError("source_event_count_mismatch");
  }
  if (projection.source_last_event_hash !== events.at(-1).event_hash) {
    throw new ConformanceError("source_last_event_hash_mismatch");
  }
  if (
    projection.coverage_status === "complete"
    && projection.source_event_count
      !== projection.source_last_sequence - projection.source_first_sequence + 1
  ) {
    throw new ConformanceError("complete_coverage_not_contiguous");
  }
  if (!PROJECTION_ID_PATTERN.test(projection.projection_id)) {
    throw new ConformanceError("projection_id_format_invalid");
  }
  if (computeProjectionId(projection) !== projection.projection_id) {
    throw new ConformanceError("projection_id_mismatch");
  }

  const nodes = projection.nodes;
  if (!Array.isArray(nodes) || nodes.length === 0) throw new ConformanceError("nodes_invalid");
  const nodeIds = nodes.map((node) => node.node_id);
  if (new Set(nodeIds).size !== nodeIds.length) throw new ConformanceError("duplicate_node_id");
  if (nodeIds.some((id, index) => id !== sortedUtf8(nodeIds)[index])) {
    throw new ConformanceError("nodes_not_sorted");
  }
  for (const node of nodes) {
    exactFields(node, NODE_FIELDS, "node");
    const refs = node.source_event_refs;
    if (!Array.isArray(refs) || refs.length === 0) {
      throw new ConformanceError("node_source_event_refs_invalid");
    }
    if (new Set(refs).size !== refs.length) throw new ConformanceError("duplicate_source_event_ref");
    if (refs.some((ref, index) => ref !== sortedUtf8(refs)[index])) {
      throw new ConformanceError("source_event_refs_not_sorted");
    }
    if (refs.some((ref) => !eventById.has(ref))) throw new ConformanceError("unknown_source_event_ref");
    if (!SHA256_PATTERN.test(node.subject_digest)) throw new ConformanceError("node_subject_digest_invalid");
    if (!NODE_ID_PATTERN.test(node.node_id)) throw new ConformanceError("node_id_format_invalid");
    if (computeNodeId(node) !== node.node_id) throw new ConformanceError("node_id_mismatch");
  }

  const edges = projection.edges;
  if (!Array.isArray(edges)) throw new ConformanceError("edges_invalid");
  const edgeIds = edges.map((edge) => edge.edge_id);
  if (new Set(edgeIds).size !== edgeIds.length) throw new ConformanceError("duplicate_edge_id");
  if (edgeIds.some((id, index) => id !== sortedUtf8(edgeIds)[index])) {
    throw new ConformanceError("edges_not_sorted");
  }
  const nodeIdSet = new Set(nodeIds);
  for (const edge of edges) {
    exactFields(edge, EDGE_FIELDS, "edge");
    const refs = edge.source_event_refs;
    if (!Array.isArray(refs) || refs.length === 0) {
      throw new ConformanceError("edge_source_event_refs_invalid");
    }
    if (new Set(refs).size !== refs.length) throw new ConformanceError("duplicate_source_event_ref");
    if (refs.some((ref, index) => ref !== sortedUtf8(refs)[index])) {
      throw new ConformanceError("source_event_refs_not_sorted");
    }
    if (refs.some((ref) => !eventById.has(ref))) throw new ConformanceError("unknown_source_event_ref");
    if (!nodeIdSet.has(edge.source_node_id) || !nodeIdSet.has(edge.target_node_id)) {
      throw new ConformanceError("edge_endpoint_missing");
    }
    if (edge.source_node_id === edge.target_node_id) {
      throw new ConformanceError("self_association_forbidden");
    }
    if (!EDGE_ID_PATTERN.test(edge.edge_id)) throw new ConformanceError("edge_id_format_invalid");
    if (computeEdgeId(edge) !== edge.edge_id) throw new ConformanceError("edge_id_mismatch");

    const confidence = edge.confidence_basis_points;
    const confirmationRef = edge.confirmation_event_ref;
    if (edge.derivation === "extracted") {
      if (confidence !== 10000) throw new ConformanceError("extracted_confidence_invalid");
      if (confirmationRef !== null) throw new ConformanceError("extracted_confirmation_forbidden");
    } else if (edge.derivation === "inferred") {
      if (!Number.isSafeInteger(confidence) || confidence < 0 || confidence >= 10000) {
        throw new ConformanceError("inferred_confidence_invalid");
      }
      if (confirmationRef !== null) throw new ConformanceError("inferred_confirmation_forbidden");
    } else if (edge.derivation === "confirmed") {
      if (confidence !== 10000) throw new ConformanceError("confirmed_confidence_invalid");
      if (confirmationRef === null) throw new ConformanceError("confirmed_confirmation_required");
      if (!refs.includes(confirmationRef)) {
        throw new ConformanceError("confirmation_event_not_in_source_refs");
      }
      const confirmationEvent = eventById.get(confirmationRef);
      if (
        confirmationEvent === undefined
        || confirmationEvent.event_type !== "knowledge.relation.confirmed"
        || !["guardian", "instance"].includes(confirmationEvent.actor)
      ) {
        throw new ConformanceError("confirmation_event_invalid");
      }
    } else {
      throw new ConformanceError("edge_derivation_invalid");
    }
  }

  if (computeProjectionDigest(projection) !== projection.projection_digest) {
    throw new ConformanceError("projection_digest_mismatch");
  }
  if (!isDeepStrictEqual(projection, buildProjection(events, projection.coverage_status))) {
    throw new ConformanceError("projection_rebuild_mismatch");
  }
  return { events: events.length, nodes: nodes.length, edges: edges.length };
}

function applyMutation(testCase, baseProjection, baseEvents) {
  const projection = structuredClone(baseProjection);
  const events = structuredClone(baseEvents);
  const mutation = testCase.mutation;
  switch (mutation.operation) {
    case "projection_add_field":
    case "projection_set":
      projection[mutation.field] = mutation.value;
      break;
    case "source_event_set":
      events[mutation.index][mutation.field] = mutation.value;
      break;
    case "node_set":
    case "node_add_field":
      projection.nodes[mutation.index][mutation.field] = mutation.value;
      break;
    case "node_reverse_refs":
      projection.nodes[mutation.index].source_event_refs.reverse();
      break;
    case "nodes_reverse":
      projection.nodes.reverse();
      break;
    case "node_duplicate":
      projection.nodes.push(structuredClone(projection.nodes[mutation.index]));
      break;
    case "edge_set":
      projection.edges[mutation.index][mutation.field] = mutation.value;
      break;
    case "edges_reverse":
      projection.edges.reverse();
      break;
    case "edge_duplicate":
      projection.edges.push(structuredClone(projection.edges[mutation.index]));
      break;
    default:
      throw new ConformanceError(`unknown_projection_mutation:${mutation.operation}`);
  }
  for (const index of mutation.recompute_source_event_hashes ?? []) {
    events[index].event_hash = computeMemoryEventHash(events[index]);
  }
  for (const index of mutation.recompute_node_ids ?? []) {
    projection.nodes[index].node_id = computeNodeId(projection.nodes[index]);
  }
  if ((mutation.recompute_node_ids ?? []).length > 0) {
    projection.nodes.sort((left, right) => compareUtf8(left.node_id, right.node_id));
  }
  for (const index of mutation.recompute_edge_ids ?? []) {
    projection.edges[index].edge_id = computeEdgeId(projection.edges[index]);
  }
  if ((mutation.recompute_edge_ids ?? []).length > 0) {
    projection.edges.sort((left, right) => compareUtf8(left.edge_id, right.edge_id));
  }
  if (mutation.recompute_projection_digest) {
    projection.projection_digest = computeProjectionDigest(projection);
  }
  return { projection, events };
}

function evaluateRejection(testCase, projection, events) {
  const candidate = applyMutation(testCase, projection, events);
  try {
    validateProjection(candidate.projection, candidate.events);
  } catch (error) {
    if (error instanceof ConformanceError) return error.message;
    throw error;
  }
  return null;
}

function main() {
  const failures = [];
  if (vectors.profile !== "genesis.memory.associative.projection.conformance.v0.1") {
    failures.push("vector_profile_invalid");
  }
  if (vectors.status !== "draft") failures.push("vector_status_invalid");
  if (JSON.stringify(vectors.domains) !== JSON.stringify(EXPECTED_DOMAINS)) {
    failures.push("vector_domains_invalid");
  }

  let counts = { events: 0, nodes: 0, edges: 0 };
  try {
    counts = validateProjection(vectors.projection, vectors.source_memory_events);
  } catch (error) {
    failures.push(`positive_projection:${error.message}`);
  }
  const derivations = new Set(vectors.projection.edges.map((edge) => edge.derivation));
  if (
    derivations.size !== 3
    || !["extracted", "inferred", "confirmed"].every((value) => derivations.has(value))
  ) {
    failures.push("derivation_fixture_coverage_invalid");
  }

  for (const testCase of vectors.must_reject) {
    const actual = evaluateRejection(testCase, vectors.projection, vectors.source_memory_events);
    if (actual !== testCase.expected_error) {
      failures.push(`${testCase.case_id}:expected=${testCase.expected_error}:actual=${actual}`);
    }
  }
  if (failures.length > 0) {
    failures.forEach((failure) => console.error(`FAIL ${failure}`));
    process.exitCode = 1;
    return;
  }
  console.log(`OK accepted memory chain (${counts.events} events)`);
  console.log(`OK deterministic associative projection (${counts.nodes} nodes, ${counts.edges} edges)`);
  console.log("OK provenance keeps extracted, inferred, and confirmed relations distinct");
  console.log(`OK associative boundary rejection cases (${vectors.must_reject.length})`);
  console.log("NOTE The projection is a rebuildable cache, never memory or identity authority.");
}

main();

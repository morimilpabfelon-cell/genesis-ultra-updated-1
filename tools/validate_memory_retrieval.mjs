#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VECTORS = path.join(ROOT, "conformance", "memory_retrieval_vectors.json");

const DOMAINS = {
  memory_event: "genesis.memory.event.v0.1",
  record: "genesis.memory.retrieval.record.v0.1",
  frame: "genesis.memory.retrieval.frame.v0.1",
  checkpoint: "genesis.memory.retrieval.checkpoint.v0.1",
  query: "genesis.memory.retrieval.query.v0.1",
  query_result: "genesis.memory.retrieval.query.result.v0.1",
  projection_id: "genesis.memory.retrieval.projection.id.v0.1",
  projection: "genesis.memory.retrieval.projection.v0.1"
};
const PROFILE = "genesis.memory.retrieval.algorithm.v0.1";
const EVENT_FIELDS = new Set([
  "schema_version", "hash_profile", "event_id", "instance_id", "body_id", "sequence",
  "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
  "observed_at", "provenance_digest", "privacy", "event_hash"
]);
const RECORD_FIELDS = new Set([
  "record_id", "event_id", "gate_decision_ref", "content_digest", "normalized_text", "accepted_at"
]);
const PROJECTION_FIELDS = new Set([
  "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
  "coverage_status", "source_first_sequence", "source_last_sequence", "source_event_count",
  "source_last_event_hash", "record_count", "frames", "lexicon", "checkpoints",
  "query_results", "projection_digest"
]);
const FRAME_FIELDS = new Set([
  "frame_id", "event_id", "sequence", "observed_at", "content_digest", "content_type",
  "token_count", "terms"
]);
const TERM_FIELDS = new Set(["term", "frequency"]);
const LEXICON_FIELDS = new Set(["term", "document_frequency", "event_refs"]);
const CHECKPOINT_FIELDS = new Set(["sequence", "frame_count", "frames_digest"]);
const QUERY_RESULT_SET_FIELDS = new Set([
  "query_id", "query_digest", "normalized_terms", "as_of_sequence", "top_k",
  "candidate_count", "results", "result_digest"
]);
const RESULT_FIELDS = new Set([
  "rank", "event_id", "frame_id", "sequence", "score", "lexical_score", "graph_score",
  "temporal_score", "matched_terms", "reason_codes"
]);
const IDENTITY_AUTHORITY_FIELDS = new Set([
  "companion_name", "guardian_id", "seed_id", "seed_root_hash", "identity_digest",
  "active_writer", "authority_epoch", "write_memory"
]);
const RAW_PLATFORM_FIELDS = new Set([
  "raw_content", "payload", "embedding", "absolute_path", "platform_handle",
  "platform_account", "vendor", "token", "credential", "normalized_text"
]);

class ConformanceError extends Error {}

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
function utf8Sorted(values) { return [...values].sort(utf8Compare); }
function frame(value) {
  if (typeof value !== "string") throw new ConformanceError("field_must_be_string");
  if (value.normalize("NFC") !== value) throw new ConformanceError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  const preimage = Buffer.concat([frame(domain), ...fields.map(frame)]);
  return `${prefix}${crypto.createHash("sha256").update(preimage).digest("hex")}`;
}
function sameSet(actual, expected) {
  return actual.size === expected.size && [...actual].every((item) => expected.has(item));
}
function exactFields(value, expected, label) {
  const actual = new Set(Object.keys(value));
  const extra = [...actual].filter((key) => !expected.has(key));
  if (extra.some((key) => IDENTITY_AUTHORITY_FIELDS.has(key))) {
    throw new ConformanceError("retrieval_contains_identity_authority");
  }
  if (extra.some((key) => RAW_PLATFORM_FIELDS.has(key))) {
    throw new ConformanceError("retrieval_contains_raw_or_platform_data");
  }
  if (!sameSet(actual, expected)) throw new ConformanceError(`${label}_fields_invalid`);
}
function normalizeTerms(text) {
  if (typeof text !== "string") throw new ConformanceError("retrieval_text_invalid");
  if (text.normalize("NFC") !== text) throw new ConformanceError("retrieval_text_not_nfc");
  const folded = text.toLocaleLowerCase("und").normalize("NFKD").replace(/\p{M}/gu, "");
  return folded.match(/[a-z0-9]+/g) ?? [];
}
function computeMemoryEventHash(event) {
  return hashFields(DOMAINS.memory_event, [
    event.schema_version, event.event_id, event.instance_id, event.body_id, String(event.sequence),
    event.previous_event_hash, event.event_type, event.actor, event.content_digest, event.content_type,
    event.observed_at, event.provenance_digest, event.privacy
  ], "evsha256:");
}
function computeRecordId(record) {
  return hashFields(DOMAINS.record, [
    record.event_id, record.gate_decision_ref, record.content_digest, record.accepted_at
  ], "rrsha256:");
}
function termFrequencies(text) {
  const tokens = normalizeTerms(text);
  const counts = new Map();
  for (const token of tokens) counts.set(token, (counts.get(token) ?? 0) + 1);
  return {
    terms: utf8Sorted([...counts.keys()]).map((term) => ({ term, frequency: counts.get(term) })),
    tokenCount: tokens.length
  };
}
function computeFrameId(item) {
  const flattened = item.terms.flatMap((term) => [term.term, String(term.frequency)]);
  return hashFields(DOMAINS.frame, [
    item.event_id, String(item.sequence), item.observed_at, item.content_digest, item.content_type,
    String(item.token_count), String(item.terms.length), ...flattened
  ], "rfsha256:");
}
function computeCheckpointDigest(sequence, frames) {
  const ids = frames.filter((item) => item.sequence <= sequence).map((item) => item.frame_id);
  return hashFields(DOMAINS.checkpoint, [String(sequence), String(ids.length), ...ids]);
}
function computeQueryDigest(query, normalized) {
  const anchors = utf8Sorted(query.anchor_event_refs ?? []);
  return hashFields(DOMAINS.query, [
    query.query_id, String(query.as_of_sequence), String(query.top_k), String(normalized.length),
    ...normalized, String(anchors.length), ...anchors
  ], "rqsha256:");
}
function buildAdjacency(associative) {
  const nodes = Array.isArray(associative?.nodes) ? associative.nodes : [];
  const edges = Array.isArray(associative?.edges) ? associative.edges : [];
  const refsByNode = new Map(nodes
    .filter((node) => node && typeof node.node_id === "string")
    .map((node) => [node.node_id, new Set(node.source_event_refs ?? [])]));
  const adjacency = new Map();
  const add = (left, right) => {
    if (!adjacency.has(left)) adjacency.set(left, new Set());
    adjacency.get(left).add(right);
  };
  for (const edge of edges) {
    const left = refsByNode.get(edge?.source_node_id) ?? new Set();
    const right = refsByNode.get(edge?.target_node_id) ?? new Set();
    for (const source of left) for (const target of right) {
      if (source === target) continue;
      add(source, target);
      add(target, source);
    }
  }
  return adjacency;
}
function computeResultDigest(resultSet) {
  const flattened = resultSet.results.flatMap((result) => [
    String(result.rank), result.event_id, result.frame_id, String(result.sequence), String(result.score),
    String(result.lexical_score), String(result.graph_score), String(result.temporal_score),
    String(result.matched_terms.length), ...result.matched_terms,
    String(result.reason_codes.length), ...result.reason_codes
  ]);
  return hashFields(DOMAINS.query_result, [
    resultSet.query_digest, String(resultSet.candidate_count), String(resultSet.results.length), ...flattened
  ]);
}
function executeQuery(query, frames, adjacency, latestSequence) {
  const normalized = utf8Sorted(new Set(normalizeTerms(query.text)));
  const asOf = query.as_of_sequence;
  const topK = query.top_k;
  if (!Number.isSafeInteger(asOf) || asOf < 0 || asOf > latestSequence) {
    throw new ConformanceError("query_as_of_sequence_invalid");
  }
  if (!Number.isSafeInteger(topK) || topK < 1 || topK > 20) {
    throw new ConformanceError("query_top_k_invalid");
  }
  const candidates = frames.filter((item) => item.sequence <= asOf);
  const candidateCount = candidates.length;
  const anchors = new Set(query.anchor_event_refs ?? []);
  const known = new Set(candidates.map((item) => item.event_id));
  if ([...anchors].some((item) => !known.has(item))) {
    throw new ConformanceError("query_anchor_event_unknown_or_future");
  }
  const df = new Map(normalized.map((term) => [
    term,
    candidates.filter((item) => item.terms.some((pair) => pair.term === term)).length
  ]));
  const scored = [];
  for (const item of candidates) {
    const freq = new Map(item.terms.map((pair) => [pair.term, pair.frequency]));
    const matched = normalized.filter((term) => freq.has(term));
    let lexical = 0;
    for (const term of matched) {
      const rarity = Math.floor(((candidateCount + 1) * 100000) / (df.get(term) + 1));
      const tf = freq.get(term);
      const tfWeight = Math.floor((tf * 1000) / (tf + 1));
      lexical += Math.floor((rarity * tfWeight) / 1000);
    }
    let graph = 0;
    let graphReason = null;
    if (anchors.has(item.event_id)) {
      graph = 300000;
      graphReason = "graph_anchor";
    } else if ([...anchors].some((anchor) => adjacency.get(anchor)?.has(item.event_id))) {
      graph = 180000;
      graphReason = "graph_neighbor";
    }
    const temporal = Math.floor(((item.sequence + 1) * 100000) / (asOf + 1));
    if (lexical === 0 && graph === 0) continue;
    const reasons = [];
    if (lexical) reasons.push("lexical_match");
    if (graphReason) reasons.push(graphReason);
    scored.push({
      event_id: item.event_id,
      frame_id: item.frame_id,
      sequence: item.sequence,
      score: lexical * 7 + graph * 2 + temporal,
      lexical_score: lexical,
      graph_score: graph,
      temporal_score: temporal,
      matched_terms: matched,
      reason_codes: reasons
    });
  }
  scored.sort((left, right) =>
    right.score - left.score || right.sequence - left.sequence || utf8Compare(left.event_id, right.event_id));
  const results = scored.slice(0, topK).map((item, index) => ({ rank: index + 1, ...item }));
  const resultSet = {
    query_id: query.query_id,
    query_digest: computeQueryDigest(query, normalized),
    normalized_terms: normalized,
    as_of_sequence: asOf,
    top_k: topK,
    candidate_count: candidateCount,
    results,
    result_digest: ""
  };
  resultSet.result_digest = computeResultDigest(resultSet);
  return resultSet;
}
function computeProjectionId(projection) {
  return hashFields(DOMAINS.projection_id, [
    projection.schema_version, projection.instance_id, projection.projection_profile,
    projection.coverage_status, String(projection.source_first_sequence),
    String(projection.source_last_sequence), String(projection.source_event_count),
    projection.source_last_event_hash
  ], "rpsha256:");
}
function computeProjectionDigest(projection) {
  const lexiconFlat = projection.lexicon.flatMap((item) => [
    item.term, String(item.document_frequency), String(item.event_refs.length), ...item.event_refs
  ]);
  return hashFields(DOMAINS.projection, [
    projection.schema_version, projection.hash_profile, projection.projection_id,
    projection.instance_id, projection.projection_profile, projection.coverage_status,
    String(projection.source_first_sequence), String(projection.source_last_sequence),
    String(projection.source_event_count), projection.source_last_event_hash,
    String(projection.record_count), String(projection.frames.length),
    ...projection.frames.map((item) => item.frame_id),
    String(projection.lexicon.length), ...lexiconFlat,
    String(projection.checkpoints.length), ...projection.checkpoints.map((item) => item.frames_digest),
    String(projection.query_results.length), ...projection.query_results.map((item) => item.result_digest)
  ]);
}
function validateInputs(document) {
  if (document.profile !== "genesis.memory.retrieval.conformance.v0.1") {
    throw new ConformanceError("retrieval_conformance_profile_invalid");
  }
  if (JSON.stringify(document.domains) !== JSON.stringify(DOMAINS)) {
    throw new ConformanceError("retrieval_domains_invalid");
  }
  const events = document.source_memory_events;
  const records = document.accepted_records;
  const queries = document.queries;
  if (!Array.isArray(events) || events.length === 0) throw new ConformanceError("source_memory_events_invalid");
  if (!Array.isArray(records) || records.length !== events.length) throw new ConformanceError("accepted_record_coverage_invalid");
  if (!Array.isArray(queries) || queries.length === 0) throw new ConformanceError("retrieval_queries_invalid");
  const instance = events[0]?.instance_id;
  const eventIds = new Set();
  events.forEach((event, index) => {
    exactFields(event, EVENT_FIELDS, "source_event");
    if (event.instance_id !== instance) throw new ConformanceError("source_instance_id_mismatch");
    if (event.sequence !== index) throw new ConformanceError("source_memory_sequence_invalid");
    const expectedPrevious = index === 0 ? "GENESIS" : events[index - 1].event_hash;
    if (event.previous_event_hash !== expectedPrevious) throw new ConformanceError("source_memory_chain_broken");
    if (event.event_hash !== computeMemoryEventHash(event)) throw new ConformanceError("source_memory_event_hash_mismatch");
    if (eventIds.has(event.event_id)) throw new ConformanceError("source_memory_event_duplicate");
    eventIds.add(event.event_id);
  });
  const byEvent = new Map(events.map((event) => [event.event_id, event]));
  const recordEvents = new Set();
  for (const record of records) {
    exactFields(record, RECORD_FIELDS, "accepted_record");
    if (!byEvent.has(record.event_id)) throw new ConformanceError("accepted_record_event_unknown");
    if (recordEvents.has(record.event_id)) throw new ConformanceError("accepted_record_duplicate");
    recordEvents.add(record.event_id);
    const event = byEvent.get(record.event_id);
    if (record.content_digest !== event.content_digest) throw new ConformanceError("accepted_record_content_digest_mismatch");
    if (typeof record.gate_decision_ref !== "string" || !record.gate_decision_ref.startsWith("gate_")) {
      throw new ConformanceError("accepted_record_gate_decision_invalid");
    }
    const tokens = normalizeTerms(record.normalized_text);
    if (tokens.length === 0) throw new ConformanceError("accepted_record_text_empty");
    if (Buffer.byteLength(record.normalized_text, "utf8") > 4096) throw new ConformanceError("accepted_record_text_too_large");
    if (record.record_id !== computeRecordId(record)) throw new ConformanceError("accepted_record_id_mismatch");
  }
  const queryIds = new Set();
  for (const query of queries) {
    if (!sameSet(new Set(Object.keys(query)), new Set(["query_id", "text", "top_k", "as_of_sequence", "anchor_event_refs"]))) {
      throw new ConformanceError("retrieval_query_fields_invalid");
    }
    if (queryIds.has(query.query_id)) throw new ConformanceError("retrieval_query_duplicate");
    queryIds.add(query.query_id);
    normalizeTerms(query.text);
    if (!Array.isArray(query.anchor_event_refs) || new Set(query.anchor_event_refs).size !== query.anchor_event_refs.length) {
      throw new ConformanceError("query_anchor_event_refs_invalid");
    }
    if (query.anchor_event_refs.some((item) => !eventIds.has(item))) {
      throw new ConformanceError("query_anchor_event_unknown_or_future");
    }
  }
}
function buildProjection(document) {
  validateInputs(document);
  const events = document.source_memory_events;
  const recordsByEvent = new Map(document.accepted_records.map((item) => [item.event_id, item]));
  const frames = events.map((event) => {
    const record = recordsByEvent.get(event.event_id);
    const { terms, tokenCount } = termFrequencies(record.normalized_text);
    const item = {
      frame_id: "",
      event_id: event.event_id,
      sequence: event.sequence,
      observed_at: event.observed_at,
      content_digest: event.content_digest,
      content_type: event.content_type,
      token_count: tokenCount,
      terms
    };
    item.frame_id = computeFrameId(item);
    return item;
  });
  const lexiconMap = new Map();
  for (const item of frames) for (const pair of item.terms) {
    if (!lexiconMap.has(pair.term)) lexiconMap.set(pair.term, []);
    lexiconMap.get(pair.term).push(item.event_id);
  }
  const lexicon = utf8Sorted([...lexiconMap.keys()]).map((term) => ({
    term,
    document_frequency: lexiconMap.get(term).length,
    event_refs: lexiconMap.get(term)
  }));
  const checkpoints = frames.map((item) => ({
    sequence: item.sequence,
    frame_count: item.sequence + 1,
    frames_digest: computeCheckpointDigest(item.sequence, frames)
  }));
  const adjacency = buildAdjacency(document.associative_projection ?? {});
  const queryResults = document.queries.map((query) => executeQuery(query, frames, adjacency, events.at(-1).sequence));
  const projection = {
    schema_version: "genesis.memory.retrieval.projection.v0.1",
    hash_profile: "genesis.hash.fields.v0.1",
    projection_id: "",
    instance_id: events[0].instance_id,
    projection_profile: PROFILE,
    coverage_status: "complete",
    source_first_sequence: events[0].sequence,
    source_last_sequence: events.at(-1).sequence,
    source_event_count: events.length,
    source_last_event_hash: events.at(-1).event_hash,
    record_count: document.accepted_records.length,
    frames,
    lexicon,
    checkpoints,
    query_results: queryResults,
    projection_digest: ""
  };
  projection.projection_id = computeProjectionId(projection);
  projection.projection_digest = computeProjectionDigest(projection);
  return projection;
}
function deepEqual(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function validateProjection(document) {
  const expected = buildProjection(document);
  const projection = document.projection;
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    throw new ConformanceError("retrieval_projection_missing");
  }
  exactFields(projection, PROJECTION_FIELDS, "retrieval_projection");
  if (projection.projection_profile !== PROFILE) throw new ConformanceError("retrieval_projection_profile_invalid");
  for (const item of projection.frames) {
    exactFields(item, FRAME_FIELDS, "retrieval_frame");
    for (const pair of item.terms) {
      exactFields(pair, TERM_FIELDS, "retrieval_term");
      if (!/^[a-z0-9]+$/.test(pair.term)) throw new ConformanceError("retrieval_term_invalid");
    }
  }
  for (const item of projection.lexicon) exactFields(item, LEXICON_FIELDS, "retrieval_lexicon");
  for (const item of projection.checkpoints) exactFields(item, CHECKPOINT_FIELDS, "retrieval_checkpoint");
  for (const item of projection.query_results) {
    exactFields(item, QUERY_RESULT_SET_FIELDS, "retrieval_query_result_set");
    for (const result of item.results) exactFields(result, RESULT_FIELDS, "retrieval_query_result");
  }
  const scalarFields = [
    "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
    "coverage_status", "source_first_sequence", "source_last_sequence", "source_event_count",
    "source_last_event_hash", "record_count"
  ];
  for (const field of scalarFields) {
    if (projection[field] !== expected[field]) throw new ConformanceError(`retrieval_projection_${field}_mismatch`);
  }
  if (!deepEqual(projection.frames, expected.frames)) throw new ConformanceError("retrieval_frames_mismatch");
  if (!deepEqual(projection.lexicon, expected.lexicon)) throw new ConformanceError("retrieval_lexicon_mismatch");
  if (!deepEqual(projection.checkpoints, expected.checkpoints)) throw new ConformanceError("retrieval_checkpoints_mismatch");
  if (!deepEqual(projection.query_results, expected.query_results)) throw new ConformanceError("retrieval_query_results_mismatch");
  if (projection.projection_digest !== computeProjectionDigest(projection)) {
    throw new ConformanceError("retrieval_projection_digest_mismatch");
  }
  return expected;
}
function applyMutation(document, mutation) {
  switch (mutation.operation) {
    case "projection_add_field":
    case "projection_set":
      document.projection[mutation.field] = mutation.value;
      break;
    case "frame_add_field":
    case "frame_set":
      document.projection.frames[mutation.index][mutation.field] = mutation.value;
      break;
    case "lexicon_set":
      document.projection.lexicon[mutation.index][mutation.field] = mutation.value;
      break;
    case "checkpoint_set":
      document.projection.checkpoints[mutation.index][mutation.field] = mutation.value;
      break;
    case "query_result_set":
      document.projection.query_results[mutation.query_index].results[mutation.result_index][mutation.field] = mutation.value;
      break;
    case "source_event_set":
      document.source_memory_events[mutation.index][mutation.field] = mutation.value;
      if (mutation.recompute_event_hash) {
        document.source_memory_events[mutation.index].event_hash = computeMemoryEventHash(document.source_memory_events[mutation.index]);
      }
      break;
    case "record_set":
      document.accepted_records[mutation.index][mutation.field] = mutation.value;
      if (mutation.recompute_record_id) {
        document.accepted_records[mutation.index].record_id = computeRecordId(document.accepted_records[mutation.index]);
      }
      break;
    case "record_duplicate":
      document.accepted_records.push(structuredClone(document.accepted_records[mutation.index]));
      break;
    case "query_set":
      document.queries[mutation.index][mutation.field] = mutation.value;
      break;
    default:
      throw new Error(`unknown mutation: ${mutation.operation}`);
  }
}
function validateNegativeCases(document) {
  let count = 0;
  for (const testCase of document.must_reject ?? []) {
    const mutated = structuredClone(document);
    applyMutation(mutated, testCase.mutation);
    try {
      validateProjection(mutated);
    } catch (error) {
      if (!(error instanceof ConformanceError)) throw error;
      if (error.message !== testCase.expected_error) {
        throw new Error(`${testCase.case_id}: expected ${testCase.expected_error}, got ${error.message}`);
      }
      count += 1;
      continue;
    }
    throw new Error(`${testCase.case_id}: mutation accepted`);
  }
  return count;
}

export {
  ConformanceError,
  DOMAINS,
  PROFILE,
  buildProjection,
  executeQuery,
  normalizeTerms,
  validateInputs,
  validateProjection
};

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const vectorPath = process.argv[2] ? path.resolve(process.argv[2]) : VECTORS;
  const document = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
  const expected = validateProjection(document);
  const rejected = validateNegativeCases(document);
  console.log(`OK deterministic retrieval projection (${expected.frames.length} frames, ${expected.lexicon.length} terms)`);
  console.log(`OK lexical, graph-aware and temporal queries (${expected.query_results.length})`);
  console.log(`OK replay checkpoints (${expected.checkpoints.length})`);
  console.log(`OK retrieval boundary rejection cases (${rejected})`);
  console.log("NOTE Retrieval remains a rebuildable read model; append-only memory remains authoritative.");
}

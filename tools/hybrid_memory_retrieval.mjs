#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  buildProjection as buildBaseProjection,
  normalizeTerms,
  DOMAINS as BASE_DOMAINS,
  ConformanceError as BaseConformanceError
} from "./validate_memory_retrieval.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "hybrid_memory_retrieval_vectors.json");
const PROFILE = "genesis.memory.hybrid_retrieval.conformance.v0.1";
const ALGORITHM = "genesis.memory.hybrid_retrieval.algorithm.v0.1";
const SCHEMA = "genesis.memory.hybrid_retrieval.projection.v0.1";
const HASH_PROFILE = "genesis.hash.fields.v0.1";
const SEMANTIC_PROFILE_SCHEMA = "genesis.memory.semantic.profile.v0.1";
const SEMANTIC_ADAPTER = "genesis.memory.semantic.simplex_u16.v0.1";
const SEMANTIC_SIMILARITY = "genesis.memory.semantic.dot_product.v0.1";
const DOMAINS = Object.freeze({
  semantic_profile: "genesis.memory.semantic.profile.v0.1",
  semantic_frame: "genesis.memory.semantic.frame.v0.1",
  semantic_query_text: "genesis.memory.semantic.query.text.v0.1",
  semantic_query: "genesis.memory.semantic.query.v0.1",
  hybrid_query: "genesis.memory.hybrid_retrieval.query.v0.1",
  hybrid_result: "genesis.memory.hybrid_retrieval.query.result.v0.1",
  hybrid_projection_id: "genesis.memory.hybrid_retrieval.projection.id.v0.1",
  hybrid_projection: "genesis.memory.hybrid_retrieval.projection.v0.1"
});
const PROFILE_FIELDS = new Set([
  "schema_version", "hash_profile", "adapter_profile", "model_digest", "dimensions",
  "vector_scale", "similarity_profile", "profile_digest"
]);
const SEMANTIC_FRAME_FIELDS = new Set(["event_id", "content_digest", "vector", "vector_digest"]);
const SEMANTIC_QUERY_FIELDS = new Set(["query_id", "query_text_digest", "vector", "vector_digest"]);
const PROJECTION_FIELDS = new Set([
  "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
  "base_projection_digest", "semantic_profile_digest", "semantic_coverage_status",
  "source_event_count", "source_last_sequence", "semantic_frame_count", "semantic_frames",
  "query_results", "projection_digest"
]);
const SEMANTIC_REF_FIELDS = new Set(["event_id", "vector_digest"]);
const QUERY_RESULT_FIELDS = new Set([
  "query_id", "base_query_digest", "semantic_query_digest", "hybrid_query_digest", "mode",
  "normalized_terms", "as_of_sequence", "top_k", "candidate_count", "results", "result_digest"
]);
const RESULT_FIELDS = new Set([
  "rank", "event_id", "frame_id", "sequence", "score", "lexical_score", "semantic_score",
  "graph_score", "temporal_score", "matched_terms", "reason_codes"
]);
const IDENTITY_AUTHORITY_FIELDS = new Set([
  "companion_name", "guardian_id", "seed_id", "seed_root_hash", "identity_digest",
  "active_writer", "authority_epoch", "write_memory"
]);
const RAW_PLATFORM_FIELDS = new Set([
  "raw_content", "payload", "embedding", "absolute_path", "platform_handle",
  "platform_account", "vendor", "token", "credential", "normalized_text"
]);

class HybridConformanceError extends Error {}

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
function utf8Sorted(values) { return [...values].sort(utf8Compare); }
function frame(value) {
  if (typeof value !== "string") throw new HybridConformanceError("field_must_be_string");
  if (value.normalize("NFC") !== value) throw new HybridConformanceError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  const payload = Buffer.concat([frame(domain), ...fields.map((value) => frame(String(value)))]);
  return `${prefix}${crypto.createHash("sha256").update(payload).digest("hex")}`;
}
function sameSet(left, right) {
  return left.size === right.size && [...left].every((item) => right.has(item));
}
function exactFields(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HybridConformanceError(`${label}_invalid`);
  }
  const actual = new Set(Object.keys(value));
  const extra = [...actual].filter((key) => !expected.has(key));
  if (extra.some((key) => IDENTITY_AUTHORITY_FIELDS.has(key))) {
    throw new HybridConformanceError("hybrid_contains_identity_authority");
  }
  if (extra.some((key) => RAW_PLATFORM_FIELDS.has(key))) {
    throw new HybridConformanceError("hybrid_contains_raw_or_platform_data");
  }
  if (!sameSet(actual, expected)) throw new HybridConformanceError(`${label}_fields_invalid`);
}
function semanticProfileDigest(profile) {
  return hashFields(DOMAINS.semantic_profile, [
    profile.schema_version, profile.hash_profile, profile.adapter_profile, profile.model_digest,
    profile.dimensions, profile.vector_scale, profile.similarity_profile
  ]);
}
function semanticFrameDigest(profileDigest, item) {
  return hashFields(DOMAINS.semantic_frame, [
    profileDigest, item.event_id, item.content_digest, item.vector.length, ...item.vector
  ], "sfsha256:");
}
function semanticTextDigest(text) {
  return hashFields(DOMAINS.semantic_query_text, [text]);
}
function semanticQueryDigest(profileDigest, item) {
  return hashFields(DOMAINS.semantic_query, [
    profileDigest, item.query_id, item.query_text_digest, item.vector.length, ...item.vector
  ], "sqsha256:");
}
function validateVector(vector, profile) {
  if (!Array.isArray(vector) || vector.length !== profile.dimensions) {
    throw new HybridConformanceError("semantic_vector_dimensions_invalid");
  }
  if (vector.some((value) => !Number.isSafeInteger(value) || value < 0 || value > profile.vector_scale)) {
    throw new HybridConformanceError("semantic_vector_component_invalid");
  }
  if (vector.reduce((sum, value) => sum + value, 0) !== profile.vector_scale) {
    throw new HybridConformanceError("semantic_vector_scale_mismatch");
  }
}
function validateSemanticLayer(document, baseProjection) {
  const profile = document.semantic_profile;
  const frames = document.semantic_frames;
  const queries = document.semantic_queries;
  if (!Array.isArray(frames) || !Array.isArray(queries)) {
    throw new HybridConformanceError("semantic_collections_invalid");
  }
  if (profile === null) {
    if (frames.length !== 0 || queries.length !== 0) {
      throw new HybridConformanceError("semantic_disabled_data_forbidden");
    }
    return { profile: null, frameMap: new Map(), queryMap: new Map() };
  }
  exactFields(profile, PROFILE_FIELDS, "semantic_profile");
  if (profile.schema_version !== SEMANTIC_PROFILE_SCHEMA || profile.hash_profile !== HASH_PROFILE) {
    throw new HybridConformanceError("semantic_profile_version_invalid");
  }
  if (profile.adapter_profile !== SEMANTIC_ADAPTER) {
    throw new HybridConformanceError("semantic_adapter_profile_invalid");
  }
  if (profile.similarity_profile !== SEMANTIC_SIMILARITY) {
    throw new HybridConformanceError("semantic_similarity_profile_invalid");
  }
  if (!Number.isSafeInteger(profile.dimensions) || profile.dimensions < 2 || profile.dimensions > 1024) {
    throw new HybridConformanceError("semantic_dimensions_invalid");
  }
  if (!Number.isSafeInteger(profile.vector_scale) || profile.vector_scale < 1 || profile.vector_scale > 32767) {
    throw new HybridConformanceError("semantic_vector_scale_invalid");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(profile.model_digest)) {
    throw new HybridConformanceError("semantic_model_digest_invalid");
  }
  if (profile.profile_digest !== semanticProfileDigest(profile)) {
    throw new HybridConformanceError("semantic_profile_digest_mismatch");
  }
  const events = new Map(document.source_memory_events.map((event) => [event.event_id, event]));
  const frameMap = new Map();
  for (const item of frames) {
    exactFields(item, SEMANTIC_FRAME_FIELDS, "semantic_frame");
    const event = events.get(item.event_id);
    if (!event) throw new HybridConformanceError("semantic_frame_event_unknown");
    if (frameMap.has(item.event_id)) throw new HybridConformanceError("semantic_frame_duplicate");
    if (item.content_digest !== event.content_digest) {
      throw new HybridConformanceError("semantic_frame_content_digest_mismatch");
    }
    validateVector(item.vector, profile);
    if (item.vector_digest !== semanticFrameDigest(profile.profile_digest, item)) {
      throw new HybridConformanceError("semantic_frame_digest_mismatch");
    }
    frameMap.set(item.event_id, item);
  }
  if (frameMap.size !== events.size) throw new HybridConformanceError("semantic_frame_coverage_invalid");
  const baseQueries = new Map(document.queries.map((query) => [query.query_id, query]));
  const queryMap = new Map();
  for (const item of queries) {
    exactFields(item, SEMANTIC_QUERY_FIELDS, "semantic_query");
    const query = baseQueries.get(item.query_id);
    if (!query) throw new HybridConformanceError("semantic_query_unknown");
    if (queryMap.has(item.query_id)) throw new HybridConformanceError("semantic_query_duplicate");
    if (item.query_text_digest !== semanticTextDigest(query.text)) {
      throw new HybridConformanceError("semantic_query_text_digest_mismatch");
    }
    validateVector(item.vector, profile);
    if (item.vector_digest !== semanticQueryDigest(profile.profile_digest, item)) {
      throw new HybridConformanceError("semantic_query_digest_mismatch");
    }
    queryMap.set(item.query_id, item);
  }
  if (baseProjection.frames.length !== frameMap.size) {
    throw new HybridConformanceError("semantic_frame_coverage_invalid");
  }
  return { profile, frameMap, queryMap };
}
function buildAdjacency(associative) {
  const nodes = Array.isArray(associative?.nodes) ? associative.nodes : [];
  const edges = Array.isArray(associative?.edges) ? associative.edges : [];
  const refs = new Map(nodes.map((node) => [node.node_id, new Set(node.source_event_refs ?? [])]));
  const adjacency = new Map();
  const add = (left, right) => {
    if (!adjacency.has(left)) adjacency.set(left, new Set());
    adjacency.get(left).add(right);
  };
  for (const edge of edges) {
    for (const left of refs.get(edge.source_node_id) ?? []) {
      for (const right of refs.get(edge.target_node_id) ?? []) {
        if (left === right) continue;
        add(left, right);
        add(right, left);
      }
    }
  }
  return adjacency;
}
function lexicalEvidence(query, candidates) {
  const normalized = utf8Sorted(new Set(normalizeTerms(query.text)));
  const frequencies = new Map();
  for (const term of normalized) {
    frequencies.set(term, candidates.filter((item) => item.terms.some((pair) => pair.term === term)).length);
  }
  const scores = new Map();
  for (const item of candidates) {
    const terms = new Map(item.terms.map((pair) => [pair.term, pair.frequency]));
    const matched = normalized.filter((term) => terms.has(term));
    let lexical = 0;
    for (const term of matched) {
      const rarity = Math.floor(((candidates.length + 1) * 100000) / (frequencies.get(term) + 1));
      const tfWeight = Math.floor((terms.get(term) * 1000) / (terms.get(term) + 1));
      lexical += Math.floor((rarity * tfWeight) / 1000);
    }
    scores.set(item.event_id, { lexical, matched });
  }
  return { normalized, scores };
}
function computeHybridResultDigest(resultSet) {
  const flattened = resultSet.results.flatMap((result) => [
    String(result.rank), result.event_id, result.frame_id, String(result.sequence), String(result.score),
    String(result.lexical_score), String(result.semantic_score), String(result.graph_score),
    String(result.temporal_score), String(result.matched_terms.length), ...result.matched_terms,
    String(result.reason_codes.length), ...result.reason_codes
  ]);
  return hashFields(DOMAINS.hybrid_result, [
    resultSet.hybrid_query_digest, String(resultSet.candidate_count),
    String(resultSet.results.length), ...flattened
  ]);
}
function executeHybridQuery(query, baseQueryResult, baseProjection, semantic, adjacency) {
  const candidates = baseProjection.frames.filter((item) => item.sequence <= query.as_of_sequence);
  const { normalized, scores } = lexicalEvidence(query, candidates);
  if (JSON.stringify(normalized) !== JSON.stringify(baseQueryResult.normalized_terms)) {
    throw new HybridConformanceError("hybrid_base_query_terms_mismatch");
  }
  const anchors = new Set(query.anchor_event_refs ?? []);
  const semanticQuery = semantic.queryMap.get(query.query_id) ?? null;
  const mode = semanticQuery ? "hybrid" : "lexical_fallback";
  const scaleSquared = semantic.profile ? semantic.profile.vector_scale ** 2 : 1;
  const scored = [];
  for (const item of candidates) {
    const lexicalData = scores.get(item.event_id);
    let semanticScore = 0;
    if (semanticQuery) {
      const frameVector = semantic.frameMap.get(item.event_id).vector;
      const dot = semanticQuery.vector.reduce((sum, value, index) => sum + value * frameVector[index], 0);
      semanticScore = Math.floor((dot * 100000) / scaleSquared);
    }
    let graphScore = 0;
    let graphReason = null;
    if (anchors.has(item.event_id)) {
      graphScore = 300000;
      graphReason = "graph_anchor";
    } else if ([...anchors].some((anchor) => adjacency.get(anchor)?.has(item.event_id))) {
      graphScore = 180000;
      graphReason = "graph_neighbor";
    }
    const temporalScore = Math.floor(((item.sequence + 1) * 100000) / (query.as_of_sequence + 1));
    if (lexicalData.lexical === 0 && semanticScore === 0 && graphScore === 0) continue;
    const reasons = [];
    if (lexicalData.lexical) reasons.push("lexical_match");
    if (semanticScore) reasons.push("semantic_match");
    if (graphReason) reasons.push(graphReason);
    scored.push({
      event_id: item.event_id,
      frame_id: item.frame_id,
      sequence: item.sequence,
      score: lexicalData.lexical * 7 + semanticScore * 6 + graphScore * 2 + temporalScore,
      lexical_score: lexicalData.lexical,
      semantic_score: semanticScore,
      graph_score: graphScore,
      temporal_score: temporalScore,
      matched_terms: lexicalData.matched,
      reason_codes: reasons
    });
  }
  scored.sort((left, right) =>
    right.score - left.score || right.sequence - left.sequence || utf8Compare(left.event_id, right.event_id));
  const semanticQueryDigestValue = semanticQuery?.vector_digest ?? null;
  const hybridQueryDigest = hashFields(DOMAINS.hybrid_query, [
    baseQueryResult.query_digest, semanticQueryDigestValue ?? "", mode
  ], "hqsha256:");
  const resultSet = {
    query_id: query.query_id,
    base_query_digest: baseQueryResult.query_digest,
    semantic_query_digest: semanticQueryDigestValue,
    hybrid_query_digest: hybridQueryDigest,
    mode,
    normalized_terms: normalized,
    as_of_sequence: query.as_of_sequence,
    top_k: query.top_k,
    candidate_count: candidates.length,
    results: scored.slice(0, query.top_k).map((item, index) => ({ rank: index + 1, ...item })),
    result_digest: ""
  };
  resultSet.result_digest = computeHybridResultDigest(resultSet);
  return resultSet;
}
function computeProjectionId(projection) {
  return hashFields(DOMAINS.hybrid_projection_id, [
    projection.schema_version, projection.instance_id, projection.projection_profile,
    projection.base_projection_digest, projection.semantic_profile_digest ?? "",
    projection.semantic_coverage_status, projection.source_event_count,
    projection.source_last_sequence, projection.semantic_frame_count
  ], "hrpsha256:");
}
function computeProjectionDigest(projection) {
  const semanticFlat = projection.semantic_frames.flatMap((item) => [item.event_id, item.vector_digest]);
  return hashFields(DOMAINS.hybrid_projection, [
    projection.schema_version, projection.hash_profile, projection.projection_id,
    projection.instance_id, projection.projection_profile, projection.base_projection_digest,
    projection.semantic_profile_digest ?? "", projection.semantic_coverage_status,
    projection.source_event_count, projection.source_last_sequence, projection.semantic_frame_count,
    projection.semantic_frames.length, ...semanticFlat, projection.query_results.length,
    ...projection.query_results.map((item) => item.result_digest)
  ]);
}
function baseDocument(document) {
  return {
    profile: "genesis.memory.retrieval.conformance.v0.1",
    status: document.status ?? "runtime-derived",
    domains: BASE_DOMAINS,
    source_memory_events: structuredClone(document.source_memory_events),
    accepted_records: structuredClone(document.accepted_records),
    associative_projection: structuredClone(document.associative_projection ?? {}),
    queries: structuredClone(document.queries)
  };
}
function validateDocumentHeader(document) {
  if (document.profile !== PROFILE) throw new HybridConformanceError("hybrid_conformance_profile_invalid");
  if (JSON.stringify(document.domains) !== JSON.stringify(DOMAINS)) {
    throw new HybridConformanceError("hybrid_domains_invalid");
  }
  if (!Array.isArray(document.queries) || document.queries.length === 0) {
    throw new HybridConformanceError("hybrid_queries_invalid");
  }
}
function buildHybridProjection(document) {
  validateDocumentHeader(document);
  let baseProjection;
  try {
    baseProjection = buildBaseProjection(baseDocument(document));
  } catch (error) {
    if (error instanceof BaseConformanceError) throw new HybridConformanceError(error.message);
    throw error;
  }
  const semantic = validateSemanticLayer(document, baseProjection);
  const baseResults = new Map(baseProjection.query_results.map((item) => [item.query_id, item]));
  const adjacency = buildAdjacency(document.associative_projection ?? {});
  const queryResults = document.queries.map((query) =>
    executeHybridQuery(query, baseResults.get(query.query_id), baseProjection, semantic, adjacency));
  const semanticRefs = semantic.profile
    ? document.semantic_frames.map((item) => ({ event_id: item.event_id, vector_digest: item.vector_digest }))
    : [];
  const projection = {
    schema_version: SCHEMA,
    hash_profile: HASH_PROFILE,
    projection_id: "",
    instance_id: baseProjection.instance_id,
    projection_profile: ALGORITHM,
    base_projection_digest: baseProjection.projection_digest,
    semantic_profile_digest: semantic.profile?.profile_digest ?? null,
    semantic_coverage_status: semantic.profile ? "complete" : "disabled",
    source_event_count: baseProjection.source_event_count,
    source_last_sequence: baseProjection.source_last_sequence,
    semantic_frame_count: semanticRefs.length,
    semantic_frames: semanticRefs,
    query_results: queryResults,
    projection_digest: ""
  };
  projection.projection_id = computeProjectionId(projection);
  projection.projection_digest = computeProjectionDigest(projection);
  return projection;
}
function deepEqual(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function validateProjection(document) {
  const expected = buildHybridProjection(document);
  const projection = document.projection;
  exactFields(projection, PROJECTION_FIELDS, "hybrid_projection");
  if (projection.projection_profile !== ALGORITHM) {
    throw new HybridConformanceError("hybrid_projection_profile_invalid");
  }
  for (const item of projection.semantic_frames) exactFields(item, SEMANTIC_REF_FIELDS, "hybrid_semantic_ref");
  for (const item of projection.query_results) {
    exactFields(item, QUERY_RESULT_FIELDS, "hybrid_query_result_set");
    for (const result of item.results) exactFields(result, RESULT_FIELDS, "hybrid_query_result");
  }
  const scalars = [
    "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
    "base_projection_digest", "semantic_profile_digest", "semantic_coverage_status",
    "source_event_count", "source_last_sequence", "semantic_frame_count"
  ];
  for (const field of scalars) {
    if (projection[field] !== expected[field]) throw new HybridConformanceError(`hybrid_projection_${field}_mismatch`);
  }
  if (!deepEqual(projection.semantic_frames, expected.semantic_frames)) {
    throw new HybridConformanceError("hybrid_semantic_frames_mismatch");
  }
  if (!deepEqual(projection.query_results, expected.query_results)) {
    throw new HybridConformanceError("hybrid_query_results_mismatch");
  }
  if (projection.projection_digest !== computeProjectionDigest(projection)) {
    throw new HybridConformanceError("hybrid_projection_digest_mismatch");
  }
  return expected;
}
function getPath(target, parts) {
  return parts.reduce((value, part) => value[part], target);
}
function setPath(target, parts, value) {
  let cursor = target;
  for (const part of parts.slice(0, -1)) cursor = cursor[part];
  cursor[parts.at(-1)] = value;
}
function applyMutation(document, mutation) {
  if (mutation.operation === "set") {
    setPath(document, mutation.path, mutation.value);
  } else if (mutation.operation === "delete") {
    let cursor = document;
    for (const part of mutation.path.slice(0, -1)) cursor = cursor[part];
    if (Array.isArray(cursor)) cursor.splice(Number(mutation.path.at(-1)), 1);
    else delete cursor[mutation.path.at(-1)];
  } else if (mutation.operation === "duplicate") {
    getPath(document, mutation.target).push(structuredClone(getPath(document, mutation.path)));
  } else if (mutation.operation === "append") {
    getPath(document, mutation.path).push(structuredClone(mutation.value));
  } else {
    throw new Error(`unknown_hybrid_mutation:${mutation.operation}`);
  }
  if (Number.isSafeInteger(mutation.recompute_event_hash_index)) {
    const event = document.source_memory_events[mutation.recompute_event_hash_index];
    event.event_hash = hashFields(BASE_DOMAINS.memory_event, [
      event.schema_version, event.event_id, event.instance_id, event.body_id, event.sequence,
      event.previous_event_hash, event.event_type, event.actor, event.content_digest,
      event.content_type, event.observed_at, event.provenance_digest, event.privacy
    ], "evsha256:");
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
      if (!(error instanceof HybridConformanceError)) throw error;
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
function validateConformance(document) {
  const projection = validateProjection(document);
  if (projection.projection_digest !== document.expected?.projection_digest) {
    throw new HybridConformanceError("hybrid_expected_projection_digest_mismatch");
  }
  const resultDigests = Object.fromEntries(projection.query_results.map((item) => [item.query_id, item.result_digest]));
  if (!deepEqual(resultDigests, document.expected?.query_result_digests)) {
    throw new HybridConformanceError("hybrid_expected_query_digests_mismatch");
  }
  const fallbackDocument = structuredClone(document);
  fallbackDocument.semantic_profile = null;
  fallbackDocument.semantic_frames = [];
  fallbackDocument.semantic_queries = [];
  delete fallbackDocument.projection;
  delete fallbackDocument.expected;
  delete fallbackDocument.must_reject;
  const fallback = buildHybridProjection(fallbackDocument);
  if (fallback.projection_digest !== document.expected?.fallback_projection_digest) {
    throw new HybridConformanceError("hybrid_expected_fallback_digest_mismatch");
  }
  if (fallback.query_results.some((item) =>
    item.mode !== "lexical_fallback" || item.results.some((result) => result.semantic_score !== 0))) {
    throw new HybridConformanceError("hybrid_fallback_behavior_invalid");
  }
  return { projection, fallback, rejected: validateNegativeCases(document) };
}
function readJson(file) { return JSON.parse(fs.readFileSync(path.resolve(file), "utf8")); }
function atomicWrite(file, value, exclusive = false) {
  const resolved = path.resolve(file);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  if (exclusive && fs.existsSync(resolved)) throw new Error("output_exists");
  const temporary = `${resolved}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  fs.renameSync(temporary, resolved);
}
function parseOptions(args, latestSequence, dimensions, scale) {
  const options = { topK: 5, asOf: latestSequence, anchors: [], vector: null };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag === "--top-k") options.topK = Number.parseInt(value, 10);
    else if (flag === "--as-of") options.asOf = Number.parseInt(value, 10);
    else if (flag === "--anchor") options.anchors.push(value);
    else if (flag === "--semantic-vector") {
      options.vector = value.split(",").map((item) => Number.parseInt(item, 10));
      if (options.vector.length !== dimensions || options.vector.reduce((sum, item) => sum + item, 0) !== scale) {
        throw new Error("semantic_vector_cli_invalid");
      }
    } else throw new Error(`unknown_option:${flag}`);
    index += 1;
  }
  return options;
}
function usage(code = 0) {
  console.log(`Genesis neutral hybrid memory retrieval\n\nUsage:\n  node tools/hybrid_memory_retrieval.mjs validate [vector.json]\n  node tools/hybrid_memory_retrieval.mjs build <input.json> [output.json]\n  node tools/hybrid_memory_retrieval.mjs sync <input.json> <output.json>\n  node tools/hybrid_memory_retrieval.mjs query <input.json> <text> [--semantic-vector n,n,...] [--top-k N] [--as-of N] [--anchor event_id]\n\nSemantic evidence is optional. Without a semantic query vector the tool uses deterministic lexical fallback. The append-only chain remains authoritative.`);
  process.exit(code);
}

export {
  ALGORITHM,
  DOMAINS,
  HybridConformanceError,
  PROFILE,
  buildHybridProjection,
  semanticFrameDigest,
  semanticProfileDigest,
  semanticQueryDigest,
  semanticTextDigest,
  validateConformance,
  validateProjection
};

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const [command, input, ...rest] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h") usage();
  try {
    if (command === "validate") {
      const { projection, fallback, rejected } = validateConformance(readJson(input ?? DEFAULT_VECTOR));
      console.log(`OK neutral hybrid retrieval (${projection.query_results.length} queries)`);
      console.log(`OK hybrid projection ${projection.projection_digest}`);
      console.log(`OK lexical fallback ${fallback.projection_digest}`);
      console.log(`OK hybrid boundary rejection cases (${rejected})`);
    } else if (command === "build" || command === "sync") {
      if (!input) usage(1);
      const document = readJson(input);
      const projection = buildHybridProjection(document);
      const output = rest[0];
      if (command === "sync" && !output) usage(1);
      if (output) {
        atomicWrite(output, projection, command === "build");
        console.log(`Hybrid retrieval projection written: ${path.resolve(output)}`);
        console.log(`Digest: ${projection.projection_digest}`);
      } else process.stdout.write(`${JSON.stringify(projection, null, 2)}\n`);
    } else if (command === "query") {
      if (!input || rest.length === 0) usage(1);
      const [text, ...flags] = rest;
      const document = readJson(input);
      const latest = document.source_memory_events?.at(-1)?.sequence;
      if (!Number.isSafeInteger(latest)) throw new Error("source_memory_events_invalid");
      const dimensions = document.semantic_profile?.dimensions ?? 0;
      const scale = document.semantic_profile?.vector_scale ?? 0;
      const options = parseOptions(flags, latest, dimensions, scale);
      document.queries = [{
        query_id: "hybrid_cli_query",
        text,
        top_k: options.topK,
        as_of_sequence: options.asOf,
        anchor_event_refs: options.anchors
      }];
      document.semantic_queries = [];
      if (options.vector) {
        if (!document.semantic_profile) throw new Error("semantic_profile_disabled");
        const item = {
          query_id: "hybrid_cli_query",
          query_text_digest: semanticTextDigest(text),
          vector: options.vector,
          vector_digest: ""
        };
        item.vector_digest = semanticQueryDigest(document.semantic_profile.profile_digest, item);
        document.semantic_queries.push(item);
      }
      delete document.projection;
      delete document.expected;
      delete document.must_reject;
      process.stdout.write(`${JSON.stringify(buildHybridProjection(document).query_results[0], null, 2)}\n`);
    } else usage(1);
  } catch (error) {
    const message = error instanceof HybridConformanceError || error instanceof BaseConformanceError
      ? error.message
      : `hybrid_memory_retrieval_failed:${error.message}`;
    console.error(message);
    process.exit(1);
  }
}

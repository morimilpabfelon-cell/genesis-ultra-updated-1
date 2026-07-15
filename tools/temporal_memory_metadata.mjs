#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "temporal_memory_metadata_vectors.json");
const CANONICAL_TIME = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const MENTION_KINDS = new Set(["instant", "interval", "none"]);
const PRECISIONS = new Set(["second", "day", "month", "unknown"]);
const RELATIONS = new Set(["before", "after", "during", "overlaps", "same_time", "none"]);
const SOURCE_KINDS = new Set(["explicit_text", "relative_text", "guardian_confirmed", "no_temporal_claim"]);
const QUERY_TYPES = new Set(["captured_between", "stored_between", "mentioned_between", "before_event", "after_event", "active_at"]);
const AUTHORITY_FIELDS = new Set(["active_writer", "write_memory", "authority_grant", "guardian_key", "seed_root_hash"]);

export class TemporalError extends Error {}
function frame(value) {
  if (typeof value !== "string" || value.normalize("NFC") !== value) throw new TemporalError("temporal_text_invalid");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  return `${prefix}${crypto.createHash("sha256").update(Buffer.concat([frame(domain), ...fields.map(frame)])).digest("hex")}`;
}
function parseTime(value) {
  if (typeof value !== "string" || !CANONICAL_TIME.test(value)) throw new TemporalError("temporal_timestamp_invalid");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().replace(".000Z", "Z") !== value) throw new TemporalError("temporal_timestamp_invalid");
  return ms;
}
function nullable(value) { return value === null ? "" : String(value); }
function exactFields(object, expected, label) {
  if (!object || typeof object !== "object" || Array.isArray(object)) throw new TemporalError(`${label}_invalid`);
  const keys = Object.keys(object);
  if (keys.some((key) => AUTHORITY_FIELDS.has(key))) throw new TemporalError("temporal_contains_authority");
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) throw new TemporalError(`${label}_fields_invalid`);
}
function utf8Compare(a, b) { return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
function sortedUtf8(values) { return [...values].sort(utf8Compare); }
export function computeAnnotationDigest(annotation) {
  return hashFields("genesis.memory.temporal.annotation.v0.1", [annotation.event_id, annotation.content_digest, annotation.capture_time, annotation.storage_time, annotation.mention_kind, nullable(annotation.mentioned_start), nullable(annotation.mentioned_end), annotation.precision, annotation.relation, nullable(annotation.related_event_ref), annotation.source_kind, String(annotation.confidence_milli), annotation.extractor_digest, annotation.evidence_digest], "tmsha256:");
}
export function computeAccessDigest(decision) {
  const refs = sortedUtf8(decision.allowed_event_refs);
  return hashFields("genesis.memory.temporal.access.v0.1", [decision.decision_id, String(decision.as_of_sequence), String(refs.length), ...refs], "tasha256:");
}
export function computeQueryResultDigest(result) {
  const denialFlat = sortedUtf8(Object.keys(result.denial_counts)).flatMap((key) => [key, String(result.denial_counts[key])]);
  return hashFields("genesis.memory.temporal.query.result.v0.1", [result.query_id, result.access_decision_ref, result.query_type, String(result.as_of_sequence), String(result.candidate_count), String(result.matched_event_refs.length), ...result.matched_event_refs, String(denialFlat.length / 2), ...denialFlat]);
}
function computeProjectionId(document) {
  return hashFields("genesis.memory.temporal.projection.id.v0.1", [document.instance_id, document.extraction_profile, String(document.events.length), String(document.events.at(-1).sequence)], "tpsha256:");
}
function computeProjectionDigest(projection) {
  const fields = [projection.schema_version, projection.hash_profile, projection.projection_id, projection.instance_id, projection.extraction_profile, String(projection.source_event_count), String(projection.source_last_sequence), String(projection.annotation_count)];
  for (const annotation of projection.annotations) fields.push(annotation.event_id, annotation.annotation_digest, annotation.mention_kind, nullable(annotation.mentioned_start), nullable(annotation.mentioned_end), annotation.relation, nullable(annotation.related_event_ref));
  fields.push(String(projection.query_results.length));
  for (const result of projection.query_results) fields.push(result.query_id, result.result_digest);
  return hashFields("genesis.memory.temporal.projection.v0.1", fields);
}
function rangeFor(annotation) { return annotation.mention_kind === "none" ? null : [parseTime(annotation.mentioned_start), parseTime(annotation.mentioned_end)]; }
function findEvent(events, id) { return events.find((item) => item.event_id === id); }

export function validateDocument(document) {
  exactFields(document, new Set(["profile", "status", "instance_id", "extraction_profile", "events", "accepted_records", "annotations", "access_decisions", "queries", "expected", "must_reject"]), "temporal_document");
  if (document.profile !== "genesis.memory.temporal_metadata.conformance.v0.1") throw new TemporalError("temporal_profile_invalid");
  if (document.status !== "draft") throw new TemporalError("temporal_status_invalid");
  if (typeof document.instance_id !== "string" || document.instance_id.length === 0) throw new TemporalError("temporal_instance_invalid");
  if (document.extraction_profile !== "genesis.memory.temporal.explicit_adapter.v0.1") throw new TemporalError("temporal_extraction_profile_invalid");
  if (!Array.isArray(document.events) || document.events.length === 0) throw new TemporalError("temporal_events_invalid");
  const eventIds = new Set();
  document.events.forEach((event, index) => {
    exactFields(event, new Set(["event_id", "sequence", "content_digest", "observed_at"]), "temporal_event");
    if (event.sequence !== index) throw new TemporalError("temporal_event_sequence_invalid");
    if (eventIds.has(event.event_id)) throw new TemporalError("temporal_event_duplicate");
    if (!/^sha256:[a-f0-9]{64}$/.test(event.content_digest)) throw new TemporalError("temporal_content_digest_invalid");
    parseTime(event.observed_at); eventIds.add(event.event_id);
  });
  if (!Array.isArray(document.accepted_records) || document.accepted_records.length !== document.events.length) throw new TemporalError("temporal_record_coverage_invalid");
  const recordMap = new Map();
  for (const record of document.accepted_records) {
    exactFields(record, new Set(["event_id", "content_digest", "accepted_at", "text_digest"]), "temporal_record");
    if (!eventIds.has(record.event_id)) throw new TemporalError("temporal_record_event_unknown");
    if (recordMap.has(record.event_id)) throw new TemporalError("temporal_record_duplicate");
    const event = findEvent(document.events, record.event_id);
    if (record.content_digest !== event.content_digest) throw new TemporalError("temporal_record_content_mismatch");
    if (!/^sha256:[a-f0-9]{64}$/.test(record.text_digest)) throw new TemporalError("temporal_text_digest_invalid");
    if (parseTime(record.accepted_at) < parseTime(event.observed_at)) throw new TemporalError("temporal_storage_before_capture");
    recordMap.set(record.event_id, record);
  }
  if (!Array.isArray(document.annotations)) throw new TemporalError("temporal_annotations_invalid");
  const annotationMap = new Map();
  const annotationFields = new Set(["event_id", "content_digest", "capture_time", "storage_time", "mention_kind", "mentioned_start", "mentioned_end", "precision", "relation", "related_event_ref", "source_kind", "confidence_milli", "extractor_digest", "evidence_digest", "annotation_digest"]);
  for (const annotation of document.annotations) {
    exactFields(annotation, annotationFields, "temporal_annotation");
    if (!eventIds.has(annotation.event_id)) throw new TemporalError("temporal_annotation_event_unknown");
    if (annotationMap.has(annotation.event_id)) throw new TemporalError("temporal_annotation_duplicate");
    const event = findEvent(document.events, annotation.event_id), record = recordMap.get(annotation.event_id);
    if (annotation.content_digest !== event.content_digest) throw new TemporalError("temporal_annotation_content_mismatch");
    if (annotation.capture_time !== event.observed_at) throw new TemporalError("temporal_capture_time_mismatch");
    if (annotation.storage_time !== record.accepted_at) throw new TemporalError("temporal_storage_time_mismatch");
    if (!MENTION_KINDS.has(annotation.mention_kind)) throw new TemporalError("temporal_mention_kind_invalid");
    if (!PRECISIONS.has(annotation.precision)) throw new TemporalError("temporal_precision_invalid");
    if (!RELATIONS.has(annotation.relation)) throw new TemporalError("temporal_relation_invalid");
    if (!SOURCE_KINDS.has(annotation.source_kind)) throw new TemporalError("temporal_source_kind_invalid");
    if (!Number.isSafeInteger(annotation.confidence_milli) || annotation.confidence_milli < 0 || annotation.confidence_milli > 1000) throw new TemporalError("temporal_confidence_invalid");
    if (!/^sha256:[a-f0-9]{64}$/.test(annotation.extractor_digest) || !/^sha256:[a-f0-9]{64}$/.test(annotation.evidence_digest)) throw new TemporalError("temporal_provenance_digest_invalid");
    if (annotation.mention_kind === "none") {
      if (annotation.mentioned_start !== null || annotation.mentioned_end !== null) throw new TemporalError("temporal_none_has_interval");
      if (annotation.relation !== "none" || annotation.related_event_ref !== null) throw new TemporalError("temporal_none_has_relation");
      if (annotation.precision !== "unknown" || annotation.source_kind !== "no_temporal_claim" || annotation.confidence_milli !== 0) throw new TemporalError("temporal_none_metadata_invalid");
    } else {
      const start = parseTime(annotation.mentioned_start), end = parseTime(annotation.mentioned_end);
      if (annotation.mention_kind === "instant" && start !== end) throw new TemporalError("temporal_instant_range_invalid");
      if (annotation.mention_kind === "interval" && start >= end) throw new TemporalError("temporal_interval_order_invalid");
      if (annotation.source_kind === "no_temporal_claim") throw new TemporalError("temporal_claim_source_invalid");
      if (annotation.relation === "none" && annotation.related_event_ref !== null) throw new TemporalError("temporal_relation_ref_unexpected");
      if (annotation.relation !== "none") {
        if (annotation.related_event_ref === null) throw new TemporalError("temporal_relation_ref_missing");
        if (!eventIds.has(annotation.related_event_ref)) throw new TemporalError("temporal_relation_target_unknown");
        if (annotation.related_event_ref === annotation.event_id) throw new TemporalError("temporal_relation_self");
      }
    }
    if (annotation.annotation_digest !== computeAnnotationDigest(annotation)) throw new TemporalError("temporal_annotation_digest_mismatch");
    annotationMap.set(annotation.event_id, annotation);
  }
  if (annotationMap.size !== document.events.length) throw new TemporalError("temporal_annotation_coverage_invalid");
  for (const annotation of document.annotations) {
    if (annotation.relation === "none") continue;
    const sourceRange = rangeFor(annotation), targetRange = rangeFor(annotationMap.get(annotation.related_event_ref));
    if (sourceRange === null || targetRange === null) throw new TemporalError("temporal_relation_range_missing");
    const [s0, s1] = sourceRange, [t0, t1] = targetRange;
    const valid = { before: s1 <= t0, after: s0 >= t1, during: s0 >= t0 && s1 <= t1, overlaps: s0 <= t1 && s1 >= t0 && !(s0 >= t0 && s1 <= t1) && !(t0 >= s0 && t1 <= s1), same_time: s0 === t0 && s1 === t1 }[annotation.relation];
    if (!valid) throw new TemporalError("temporal_relation_contradiction");
  }
  if (!Array.isArray(document.access_decisions) || document.access_decisions.length === 0) throw new TemporalError("temporal_access_decisions_invalid");
  const decisionMap = new Map();
  for (const decision of document.access_decisions) {
    exactFields(decision, new Set(["decision_id", "as_of_sequence", "allowed_event_refs", "decision_digest"]), "temporal_access");
    if (decisionMap.has(decision.decision_id)) throw new TemporalError("temporal_access_duplicate");
    if (!Number.isSafeInteger(decision.as_of_sequence) || decision.as_of_sequence < 0 || decision.as_of_sequence >= document.events.length) throw new TemporalError("temporal_access_sequence_invalid");
    if (!Array.isArray(decision.allowed_event_refs) || new Set(decision.allowed_event_refs).size !== decision.allowed_event_refs.length || decision.allowed_event_refs.some((ref) => !eventIds.has(ref))) throw new TemporalError("temporal_access_refs_invalid");
    if (decision.allowed_event_refs.some((ref) => findEvent(document.events, ref).sequence > decision.as_of_sequence)) throw new TemporalError("temporal_access_future_ref");
    if (decision.decision_digest !== computeAccessDigest(decision)) throw new TemporalError("temporal_access_digest_mismatch");
    decisionMap.set(decision.decision_id, decision);
  }
  if (!Array.isArray(document.queries) || document.queries.length === 0) throw new TemporalError("temporal_queries_invalid");
  const queryIds = new Set(), queryFields = new Set(["query_id", "access_decision_ref", "query_type", "start", "end", "at", "anchor_event_ref", "expected_event_refs", "expected_denials", "expected_result_digest"]);
  for (const query of document.queries) {
    exactFields(query, queryFields, "temporal_query");
    if (queryIds.has(query.query_id)) throw new TemporalError("temporal_query_duplicate");
    if (!decisionMap.has(query.access_decision_ref)) throw new TemporalError("temporal_query_access_unknown");
    if (!QUERY_TYPES.has(query.query_type)) throw new TemporalError("temporal_query_type_invalid");
    if (query.start !== null) parseTime(query.start); if (query.end !== null) parseTime(query.end); if (query.at !== null) parseTime(query.at);
    if (query.start !== null && query.end !== null && parseTime(query.start) > parseTime(query.end)) throw new TemporalError("temporal_query_range_invalid");
    if (["captured_between", "stored_between", "mentioned_between"].includes(query.query_type)) {
      if (query.start === null || query.end === null || query.at !== null || query.anchor_event_ref !== null) throw new TemporalError("temporal_query_shape_invalid");
    } else if (query.query_type === "active_at") {
      if (query.at === null || query.start !== null || query.end !== null || query.anchor_event_ref !== null) throw new TemporalError("temporal_query_shape_invalid");
    } else if (!eventIds.has(query.anchor_event_ref) || query.start !== null || query.end !== null || query.at !== null) throw new TemporalError("temporal_query_shape_invalid");
    if (!Array.isArray(query.expected_event_refs) || new Set(query.expected_event_refs).size !== query.expected_event_refs.length) throw new TemporalError("temporal_query_expected_refs_invalid");
    if (!query.expected_denials || typeof query.expected_denials !== "object" || Array.isArray(query.expected_denials)) throw new TemporalError("temporal_query_expected_denials_invalid");
    queryIds.add(query.query_id);
  }
  return { events: document.events, eventIds, recordMap, annotationMap, decisionMap };
}
function temporalMatch(query, annotation, anchor) {
  if (query.query_type === "captured_between") { const value = parseTime(annotation.capture_time); return parseTime(query.start) <= value && value <= parseTime(query.end); }
  if (query.query_type === "stored_between") { const value = parseTime(annotation.storage_time); return parseTime(query.start) <= value && value <= parseTime(query.end); }
  const current = rangeFor(annotation); if (current === null) return false;
  const [start, end] = current;
  if (query.query_type === "mentioned_between") return start <= parseTime(query.end) && end >= parseTime(query.start);
  if (query.query_type === "active_at") { const value = parseTime(query.at); return start <= value && value <= end; }
  const anchorRange = rangeFor(anchor); if (anchorRange === null) throw new TemporalError("temporal_anchor_range_missing");
  const [a0, a1] = anchorRange;
  if (query.query_type === "before_event") return annotation.event_id !== anchor.event_id && end <= a0;
  if (query.query_type === "after_event") return annotation.event_id !== anchor.event_id && start >= a1;
  throw new TemporalError("temporal_query_type_invalid");
}
export function evaluateQuery(document, query, state = null) {
  state ??= validateDocument(document);
  const decision = state.decisionMap.get(query.access_decision_ref), allowed = new Set(decision.allowed_event_refs);
  let anchor = null;
  if (query.anchor_event_ref !== null) {
    if (!allowed.has(query.anchor_event_ref)) throw new TemporalError("temporal_anchor_not_authorized");
    const anchorEvent = findEvent(state.events, query.anchor_event_ref);
    if (anchorEvent.sequence > decision.as_of_sequence) throw new TemporalError("temporal_anchor_future");
    anchor = state.annotationMap.get(query.anchor_event_ref);
  }
  const matched = [], denial = {}; let candidateCount = 0;
  const deny = (reason) => { denial[reason] = (denial[reason] ?? 0) + 1; };
  for (const event of state.events) {
    if (event.sequence > decision.as_of_sequence) { deny("future_event"); continue; }
    if (!allowed.has(event.event_id)) { deny("acl_denied"); continue; }
    candidateCount += 1;
    if (temporalMatch(query, state.annotationMap.get(event.event_id), anchor)) matched.push(event.event_id); else deny("no_temporal_match");
  }
  const result = { query_id: query.query_id, access_decision_ref: decision.decision_id, query_type: query.query_type, as_of_sequence: decision.as_of_sequence, candidate_count: candidateCount, matched_event_refs: matched, denial_counts: denial, result_digest: "" };
  result.result_digest = computeQueryResultDigest(result); return result;
}
export function buildProjection(document) {
  const state = validateDocument(document), results = document.queries.map((query) => evaluateQuery(document, query, state));
  const annotations = document.annotations.map((item) => ({ event_id: item.event_id, annotation_digest: item.annotation_digest, mention_kind: item.mention_kind, mentioned_start: item.mentioned_start, mentioned_end: item.mentioned_end, relation: item.relation, related_event_ref: item.related_event_ref }));
  const projection = { schema_version: "genesis.memory.temporal.projection.v0.1", hash_profile: "genesis.hash.fields.v0.1", projection_id: computeProjectionId(document), instance_id: document.instance_id, extraction_profile: document.extraction_profile, source_event_count: document.events.length, source_last_sequence: document.events.at(-1).sequence, annotation_count: annotations.length, annotations, query_results: results, projection_digest: "" };
  projection.projection_digest = computeProjectionDigest(projection); return projection;
}
function applyMutation(document, mutation) {
  if (mutation.target === "event") document.events[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "record") document.accepted_records[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "annotation") document.annotations[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "annotation_rehash") { const annotation = document.annotations[mutation.index]; annotation[mutation.field] = mutation.value; annotation.annotation_digest = computeAnnotationDigest(annotation); }
  else if (mutation.target === "annotation_remove") document.annotations.splice(mutation.index, 1);
  else if (mutation.target === "annotation_duplicate") document.annotations.push(structuredClone(document.annotations[mutation.index]));
  else if (mutation.target === "access") document.access_decisions[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "access_rehash") { const decision = document.access_decisions[mutation.index]; decision[mutation.field] = mutation.value; decision.decision_digest = computeAccessDigest(decision); }
  else if (mutation.target === "query") document.queries[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "top") document[mutation.field] = mutation.value;
  else throw new Error(`unknown_mutation:${mutation.target}`);
}
function validateVector(document) {
  const projection = buildProjection(document);
  if (projection.projection_id !== document.expected.projection_id) throw new Error("temporal_expected_projection_id_mismatch");
  if (projection.projection_digest !== document.expected.projection_digest) throw new Error("temporal_expected_projection_digest_mismatch");
  document.queries.forEach((query, index) => { const actual = projection.query_results[index]; if (JSON.stringify(actual.matched_event_refs) !== JSON.stringify(query.expected_event_refs) || JSON.stringify(actual.denial_counts) !== JSON.stringify(query.expected_denials) || actual.result_digest !== query.expected_result_digest) throw new Error(`temporal_expected_query_mismatch:${query.query_id}`); });
  let rejected = 0;
  for (const testCase of document.must_reject ?? []) {
    const copy = structuredClone(document); applyMutation(copy, testCase.mutation);
    try { buildProjection(copy); } catch (error) { if (!(error instanceof TemporalError)) throw error; if (error.message !== testCase.expected_error) throw new Error(`${testCase.case_id}:expected:${testCase.expected_error}:got:${error.message}`); rejected += 1; continue; }
    throw new Error(`${testCase.case_id}:mutation_accepted`);
  }
  return { projection, rejected };
}
function atomicWrite(outputPath, value) {
  const resolved = path.resolve(outputPath); fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const temp = `${resolved}.tmp-${process.pid}`; fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, "utf8"); fs.renameSync(temp, resolved);
}
if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const [command = "validate", input = DEFAULT_VECTOR, arg] = process.argv.slice(2);
  try {
    const document = JSON.parse(fs.readFileSync(path.resolve(input), "utf8"));
    if (command === "validate") { const { projection, rejected } = validateVector(document); console.log(`OK temporal memory metadata (${projection.annotations.length} annotations, ${projection.query_results.length} queries)`); console.log(`OK temporal projection ${projection.projection_digest}`); console.log(`OK temporal boundary rejection cases (${rejected})`); console.log("NOTE temporal metadata is derived evidence and never rewrites canonical event timestamps."); }
    else if (command === "build" || command === "sync") { if (!arg) throw new TemporalError("temporal_output_path_required"); const projection = buildProjection(document); atomicWrite(arg, projection); console.log(projection.projection_digest); }
    else if (command === "query") { if (!arg) throw new TemporalError("temporal_query_id_required"); const state = validateDocument(document), query = document.queries.find((item) => item.query_id === arg); if (!query) throw new TemporalError("temporal_query_not_found"); process.stdout.write(`${JSON.stringify(evaluateQuery(document, query, state), null, 2)}\n`); }
    else throw new TemporalError("temporal_command_invalid");
  } catch (error) { console.error(error.message); process.exit(1); }
}

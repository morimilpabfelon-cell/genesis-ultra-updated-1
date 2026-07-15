#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { buildProjection, ConformanceError as RetrievalError, DOMAINS as RETRIEVAL_DOMAINS, normalizeTerms } from "./validate_memory_retrieval.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "memory_gate_retrieval_bridge_vectors.json");
const PROFILE = "genesis.memory.gate.retrieval.bridge.v0.1";
const RECEIPT_SCHEMA = "genesis.memory.gate.retrieval.bridge.receipt.v0.1";
const VIEW_SCHEMA = "genesis.memory.retrieval.accepted.view.v0.1";
const HASH_PROFILE = "genesis.hash.fields.v0.1";
const DOMAINS = Object.freeze({
  observation: "genesis.sense.observation.v0.1",
  observation_signature: "genesis.sense.observation.signature.v0.1",
  gate_decision: "genesis.memory.gate.decision.v0.1",
  gate_signature: "genesis.memory.gate.decision.signature.v0.1",
  memory_event: "genesis.memory.event.v0.1",
  accepted_view: "genesis.memory.retrieval.accepted.view.v0.1",
  bridge_receipt: "genesis.memory.gate.retrieval.bridge.receipt.v0.1"
});
const SETS = {
  observation: new Set(["schema_version","hash_profile","observation_id","instance_id","body_id","observation_sequence","sense","source_kind","captured_at","payload_digest","payload_media_type","evidence_digest","privacy","observation_digest","signature"]),
  gate: new Set(["schema_version","hash_profile","decision_id","observation_id","observation_digest","instance_id","body_id","decision","reason_code","policy_profile","decided_at","memory_event_ref","decision_digest","signature"]),
  event: new Set(["schema_version","hash_profile","event_id","instance_id","body_id","sequence","previous_event_hash","event_type","actor","content_digest","content_type","observed_at","provenance_digest","privacy","event_hash"]),
  view: new Set(["schema_version","hash_profile","event_id","content_digest","content_type","normalized_text","generated_at","generator_profile","view_digest"]),
  key: new Set(["public_key_ref","public_key_hex"]),
  query: new Set(["query_id","text","top_k","as_of_sequence","anchor_event_refs"])
};
const SENSITIVE = new Set(["raw_content","payload","private_key","secret","credential","token","absolute_path","platform_account","platform_handle","embedding"]);
class BridgeError extends Error {}

function frame(value) {
  if (typeof value !== "string") throw new BridgeError("bridge_field_must_be_string");
  if (value.normalize("NFC") !== value) throw new BridgeError("bridge_text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  return `${prefix}${crypto.createHash("sha256").update(Buffer.concat([frame(domain), ...fields.map(frame)])).digest("hex")}`;
}
function exact(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new BridgeError(`${label}_invalid`);
  const fields = Object.keys(value);
  const extra = fields.filter((field) => !expected.has(field));
  if (extra.some((field) => SENSITIVE.has(field))) throw new BridgeError("bridge_contains_sensitive_field");
  if (fields.length !== expected.size || extra.length) throw new BridgeError(`${label}_fields_invalid`);
}
function nfc(value) {
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value) throw new BridgeError("bridge_text_not_nfc");
  } else if (Array.isArray(value)) value.forEach(nfc);
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, child]) => { nfc(key); nfc(child); });
}
function signatureBytes(envelope) {
  return Buffer.concat([frame("genesis.signature.envelope.bytes.v0.1"), ...[
    "schema_version","signature_profile","signer_type","signer_id","key_epoch_id","signed_domain","signed_digest","created_at","public_key_ref"
  ].map((field) => frame(envelope[field]))]);
}
function loadKeys(entries) {
  if (!Array.isArray(entries) || !entries.length) throw new BridgeError("bridge_verification_keys_invalid");
  const result = new Map();
  for (const entry of entries) {
    exact(entry, SETS.key, "bridge_verification_key");
    if (!/^[a-f0-9]{64}$/.test(entry.public_key_hex)) throw new BridgeError("bridge_public_key_encoding_invalid");
    const raw = Buffer.from(entry.public_key_hex, "hex");
    const ref = `sha256:${crypto.createHash("sha256").update(raw).digest("hex")}`;
    if (ref !== entry.public_key_ref) throw new BridgeError("bridge_public_key_ref_mismatch");
    if (result.has(ref)) throw new BridgeError("bridge_public_key_duplicate");
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    result.set(ref, crypto.createPublicKey({ key: der, format: "der", type: "spki" }));
  }
  return result;
}
function verify(envelope, expected, keys, prefix) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) throw new BridgeError(`${prefix}_signature_invalid`);
  if (envelope.schema_version !== "genesis.signature.envelope.v0.1" || envelope.signature_profile !== "genesis.signature.ed25519.v0.1" || envelope.signer_type !== "body" || envelope.signer_id !== expected.bodyId || envelope.signed_domain !== expected.domain || envelope.signed_digest !== expected.digest || envelope.created_at !== expected.createdAt) throw new BridgeError(`${prefix}_signature_unbound`);
  const key = keys.get(envelope.public_key_ref);
  if (!key) throw new BridgeError(`${prefix}_signature_key_unknown`);
  if (!/^[a-f0-9]{128}$/.test(envelope.signature_value) || !crypto.verify(null, signatureBytes(envelope), key, Buffer.from(envelope.signature_value, "hex"))) throw new BridgeError(`${prefix}_signature_invalid`);
}
function observationDigest(item) {
  return hashFields(DOMAINS.observation, [item.schema_version,item.hash_profile,item.observation_id,item.instance_id,item.body_id,String(item.observation_sequence),item.sense,item.source_kind,item.captured_at,item.payload_digest,item.payload_media_type,item.evidence_digest,item.privacy]);
}
function gateDigest(item) {
  return hashFields(DOMAINS.gate_decision, [item.schema_version,item.hash_profile,item.decision_id,item.observation_id,item.observation_digest,item.instance_id,item.body_id,item.decision,item.reason_code,item.policy_profile,item.decided_at,item.memory_event_ref ?? ""]);
}
function eventHash(item) {
  return hashFields(DOMAINS.memory_event, [item.schema_version,item.event_id,item.instance_id,item.body_id,String(item.sequence),item.previous_event_hash,item.event_type,item.actor,item.content_digest,item.content_type,item.observed_at,item.provenance_digest,item.privacy], "evsha256:");
}
function computeViewDigest(item) {
  return hashFields(DOMAINS.accepted_view, [item.schema_version,item.hash_profile,item.event_id,item.content_digest,item.content_type,item.normalized_text,item.generated_at,item.generator_profile]);
}
function recordId(item) {
  return hashFields(RETRIEVAL_DOMAINS.record, [item.event_id,item.gate_decision_ref,item.content_digest,item.accepted_at], "rrsha256:");
}
function topLevel(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) throw new BridgeError("bridge_document_invalid");
  if (document.profile !== PROFILE) throw new BridgeError("bridge_profile_invalid");
  if (JSON.stringify(document.domains) !== JSON.stringify(DOMAINS)) throw new BridgeError("bridge_domains_invalid");
  for (const field of ["observations","gate_decisions","source_memory_events","accepted_content_views","queries"]) {
    if (!Array.isArray(document[field])) throw new BridgeError(`bridge_${field}_invalid`);
    nfc(document[field]);
  }
  nfc(document.verification_keys); nfc(document.associative_projection ?? {});
  const count = document.source_memory_events.length;
  if (!count) throw new BridgeError("bridge_source_memory_events_invalid");
  if (document.observations.length !== count || document.gate_decisions.length !== count || document.accepted_content_views.length !== count) throw new BridgeError("bridge_coverage_invalid");
  document.queries.forEach((query) => exact(query, SETS.query, "bridge_query"));
}
function buildAcceptedRecords(document) {
  topLevel(document);
  const keys = loadKeys(document.verification_keys);
  const observations = new Map();
  for (const item of document.observations) {
    exact(item, SETS.observation, "bridge_observation");
    const digest = observationDigest(item);
    if (digest !== item.observation_digest) throw new BridgeError("observation_digest_mismatch");
    verify(item.signature, { digest, domain: DOMAINS.observation_signature, bodyId: item.body_id, createdAt: item.captured_at }, keys, "observation");
    if (observations.has(item.observation_id)) throw new BridgeError("bridge_observation_duplicate");
    observations.set(item.observation_id, item);
  }
  const decisions = new Map();
  for (const item of document.gate_decisions) {
    exact(item, SETS.gate, "bridge_gate_decision");
    if (item.decision !== "accepted") throw new BridgeError("bridge_gate_not_accepted");
    if (typeof item.memory_event_ref !== "string") throw new BridgeError("bridge_gate_event_ref_missing");
    const observation = observations.get(item.observation_id);
    if (!observation) throw new BridgeError("bridge_gate_observation_unknown");
    if (item.observation_digest !== observation.observation_digest || item.instance_id !== observation.instance_id || item.body_id !== observation.body_id) throw new BridgeError("bridge_gate_observation_mismatch");
    const digest = gateDigest(item);
    if (digest !== item.decision_digest) throw new BridgeError("gate_decision_digest_mismatch");
    verify(item.signature, { digest, domain: DOMAINS.gate_signature, bodyId: item.body_id, createdAt: item.decided_at }, keys, "gate");
    if (decisions.has(item.memory_event_ref)) throw new BridgeError("bridge_gate_duplicate");
    decisions.set(item.memory_event_ref, { decision: item, observation });
  }
  const views = new Map();
  for (const item of document.accepted_content_views) {
    exact(item, SETS.view, "accepted_view");
    if (item.schema_version !== VIEW_SCHEMA || item.hash_profile !== HASH_PROFILE) throw new BridgeError("accepted_view_profile_invalid");
    if (item.view_digest !== computeViewDigest(item)) throw new BridgeError("accepted_view_digest_mismatch");
    if (!normalizeTerms(item.normalized_text).length) throw new BridgeError("accepted_record_text_empty");
    if (Buffer.byteLength(item.normalized_text, "utf8") > 4096) throw new BridgeError("accepted_record_text_too_large");
    if (views.has(item.event_id)) throw new BridgeError("accepted_view_duplicate");
    views.set(item.event_id, item);
  }
  const records = []; let previous = "GENESIS"; const ids = new Set();
  const instanceId = document.source_memory_events[0].instance_id;
  document.source_memory_events.forEach((event, index) => {
    exact(event, SETS.event, "bridge_memory_event");
    if (event.instance_id !== instanceId) throw new BridgeError("bridge_instance_mismatch");
    if (event.sequence !== index) throw new BridgeError("source_memory_sequence_invalid");
    if (event.previous_event_hash !== previous) throw new BridgeError("source_memory_chain_broken");
    if (event.event_hash !== eventHash(event)) throw new BridgeError("source_memory_event_hash_mismatch");
    if (ids.has(event.event_id)) throw new BridgeError("source_memory_event_duplicate");
    ids.add(event.event_id); previous = event.event_hash;
    const linked = decisions.get(event.event_id); const view = views.get(event.event_id);
    if (!linked || !view) throw new BridgeError("bridge_coverage_invalid");
    const { decision, observation } = linked;
    if (event.instance_id !== observation.instance_id || event.body_id !== observation.body_id || event.actor !== "body" || event.event_type !== `sense.${observation.sense}.observation`) throw new BridgeError("bridge_memory_observation_mismatch");
    if (event.content_digest !== observation.payload_digest) throw new BridgeError("memory_content_digest_mismatch");
    if (event.content_type !== observation.payload_media_type) throw new BridgeError("memory_content_type_mismatch");
    if (event.observed_at !== observation.captured_at) throw new BridgeError("memory_observed_at_mismatch");
    if (event.provenance_digest !== observation.observation_digest) throw new BridgeError("memory_provenance_digest_mismatch");
    if (event.privacy !== observation.privacy) throw new BridgeError("memory_privacy_mismatch");
    if (view.content_digest !== event.content_digest) throw new BridgeError("bridge_view_content_digest_mismatch");
    if (view.content_type !== event.content_type) throw new BridgeError("bridge_view_content_type_mismatch");
    if (Date.parse(view.generated_at) < Date.parse(decision.decided_at)) throw new BridgeError("accepted_view_before_gate");
    const record = { record_id: "", event_id: event.event_id, gate_decision_ref: decision.decision_id, content_digest: event.content_digest, normalized_text: view.normalized_text, accepted_at: decision.decided_at };
    record.record_id = recordId(record); records.push(record);
  });
  return records;
}
function buildBridgeSnapshot(document) {
  const records = buildAcceptedRecords(document);
  const base = { profile: "genesis.memory.retrieval.conformance.v0.1", status: "runtime-derived", domains: RETRIEVAL_DOMAINS, source_memory_events: structuredClone(document.source_memory_events), accepted_records: records, associative_projection: structuredClone(document.associative_projection ?? {}), queries: structuredClone(document.queries ?? []) };
  const projection = buildProjection(base);
  const receipt = { schema_version: RECEIPT_SCHEMA, hash_profile: HASH_PROFILE, bridge_profile: PROFILE, instance_id: document.source_memory_events[0].instance_id, source_first_sequence: document.source_memory_events[0].sequence, source_last_sequence: document.source_memory_events.at(-1).sequence, accepted_record_count: records.length, bridge_digest: "" };
  receipt.bridge_digest = hashFields(DOMAINS.bridge_receipt, [receipt.schema_version,receipt.bridge_profile,receipt.instance_id,String(receipt.source_first_sequence),String(receipt.source_last_sequence),String(records.length),...document.observations.map((x)=>x.observation_digest),...document.gate_decisions.map((x)=>x.decision_digest),...document.source_memory_events.map((x)=>x.event_hash),...document.accepted_content_views.map((x)=>x.view_digest),...records.map((x)=>x.record_id),projection.projection_digest]);
  return { ...base, projection, bridge_receipt: receipt };
}
function setPath(target, parts, value) { let cursor = target; for (const part of parts.slice(0,-1)) cursor = cursor[part]; cursor[parts.at(-1)] = value; }
function mutate(document, mutation) {
  if (mutation.operation === "set") setPath(document, mutation.path, mutation.value);
  else if (mutation.operation === "delete") { let cursor=document; for(const part of mutation.path.slice(0,-1)) cursor=cursor[part]; Array.isArray(cursor) ? cursor.splice(Number(mutation.path.at(-1)),1) : delete cursor[mutation.path.at(-1)]; }
  else if (mutation.operation === "duplicate") { const source=mutation.path.reduce((x,p)=>x[p],document); mutation.target.reduce((x,p)=>x[p],document).push(structuredClone(source)); }
  else throw new Error(`unknown_bridge_mutation:${mutation.operation}`);
  if (Number.isSafeInteger(mutation.recompute_view_digest_index)) { const view=document.accepted_content_views[mutation.recompute_view_digest_index]; view.view_digest=computeViewDigest(view); }
  if (Number.isSafeInteger(mutation.recompute_event_hash_index)) { const event=document.source_memory_events[mutation.recompute_event_hash_index]; event.event_hash=eventHash(event); }
}
function validateConformance(document) {
  const snapshot = buildBridgeSnapshot(document); const expected = document.expected;
  if (!expected || typeof expected !== "object") throw new BridgeError("bridge_expected_missing");
  if (JSON.stringify(snapshot.accepted_records) !== JSON.stringify(expected.accepted_records)) throw new BridgeError("bridge_expected_records_mismatch");
  if (snapshot.projection.projection_digest !== expected.projection_digest) throw new BridgeError("bridge_expected_projection_digest_mismatch");
  if (snapshot.bridge_receipt.bridge_digest !== expected.bridge_digest) throw new BridgeError("bridge_expected_receipt_digest_mismatch");
  if ((snapshot.projection.query_results[0]?.result_digest ?? null) !== expected.query_result_digest) throw new BridgeError("bridge_expected_query_digest_mismatch");
  let rejected = 0;
  for (const testCase of document.must_reject ?? []) {
    const copy = structuredClone(document);
    try { mutate(copy, testCase.mutation); buildBridgeSnapshot(copy); }
    catch (error) { if (error.message !== testCase.expected_error) throw new Error(`${testCase.case_id}: expected ${testCase.expected_error}, got ${error.message}`); rejected += 1; continue; }
    throw new Error(`${testCase.case_id}: mutation accepted`);
  }
  return { snapshot, rejected };
}
function readJson(file) { return JSON.parse(fs.readFileSync(path.resolve(file), "utf8")); }
function atomicWrite(file, value) { const resolved=path.resolve(file); fs.mkdirSync(path.dirname(resolved),{recursive:true}); const temporary=`${resolved}.${process.pid}.${Date.now()}.tmp`; fs.writeFileSync(temporary,`${JSON.stringify(value,null,2)}\n`,{encoding:"utf8",flag:"wx"}); fs.renameSync(temporary,resolved); }
function options(args, latest) { const out={topK:5,asOf:latest,anchors:[]}; for(let i=0;i<args.length;i+=2){ if(args[i]==="--top-k") out.topK=Number.parseInt(args[i+1],10); else if(args[i]==="--as-of") out.asOf=Number.parseInt(args[i+1],10); else if(args[i]==="--anchor") out.anchors.push(args[i+1]); else throw new Error(`unknown_option:${args[i]}`); } return out; }
function usage(code=0){ console.log(`Genesis memory-gate retrieval bridge\n\nUsage:\n  node tools/memory_gate_retrieval_bridge.mjs validate [vector.json]\n  node tools/memory_gate_retrieval_bridge.mjs build <bridge-input.json> [output.json]\n  node tools/memory_gate_retrieval_bridge.mjs sync <bridge-input.json> <output.json>\n  node tools/memory_gate_retrieval_bridge.mjs query <bridge-input.json> <text> [--top-k N] [--as-of N] [--anchor event_id]\n\nOnly accepted, signed and fully linked gate output becomes retrieval data. sync atomically replaces only the rebuildable snapshot.`); process.exit(code); }

export { BridgeError, DOMAINS, PROFILE, buildAcceptedRecords, buildBridgeSnapshot, computeViewDigest, validateConformance };
if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const [command,input,...rest]=process.argv.slice(2); if(!command||command==="--help"||command==="-h") usage();
  try {
    if(command==="validate"){ const {snapshot,rejected}=validateConformance(readJson(input??DEFAULT_VECTOR)); console.log(`OK memory-gate retrieval bridge (${snapshot.accepted_records.length} accepted records)`); console.log(`OK bridge receipt ${snapshot.bridge_receipt.bridge_digest}`); console.log(`OK bridge boundary rejection cases (${rejected})`); }
    else if(command==="build"||command==="sync"){ if(!input)usage(1); const snapshot=buildBridgeSnapshot(readJson(input)); const output=rest[0]; if(command==="sync"&&!output)usage(1); if(output){ if(command==="build"&&fs.existsSync(path.resolve(output)))throw new Error("output_exists"); atomicWrite(output,snapshot); console.log(`Retrieval snapshot written: ${path.resolve(output)}`); console.log(`Bridge digest: ${snapshot.bridge_receipt.bridge_digest}`); } else process.stdout.write(`${JSON.stringify(snapshot,null,2)}\n`); }
    else if(command==="query"){ if(!input||!rest.length)usage(1); const [text,...flags]=rest; const document=readJson(input); const latest=document.source_memory_events?.at(-1)?.sequence; if(!Number.isSafeInteger(latest))throw new Error("source_memory_events_invalid"); const parsed=options(flags,latest); document.queries=[{query_id:"bridge_cli_query",text,top_k:parsed.topK,as_of_sequence:parsed.asOf,anchor_event_refs:parsed.anchors}]; process.stdout.write(`${JSON.stringify(buildBridgeSnapshot(document).projection.query_results[0],null,2)}\n`); }
    else usage(1);
  } catch(error){ console.error(error instanceof BridgeError||error instanceof RetrievalError ? error.message : `memory_gate_retrieval_bridge_failed:${error.message}`); process.exit(1); }
}

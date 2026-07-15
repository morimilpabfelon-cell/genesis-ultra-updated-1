#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "memory_retrieval_acl_vectors.json");
const REQUESTER_TYPES = new Set(["instance", "guardian", "body", "engine", "observer"]);
const PURPOSES = new Set(["recall", "reasoning_context", "guardian_review", "transfer_export", "observability"]);
const PRIVACY = new Set(["private_local", "guardian_shared", "export_approved", "quarantined"]);
const AUTHORITY_FIELDS = new Set(["active_writer", "write_memory", "authority_grant", "guardian_key", "seed_root_hash"]);
const POLICY_FIELDS = new Set(["policy_id", "requester_type", "requester_id", "body_id", "purposes", "allowed_privacy", "allowed_scopes", "event_type_prefixes", "authority_epoch", "valid_from_sequence", "valid_to_sequence"]);
const REQUEST_FIELDS = new Set(["request_id", "requester_type", "requester_id", "body_id", "purpose", "requested_scopes", "event_type_prefixes", "as_of_sequence", "authority_epoch", "expected_policy_id", "expected_allowed_event_refs", "expected_denials"]);

export class AclError extends Error {}

function utf8Compare(a, b) { return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
function sorted(values) { return [...values].sort(utf8Compare); }
function frame(value) {
  if (typeof value !== "string" || value.normalize("NFC") !== value) throw new AclError("acl_text_invalid");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  return `${prefix}${crypto.createHash("sha256").update(Buffer.concat([frame(domain), ...fields.map(frame)])).digest("hex")}`;
}
function exactFields(object, expected, label) {
  if (!object || typeof object !== "object" || Array.isArray(object)) throw new AclError(`${label}_invalid`);
  const keys = Object.keys(object);
  if (keys.some((key) => AUTHORITY_FIELDS.has(key))) throw new AclError("acl_policy_contains_authority");
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) throw new AclError(`${label}_fields_invalid`);
}
function uniqueStrings(values, label) {
  if (!Array.isArray(values) || values.some((v) => typeof v !== "string" || v.length === 0) || new Set(values).size !== values.length) {
    throw new AclError(`${label}_invalid`);
  }
}
function validateDocument(document) {
  if (document.profile !== "genesis.memory.retrieval_acl.conformance.v0.1") throw new AclError("acl_profile_invalid");
  if (!Number.isSafeInteger(document.authority_epoch) || document.authority_epoch < 0) throw new AclError("acl_authority_epoch_invalid");
  if (!Array.isArray(document.events) || document.events.length === 0) throw new AclError("acl_events_invalid");
  const eventIds = new Set();
  const eventTypes = new Set();
  document.events.forEach((event, index) => {
    const expected = new Set(["event_id", "body_id", "sequence", "event_type", "privacy"]);
    exactFields(event, expected, "acl_event");
    if (event.sequence !== index) throw new AclError("acl_event_sequence_invalid");
    if (eventIds.has(event.event_id)) throw new AclError("acl_event_duplicate");
    if (!PRIVACY.has(event.privacy)) throw new AclError("acl_event_privacy_invalid");
    eventIds.add(event.event_id); eventTypes.add(event.event_type);
  });
  if (!Array.isArray(document.scope_bindings) || document.scope_bindings.length !== document.events.length) throw new AclError("acl_scope_binding_coverage_invalid");
  const bindingIds = new Set();
  const knownScopes = new Set();
  for (const binding of document.scope_bindings) {
    exactFields(binding, new Set(["event_id", "scopes"]), "acl_scope_binding");
    if (!eventIds.has(binding.event_id)) throw new AclError("acl_scope_binding_event_unknown");
    if (bindingIds.has(binding.event_id)) throw new AclError("acl_scope_binding_duplicate");
    uniqueStrings(binding.scopes, "acl_scopes");
    bindingIds.add(binding.event_id); binding.scopes.forEach((scope) => knownScopes.add(scope));
  }
  if (!Array.isArray(document.policies) || document.policies.length === 0) throw new AclError("acl_policies_invalid");
  const policyIds = new Set();
  for (const policy of document.policies) {
    exactFields(policy, POLICY_FIELDS, "acl_policy");
    if (policyIds.has(policy.policy_id)) throw new AclError("acl_policy_id_duplicate");
    if (!REQUESTER_TYPES.has(policy.requester_type)) throw new AclError("acl_requester_type_invalid");
    uniqueStrings(policy.purposes, "acl_policy_purposes");
    if (policy.purposes.some((value) => !PURPOSES.has(value))) throw new AclError("acl_policy_purpose_invalid");
    uniqueStrings(policy.allowed_privacy, "acl_policy_privacy");
    if (policy.allowed_privacy.some((value) => !PRIVACY.has(value) || value === "quarantined")) throw new AclError("acl_policy_privacy_invalid");
    uniqueStrings(policy.allowed_scopes, "acl_policy_scopes");
    if (policy.allowed_scopes.some((scope) => !knownScopes.has(scope))) throw new AclError("acl_policy_scope_unknown");
    uniqueStrings(policy.event_type_prefixes, "acl_policy_event_prefixes");
    if (policy.requester_type === "observer" && policy.allowed_privacy.some((value) => value !== "export_approved")) throw new AclError("acl_observer_privacy_invalid");
    if (policy.requester_type === "body" && policy.body_id !== policy.requester_id) throw new AclError("acl_body_policy_mismatch");
    if (policy.requester_type !== "body" && policy.body_id !== null) throw new AclError("acl_policy_body_unexpected");
    if (policy.authority_epoch !== document.authority_epoch) throw new AclError("acl_policy_epoch_invalid");
    if (!Number.isSafeInteger(policy.valid_from_sequence) || (policy.valid_to_sequence !== null && !Number.isSafeInteger(policy.valid_to_sequence))) throw new AclError("acl_policy_window_invalid");
    policyIds.add(policy.policy_id);
  }
  if (!Array.isArray(document.requests) || document.requests.length === 0) throw new AclError("acl_requests_invalid");
  for (const request of document.requests) {
    exactFields(request, REQUEST_FIELDS, "acl_request");
    if (!REQUESTER_TYPES.has(request.requester_type) || !PURPOSES.has(request.purpose)) throw new AclError("acl_request_identity_invalid");
    uniqueStrings(request.requested_scopes, "acl_requested_scopes");
    if (request.requested_scopes.some((scope) => !knownScopes.has(scope))) throw new AclError("acl_requested_scope_unknown");
    uniqueStrings(request.event_type_prefixes, "acl_request_event_prefixes");
    if (request.authority_epoch !== document.authority_epoch) throw new AclError("acl_authority_epoch_mismatch");
    if (!Number.isSafeInteger(request.as_of_sequence) || request.as_of_sequence < 0 || request.as_of_sequence >= document.events.length) throw new AclError("acl_as_of_sequence_invalid");
  }
  return { knownScopes };
}
function choosePolicy(document, request) {
  const matches = document.policies.filter((policy) =>
    policy.requester_type === request.requester_type && policy.requester_id === request.requester_id &&
    policy.body_id === request.body_id && policy.purposes.includes(request.purpose) &&
    policy.authority_epoch === request.authority_epoch && request.as_of_sequence >= policy.valid_from_sequence &&
    (policy.valid_to_sequence === null || request.as_of_sequence <= policy.valid_to_sequence));
  if (matches.length === 0) throw new AclError("acl_policy_not_found");
  if (matches.length !== 1) throw new AclError("acl_policy_ambiguous");
  return matches[0];
}
function computeDecisionDigest(decision) {
  const denialFlat = sorted(Object.keys(decision.denial_counts)).flatMap((key) => [key, String(decision.denial_counts[key])]);
  return hashFields("genesis.memory.retrieval_acl.decision.v0.1", [
    decision.request_id, decision.policy_id, String(decision.authority_epoch), String(decision.as_of_sequence),
    String(decision.effective_scopes.length), ...decision.effective_scopes,
    String(decision.allowed_event_refs.length), ...decision.allowed_event_refs,
    String(denialFlat.length / 2), ...denialFlat
  ], "aclsha256:");
}
export function evaluateRequest(document, request) {
  const policy = choosePolicy(document, request);
  const bindings = new Map(document.scope_bindings.map((item) => [item.event_id, new Set(item.scopes)]));
  const effective = request.requested_scopes.length ? sorted(request.requested_scopes.filter((scope) => policy.allowed_scopes.includes(scope))) : sorted(policy.allowed_scopes);
  const effectiveSet = new Set(effective);
  const allowed = [];
  const denial = {};
  const deny = (reason) => { denial[reason] = (denial[reason] ?? 0) + 1; };
  const prefixes = request.event_type_prefixes.length ? request.event_type_prefixes : policy.event_type_prefixes;
  for (const event of document.events) {
    if (event.sequence > request.as_of_sequence) { deny("future_event"); continue; }
    if (event.privacy === "quarantined") { deny("quarantined"); continue; }
    if (![...bindings.get(event.event_id)].some((scope) => effectiveSet.has(scope))) { deny("scope_not_allowed"); continue; }
    if (!policy.allowed_privacy.includes(event.privacy)) { deny("privacy_not_allowed"); continue; }
    if (request.requester_type === "body" && event.privacy === "private_local" && event.body_id !== request.body_id) { deny("body_mismatch"); continue; }
    if (prefixes.length && !prefixes.some((prefix) => event.event_type.startsWith(prefix))) { deny("event_type_filtered"); continue; }
    allowed.push(event.event_id);
  }
  const decision = {
    schema_version: "genesis.memory.retrieval_acl.decision.v0.1",
    request_id: request.request_id,
    policy_id: policy.policy_id,
    instance_id: document.instance_id,
    authority_epoch: request.authority_epoch,
    purpose: request.purpose,
    as_of_sequence: request.as_of_sequence,
    effective_scopes: effective,
    allowed_event_refs: allowed,
    denial_counts: denial,
    decision_digest: ""
  };
  decision.decision_digest = computeDecisionDigest(decision);
  return decision;
}
export function buildDecisions(document) {
  validateDocument(document);
  return document.requests.map((request) => evaluateRequest(document, request));
}
function applyMutation(document, mutation) {
  if (mutation.target === "request") document.requests[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "policy") document.policies[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "policy_add") document.policies[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "binding") document.scope_bindings[mutation.index][mutation.field] = mutation.value;
  else if (mutation.target === "duplicate_binding") document.scope_bindings.push(structuredClone(document.scope_bindings[mutation.index]));
  else if (mutation.target === "duplicate_policy") { const copy = structuredClone(document.policies[mutation.index]); copy.policy_id = mutation.new_policy_id; document.policies.push(copy); }
  else throw new Error(`unknown_mutation:${mutation.target}`);
}
function validateVector(document) {
  const decisions = buildDecisions(document);
  decisions.forEach((decision, index) => {
    const request = document.requests[index];
    if (decision.policy_id !== request.expected_policy_id || JSON.stringify(decision.allowed_event_refs) !== JSON.stringify(request.expected_allowed_event_refs) || JSON.stringify(decision.denial_counts) !== JSON.stringify(request.expected_denials)) {
      throw new Error(`acl_expected_decision_mismatch:${request.request_id}`);
    }
  });
  let rejected = 0;
  for (const testCase of document.must_reject ?? []) {
    const copy = structuredClone(document); applyMutation(copy, testCase.mutation);
    try { buildDecisions(copy); } catch (error) {
      if (!(error instanceof AclError)) throw error;
      if (error.message !== testCase.expected_error) throw new Error(`${testCase.case_id}:expected:${testCase.expected_error}:got:${error.message}`);
      rejected += 1; continue;
    }
    throw new Error(`${testCase.case_id}:mutation_accepted`);
  }
  return { decisions, rejected };
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const [command = "validate", input = DEFAULT_VECTOR, requestId] = process.argv.slice(2);
  try {
    const document = JSON.parse(fs.readFileSync(path.resolve(input), "utf8"));
    if (command === "validate") {
      const { decisions, rejected } = validateVector(document);
      console.log(`OK retrieval ACL (${decisions.length} requests)`);
      console.log(`OK scopes, privacy, purpose and historical isolation`);
      console.log(`OK ACL boundary rejection cases (${rejected})`);
      console.log("NOTE ACL filters candidates before ranking and never grants write authority.");
    } else if (command === "filter") {
      validateDocument(document);
      const request = document.requests.find((item) => item.request_id === requestId);
      if (!request) throw new AclError("acl_request_not_found");
      process.stdout.write(`${JSON.stringify(evaluateRequest(document, request), null, 2)}\n`);
    } else throw new AclError("acl_command_invalid");
  } catch (error) {
    console.error(error.message); process.exit(1);
  }
}

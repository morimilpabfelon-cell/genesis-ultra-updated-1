#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "guided_autonomy_vectors.json");
const MAX_INT = Number.MAX_SAFE_INTEGER;

const CAPABILITIES = new Map([
  ["memory.read", "low"],
  ["memory.propose_append", "medium"],
  ["network.read", "medium"],
  ["code.propose_change", "medium"],
  ["code.execute_sandbox", "high"],
  ["external.action", "high"],
  ["body.device.control", "critical"],
  ["transfer.prepare", "high"],
]);
const FORBIDDEN_CAPABILITIES = new Set([
  "memory.rewrite",
  "authority.self_grant",
  "guardian.replace",
  "identity.modify",
  "main.protection.disable",
  "private_eval.read",
  "active_writer.assign",
]);
const RISK_LEVEL = new Map([["low", 1], ["medium", 2], ["high", 3], ["critical", 4]]);
const MAX_LEVEL = new Map([["low", 4], ["medium", 3], ["high", 2], ["critical", 1]]);
const MODES = new Set(["one_time", "bounded", "standing"]);
const BODY_SCOPES = new Set(["specific_bodies", "registered_guardian_devices"]);
const DATA_CLASSES = new Set(["private_local", "guardian_shared", "export_approved", "public"]);
const EVENT_TYPES = new Set(["grant.issued", "grant.suspended", "grant.resumed", "grant.revoked", "grant.consumed"]);
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const SHA_RE = /^sha256:[0-9a-f]{64}$/;

const SCOPE_FIELDS = new Set(["allowed_target_refs", "allowed_action_classes", "allowed_data_classes"]);
const BUDGET_FIELDS = new Set(["max_actions_per_run", "max_duration_seconds", "max_bytes_per_run"]);
const CONTROL_FIELDS = new Set(["sandbox_required", "human_confirmation_required", "observer_required", "reversible_required"]);
const SIGNATURE_FIELDS = new Set(["schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"]);
const PROPOSAL_FIELDS = new Set(["schema_version", "hash_profile", "proposal_id", "instance_id", "body_id", "capability", "requested_level", "body_scope", "body_ids", "scope", "budget", "controls", "reason", "created_at", "proposal_digest", "signature"]);
const EVALUATION_FIELDS = new Set(["schema_version", "hash_profile", "evaluation_id", "proposal_ref", "proposal_digest", "instance_id", "capability", "evaluated_level", "fixed_budget_profile", "public_suite_digest", "private_suite_receipt_digest", "result", "reward_hacking_detected", "safety_regression_detected", "evaluated_at", "evaluation_digest", "signature"]);
const GRANT_FIELDS = new Set(["schema_version", "hash_profile", "grant_id", "guardian_id", "guardian_key_epoch_id", "instance_id", "authority_epoch", "proposal_ref", "proposal_digest", "evaluation_ref", "evaluation_digest", "capability", "autonomy_level", "risk_tier", "mode", "body_scope", "body_ids", "scope", "budget", "controls", "issued_at", "not_before", "expires_at", "use_limit", "replaces_grant_ref", "grant_digest", "signature"]);
const EVENT_FIELDS = new Set(["schema_version", "hash_profile", "ledger_id", "event_id", "sequence", "previous_event_hash", "guardian_id", "instance_id", "authority_epoch", "event_type", "grant_ref", "body_id", "use_id", "subject_digest", "recorded_at", "event_hash", "signature"]);
const USE_FIELDS_V1 = new Set(["schema_version", "hash_profile", "use_id", "instance_id", "body_id", "capability", "target_ref", "action_class", "data_class", "requested_actions", "requested_duration_seconds", "requested_bytes", "sandboxed", "human_confirmation_ref", "observer_ref", "reversible_plan_ref", "requested_at", "use_digest", "signature"]);
const USE_FIELDS_V2 = new Set(["schema_version", "hash_profile", "use_id", "grant_ref", "instance_id", "body_id", "capability", "target_ref", "action_class", "data_class", "requested_actions", "requested_duration_seconds", "requested_bytes", "sandboxed", "human_confirmation_ref", "observer_ref", "reversible_plan_ref", "requested_at", "use_digest", "signature"]);

export class ConformanceError extends Error {}
function fail(code) { throw new ConformanceError(code); }
function boolText(value) { return value ? "true" : "false"; }
function optionalText(value) { return value === null || value === undefined ? "" : String(value); }
function utf8Compare(a, b) { return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }

function encodeField(value) {
  if (typeof value !== "string") fail("field_must_be_string");
  if (value.normalize("NFC") !== value) fail("text_not_nfc");
  const raw = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${raw.length}:`, "ascii"), raw, Buffer.from("\n", "ascii")]);
}

function hashFields(domain, fields) {
  const payload = Buffer.concat([encodeField(domain), ...fields.map(encodeField)]);
  return `sha256:${crypto.createHash("sha256").update(payload).digest("hex")}`;
}

function parseUtc(value) {
  if (typeof value !== "string" || !TS_RE.test(value)) fail("timestamp_invalid");
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) fail("timestamp_invalid");
  return parsed;
}

export function validateNfc(value) {
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value) fail("text_not_nfc");
  } else if (Array.isArray(value)) {
    for (const item of value) validateNfc(item);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      validateNfc(key);
      validateNfc(item);
    }
  }
}

function exactFields(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const keys = Object.keys(value);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) fail(code);
}

export function ensureInt(value, code, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum || value > MAX_INT) fail(code);
  return value;
}

export function ensureSortedUniqueStrings(values, code, { allowEmpty = false } = {}) {
  if (!Array.isArray(values) || (!allowEmpty && values.length === 0)) fail(code);
  if (values.some((item) => typeof item !== "string" || item.length === 0)) fail(code);
  if (new Set(values).size !== values.length) fail(code);
  const sorted = [...values].sort(utf8Compare);
  if (values.some((value, index) => value !== sorted[index])) fail(code);
  return values;
}

function validateScope(scope, prefix) {
  exactFields(scope, SCOPE_FIELDS, `${prefix}_scope_fields_invalid`);
  ensureSortedUniqueStrings(scope.allowed_target_refs, `${prefix}_targets_invalid`);
  ensureSortedUniqueStrings(scope.allowed_action_classes, `${prefix}_actions_invalid`);
  const data = ensureSortedUniqueStrings(scope.allowed_data_classes, `${prefix}_data_classes_invalid`);
  if (data.some((item) => !DATA_CLASSES.has(item))) fail(`${prefix}_data_class_invalid`);
}

function validateBudget(budget, prefix) {
  exactFields(budget, BUDGET_FIELDS, `${prefix}_budget_fields_invalid`);
  ensureInt(budget.max_actions_per_run, `${prefix}_action_budget_invalid`, 1);
  ensureInt(budget.max_duration_seconds, `${prefix}_duration_budget_invalid`, 1);
  ensureInt(budget.max_bytes_per_run, `${prefix}_byte_budget_invalid`, 0);
}

function validateControls(controls, prefix) {
  exactFields(controls, CONTROL_FIELDS, `${prefix}_control_fields_invalid`);
  if ([...CONTROL_FIELDS].some((field) => typeof controls[field] !== "boolean")) fail(`${prefix}_controls_invalid`);
}

function flattenScope(scope) {
  const fields = [];
  for (const name of ["allowed_target_refs", "allowed_action_classes", "allowed_data_classes"]) {
    fields.push(String(scope[name].length), ...scope[name]);
  }
  return fields;
}
function flattenBudget(budget) { return [String(budget.max_actions_per_run), String(budget.max_duration_seconds), String(budget.max_bytes_per_run)]; }
function flattenControls(controls) { return ["sandbox_required", "human_confirmation_required", "observer_required", "reversible_required"].map((name) => boolText(controls[name])); }
function flattenBodyScope(item) { return [item.body_scope, String(item.body_ids.length), ...item.body_ids]; }

export function computeProposalDigest(item) {
  const fields = [item.schema_version, item.hash_profile, item.proposal_id, item.instance_id, item.body_id, item.capability, String(item.requested_level)];
  fields.push(...flattenBodyScope(item), ...flattenScope(item.scope), ...flattenBudget(item.budget), ...flattenControls(item.controls), item.reason, item.created_at);
  return hashFields("genesis.autonomy.capability.proposal.v0.1", fields);
}

export function computeEvaluationDigest(item) {
  return hashFields("genesis.autonomy.capability.evaluation.v0.1", [
    item.schema_version, item.hash_profile, item.evaluation_id, item.proposal_ref, item.proposal_digest,
    item.instance_id, item.capability, String(item.evaluated_level), item.fixed_budget_profile,
    item.public_suite_digest, item.private_suite_receipt_digest, item.result,
    boolText(item.reward_hacking_detected), boolText(item.safety_regression_detected), item.evaluated_at,
  ]);
}

export function computeGrantDigest(item) {
  const fields = [
    item.schema_version, item.hash_profile, item.grant_id, item.guardian_id, item.guardian_key_epoch_id,
    item.instance_id, String(item.authority_epoch), item.proposal_ref, item.proposal_digest,
    item.evaluation_ref, item.evaluation_digest, item.capability, String(item.autonomy_level),
    item.risk_tier, item.mode,
  ];
  fields.push(...flattenBodyScope(item), ...flattenScope(item.scope), ...flattenBudget(item.budget), ...flattenControls(item.controls));
  fields.push(item.issued_at, item.not_before, optionalText(item.expires_at), optionalText(item.use_limit), optionalText(item.replaces_grant_ref));
  return hashFields("genesis.autonomy.capability.grant.v0.1", fields);
}

export function computeUseDigest(item) {
  const v2 = item.schema_version === "genesis.autonomy.capability.use.v0.2";
  const fields = [item.schema_version, item.hash_profile, item.use_id];
  if (v2) fields.push(item.grant_ref);
  fields.push(
    item.instance_id, item.body_id, item.capability, item.target_ref, item.action_class,
    item.data_class, String(item.requested_actions), String(item.requested_duration_seconds),
    String(item.requested_bytes), boolText(item.sandboxed), optionalText(item.human_confirmation_ref),
    optionalText(item.observer_ref), optionalText(item.reversible_plan_ref), item.requested_at,
  );
  return hashFields(v2 ? "genesis.autonomy.capability.use.v0.2" : "genesis.autonomy.capability.use.v0.1", fields);
}

export function computeEventHash(item) {
  return hashFields("genesis.autonomy.capability.event.v0.1", [
    item.schema_version, item.hash_profile, item.ledger_id, item.event_id, String(item.sequence),
    item.previous_event_hash, item.guardian_id, item.instance_id, String(item.authority_epoch),
    item.event_type, item.grant_ref, optionalText(item.body_id), optionalText(item.use_id), item.subject_digest, item.recorded_at,
  ]);
}

function signatureBytes(envelope) {
  exactFields(envelope, SIGNATURE_FIELDS, "signature_fields_invalid");
  const values = [
    envelope.schema_version, envelope.signature_profile, envelope.signer_type, envelope.signer_id,
    envelope.key_epoch_id, envelope.signed_domain, envelope.signed_digest, envelope.created_at, envelope.public_key_ref,
  ];
  return Buffer.concat([encodeField("genesis.signature.envelope.bytes.v0.1"), ...values.map(encodeField)]);
}

function publicKeyFromRaw(hex) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({ key: Buffer.concat([prefix, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}
function privateKeyFromSeed(hex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(hex, "hex")]), format: "der", type: "pkcs8" });
}
function rawPublicFromPrivate(privateKey) {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32);
}

function validateSignature(envelope, { digest, domain, key, signerType, signerId, createdAt, prefix }) {
  exactFields(envelope, SIGNATURE_FIELDS, `${prefix}_signature_fields_invalid`);
  if (envelope.schema_version !== "genesis.signature.envelope.v0.1" || envelope.signature_profile !== "genesis.signature.ed25519.v0.1") fail(`${prefix}_signature_profile_invalid`);
  if (envelope.signer_type !== signerType || envelope.signer_id !== signerId) fail(`${prefix}_signer_mismatch`);
  if (envelope.key_epoch_id !== key.key_epoch_id) fail(`${prefix}_key_epoch_mismatch`);
  if (envelope.signed_domain !== domain) fail(`${prefix}_signature_domain_mismatch`);
  if (envelope.signed_digest !== digest) fail(`${prefix}_signature_digest_mismatch`);
  if (envelope.created_at !== createdAt) fail(`${prefix}_signature_timestamp_mismatch`);
  if (envelope.public_key_ref !== key.public_key_fingerprint) fail(`${prefix}_signature_key_mismatch`);
  try {
    const signature = Buffer.from(envelope.signature_value, "hex");
    if (signature.length !== 64 || !crypto.verify(null, signatureBytes(envelope), publicKeyFromRaw(key.public_key_hex), signature)) fail(`${prefix}_signature_invalid`);
  } catch (error) {
    if (error instanceof ConformanceError) throw error;
    fail(`${prefix}_signature_invalid`);
  }
}

function makeSignature({ key, signerType, signerId, digest, domain, createdAt }) {
  const envelope = {
    schema_version: "genesis.signature.envelope.v0.1",
    signature_profile: "genesis.signature.ed25519.v0.1",
    signer_type: signerType,
    signer_id: signerId,
    key_epoch_id: key.key_epoch_id,
    signed_domain: domain,
    signed_digest: digest,
    signature_value: "",
    created_at: createdAt,
    public_key_ref: key.public_key_fingerprint,
  };
  envelope.signature_value = crypto.sign(null, signatureBytes(envelope), privateKeyFromSeed(key.seed_hex)).toString("hex");
  return envelope;
}

function validateBodyScope(item, registered, prefix) {
  if (!BODY_SCOPES.has(item.body_scope)) fail(`${prefix}_body_scope_invalid`);
  const bodies = ensureSortedUniqueStrings(item.body_ids, `${prefix}_body_ids_invalid`, { allowEmpty: true });
  if (item.body_scope === "specific_bodies" && bodies.length === 0) fail(`${prefix}_body_ids_required`);
  if (item.body_scope === "registered_guardian_devices" && bodies.length !== 0) fail(`${prefix}_body_ids_forbidden`);
  if (bodies.some((body) => !registered.has(body))) fail(`${prefix}_body_unknown`);
}

export function validateProposal(item, document) {
  validateNfc(item);
  exactFields(item, PROPOSAL_FIELDS, "proposal_fields_invalid");
  if (item.schema_version !== document.domains.proposal || item.hash_profile !== "genesis.hash.fields.v0.1") fail("proposal_profile_invalid");
  if (item.instance_id !== document.instance_id) fail("proposal_instance_mismatch");
  if (!document.registered_body_ids.includes(item.body_id)) fail("proposal_body_unknown");
  if (FORBIDDEN_CAPABILITIES.has(item.capability)) fail("proposal_capability_forbidden");
  if (!CAPABILITIES.has(item.capability)) fail("proposal_capability_unknown");
  const level = ensureInt(item.requested_level, "proposal_level_invalid", 1);
  if (level > 4) fail("proposal_level_invalid");
  validateBodyScope(item, new Set(document.registered_body_ids), "proposal");
  validateScope(item.scope, "proposal");
  validateBudget(item.budget, "proposal");
  validateControls(item.controls, "proposal");
  if (typeof item.reason !== "string" || item.reason.length === 0) fail("proposal_reason_invalid");
  parseUtc(item.created_at);
  const digest = computeProposalDigest(item);
  if (item.proposal_digest !== digest) fail("proposal_digest_mismatch");
  validateSignature(item.signature, { digest, domain: document.domains.proposal_signature, key: document.keys.body, signerType: "body", signerId: item.body_id, createdAt: item.created_at, prefix: "proposal" });
}

export function validateEvaluation(item, proposal, document) {
  validateNfc(item);
  exactFields(item, EVALUATION_FIELDS, "evaluation_fields_invalid");
  if (item.schema_version !== document.domains.evaluation || item.hash_profile !== "genesis.hash.fields.v0.1") fail("evaluation_profile_invalid");
  if (item.proposal_ref !== proposal.proposal_id || item.proposal_digest !== proposal.proposal_digest) fail("evaluation_proposal_binding_invalid");
  if (item.instance_id !== document.instance_id || item.capability !== proposal.capability) fail("evaluation_subject_mismatch");
  const level = ensureInt(item.evaluated_level, "evaluation_level_invalid", 1);
  if (level > proposal.requested_level || level > 4) fail("evaluation_level_exceeds_proposal");
  if (!new Set(["passed", "failed"]).has(item.result)) fail("evaluation_result_invalid");
  if (typeof item.reward_hacking_detected !== "boolean" || typeof item.safety_regression_detected !== "boolean") fail("evaluation_flags_invalid");
  if (typeof item.fixed_budget_profile !== "string" || item.fixed_budget_profile.length === 0) fail("evaluation_budget_profile_invalid");
  if (!SHA_RE.test(item.public_suite_digest) || !SHA_RE.test(item.private_suite_receipt_digest)) fail("evaluation_suite_digest_invalid");
  parseUtc(item.evaluated_at);
  const digest = computeEvaluationDigest(item);
  if (item.evaluation_digest !== digest) fail("evaluation_digest_mismatch");
  validateSignature(item.signature, { digest, domain: document.domains.evaluation_signature, key: document.keys.guardian, signerType: "guardian", signerId: document.guardian_id, createdAt: item.evaluated_at, prefix: "evaluation" });
}

function controlsRequired(capability, risk, level) {
  const required = new Set(["observer_required"]);
  if (risk === "critical") for (const field of CONTROL_FIELDS) required.add(field);
  if (risk === "high") for (const field of ["sandbox_required", "observer_required", "reversible_required"]) required.add(field);
  if (level <= 2 || new Set(["external.action", "body.device.control", "transfer.prepare"]).has(capability)) required.add("human_confirmation_required");
  if (capability === "code.execute_sandbox") required.add("sandbox_required");
  return required;
}
function isSubsetList(child, parent) { return child.every((item) => parent.includes(item)); }

export function validateGrant(item, proposal, evaluation, document) {
  validateNfc(item);
  exactFields(item, GRANT_FIELDS, "grant_fields_invalid");
  if (item.schema_version !== document.domains.grant || item.hash_profile !== "genesis.hash.fields.v0.1") fail("grant_profile_invalid");
  if (item.guardian_id !== document.guardian_id || item.guardian_key_epoch_id !== document.keys.guardian.key_epoch_id) fail("grant_guardian_mismatch");
  if (item.instance_id !== document.instance_id || item.authority_epoch !== document.authority_epoch) fail("grant_authority_scope_mismatch");
  if (item.proposal_ref !== proposal.proposal_id || item.proposal_digest !== proposal.proposal_digest) fail("grant_proposal_binding_invalid");
  if (item.evaluation_ref !== evaluation.evaluation_id || item.evaluation_digest !== evaluation.evaluation_digest) fail("grant_evaluation_binding_invalid");
  if (evaluation.result !== "passed" || evaluation.reward_hacking_detected || evaluation.safety_regression_detected) fail("grant_evidence_not_acceptable");
  if (item.capability !== proposal.capability || item.capability !== evaluation.capability) fail("grant_capability_mismatch");
  const level = ensureInt(item.autonomy_level, "grant_level_invalid", 1);
  if (level > proposal.requested_level || level > evaluation.evaluated_level || level > 4) fail("grant_level_exceeds_evidence");
  const minimumRisk = CAPABILITIES.get(item.capability);
  if (!RISK_LEVEL.has(item.risk_tier) || RISK_LEVEL.get(item.risk_tier) < RISK_LEVEL.get(minimumRisk)) fail("grant_risk_underclassified");
  if (level > MAX_LEVEL.get(item.risk_tier)) fail("grant_level_exceeds_risk");
  if (!MODES.has(item.mode)) fail("grant_mode_invalid");
  validateBodyScope(item, new Set(document.registered_body_ids), "grant");
  if (item.body_scope !== proposal.body_scope) fail("grant_body_scope_expansion");
  if (item.body_scope === "specific_bodies" && !isSubsetList(item.body_ids, proposal.body_ids)) fail("grant_body_scope_expansion");
  validateScope(item.scope, "grant");
  for (const field of SCOPE_FIELDS) if (!isSubsetList(item.scope[field], proposal.scope[field])) fail("grant_scope_expansion");
  validateBudget(item.budget, "grant");
  for (const field of BUDGET_FIELDS) if (item.budget[field] > proposal.budget[field]) fail("grant_budget_expansion");
  validateControls(item.controls, "grant");
  for (const field of CONTROL_FIELDS) if (proposal.controls[field] && !item.controls[field]) fail("grant_control_weakened");
  for (const field of controlsRequired(item.capability, item.risk_tier, level)) if (!item.controls[field]) fail("grant_required_control_missing");
  const issued = parseUtc(item.issued_at);
  const notBefore = parseUtc(item.not_before);
  const expires = item.expires_at === null ? null : parseUtc(item.expires_at);
  if (notBefore < issued || (expires !== null && expires <= notBefore)) fail("grant_time_window_invalid");
  if (item.mode === "one_time") {
    if (item.body_scope !== "specific_bodies" || item.body_ids.length !== 1 || item.use_limit !== 1 || expires === null) fail("grant_one_time_constraints_invalid");
  } else if (item.mode === "bounded") {
    ensureInt(item.use_limit, "grant_use_limit_invalid", 1);
    if (expires === null) fail("grant_bounded_expiry_required");
  } else if (item.mode === "standing" && item.use_limit !== null) {
    fail("grant_standing_use_limit_forbidden");
  }
  if (item.replaces_grant_ref !== null && typeof item.replaces_grant_ref !== "string") fail("grant_replacement_invalid");
  const digest = computeGrantDigest(item);
  if (item.grant_digest !== digest) fail("grant_digest_mismatch");
  validateSignature(item.signature, { digest, domain: document.domains.grant_signature, key: document.keys.guardian, signerType: "guardian", signerId: document.guardian_id, createdAt: item.issued_at, prefix: "grant" });
}

export function validateUse(item, document) {
  validateNfc(item);
  const v2 = item.schema_version === "genesis.autonomy.capability.use.v0.2";
  exactFields(item, v2 ? USE_FIELDS_V2 : USE_FIELDS_V1, "use_fields_invalid");
  if (!v2 && item.schema_version !== document.domains.use) fail("use_profile_invalid");
  if (item.hash_profile !== "genesis.hash.fields.v0.1") fail("use_profile_invalid");
  if (v2 && (typeof item.grant_ref !== "string" || item.grant_ref.length === 0)) fail("use_grant_ref_invalid");
  if (item.instance_id !== document.instance_id || !document.registered_body_ids.includes(item.body_id)) fail("use_subject_invalid");
  for (const field of ["target_ref", "action_class", "data_class"]) if (typeof item[field] !== "string" || item[field].length === 0) fail("use_scope_value_invalid");
  for (const field of ["requested_actions", "requested_duration_seconds", "requested_bytes"]) ensureInt(item[field], `use_${field}_invalid`, field === "requested_bytes" ? 0 : 1);
  if (typeof item.sandboxed !== "boolean") fail("use_sandbox_flag_invalid");
  for (const field of ["human_confirmation_ref", "observer_ref", "reversible_plan_ref"]) if (item[field] !== null && (typeof item[field] !== "string" || item[field].length === 0)) fail("use_control_reference_invalid");
  parseUtc(item.requested_at);
  const digest = computeUseDigest(item);
  if (item.use_digest !== digest) fail("use_digest_mismatch");
  validateSignature(item.signature, { digest, domain: v2 ? "genesis.autonomy.capability.use.signature.v0.2" : document.domains.use_signature, key: document.keys.body, signerType: "body", signerId: item.body_id, createdAt: item.requested_at, prefix: "use" });
}

function stateBefore(grant, events, at) {
  let status = "not_issued";
  const consumed = new Set();
  let lastEventRef = null;
  for (const event of events) {
    if (event.grant_ref !== grant.grant_id || parseUtc(event.recorded_at) > at) continue;
    if (event.event_type === "grant.issued") status = "active";
    else if (event.event_type === "grant.suspended") status = "suspended";
    else if (event.event_type === "grant.resumed") {
      if (status === "revoked") fail("ledger_resume_after_revocation");
      status = "active";
    } else if (event.event_type === "grant.revoked") status = "revoked";
    else if (event.event_type === "grant.consumed") consumed.add(event.use_id);
    lastEventRef = event.event_id;
  }
  if (grant.use_limit !== null && consumed.size >= grant.use_limit && status === "active") status = "exhausted";
  return { status, consumed, last_event_ref: lastEventRef };
}

export function evaluateUse(item, grants, events, registered) {
  const at = parseUtc(item.requested_at);
  const v2 = item.schema_version === "genesis.autonomy.capability.use.v0.2";
  let reason = "allowed";
  let chosen = null;
  let remaining = null;
  if (FORBIDDEN_CAPABILITIES.has(item.capability)) reason = "capability_forbidden";
  else if (!CAPABILITIES.has(item.capability)) reason = "capability_unknown";
  else {
    const candidates = v2
      ? grants.filter((grant) => grant.grant_id === item.grant_ref)
      : grants.filter((grant) => grant.capability === item.capability);
    if (candidates.length === 0) reason = "grant_missing";
    else if (!v2 && candidates.length > 1) fail("capability_multiple_grants");
    else {
      [chosen] = candidates;
      if (chosen.capability !== item.capability) reason = "grant_capability_mismatch";
      else {
        const state = stateBefore(chosen, events, at);
        if (at < parseUtc(chosen.not_before)) reason = "grant_not_yet_valid";
        else if (chosen.expires_at !== null && at >= parseUtc(chosen.expires_at)) reason = "grant_expired";
        else if (state.status === "not_issued") reason = "grant_not_issued";
        else if (state.status === "suspended") reason = "grant_suspended";
        else if (state.status === "revoked") reason = "grant_revoked";
        else if (state.status === "exhausted") reason = "grant_exhausted";
        else if (state.consumed.has(item.use_id)) reason = "use_already_consumed";
        else if (chosen.body_scope === "specific_bodies" && !chosen.body_ids.includes(item.body_id)) reason = "body_not_authorized";
        else if (chosen.body_scope === "registered_guardian_devices" && !registered.has(item.body_id)) reason = "body_not_authorized";
        else if (!chosen.scope.allowed_target_refs.includes(item.target_ref)) reason = "target_not_authorized";
        else if (!chosen.scope.allowed_action_classes.includes(item.action_class)) reason = "action_not_authorized";
        else if (!chosen.scope.allowed_data_classes.includes(item.data_class)) reason = "data_class_not_authorized";
        else if (item.requested_actions > chosen.budget.max_actions_per_run) reason = "action_budget_exceeded";
        else if (item.requested_duration_seconds > chosen.budget.max_duration_seconds) reason = "duration_budget_exceeded";
        else if (item.requested_bytes > chosen.budget.max_bytes_per_run) reason = "byte_budget_exceeded";
        else if (chosen.controls.sandbox_required && !item.sandboxed) reason = "sandbox_required";
        else if (chosen.controls.human_confirmation_required && item.human_confirmation_ref === null) reason = "human_confirmation_required";
        else if (chosen.controls.observer_required && item.observer_ref === null) reason = "observer_required";
        else if (chosen.controls.reversible_required && item.reversible_plan_ref === null) reason = "reversibility_required";
        if (chosen.use_limit !== null) remaining = Math.max(0, chosen.use_limit - state.consumed.size - (reason === "allowed" ? 1 : 0));
      }
    }
  }
  const status = reason === "allowed" ? "allowed" : "denied";
  const grantRef = chosen === null ? null : chosen.grant_id;
  const decisionDigest = v2
    ? hashFields("genesis.autonomy.capability.use.decision.v0.2", [item.use_id, item.use_digest, item.grant_ref, status, reason, optionalText(remaining)])
    : hashFields("genesis.autonomy.capability.use.decision.v0.1", [item.use_id, item.use_digest, status, reason, optionalText(grantRef), optionalText(remaining)]);
  return { use_id: item.use_id, status, reason, grant_ref: grantRef, remaining_uses: remaining, decision_digest: decisionDigest };
}

export function validateLedger(events, grants, uses, document, keyResolver = null) {
  if (!Array.isArray(events) || events.length === 0) fail("ledger_events_required");
  const grantsById = new Map(grants.map((grant) => [grant.grant_id, grant]));
  const usesById = new Map(uses.map((use) => [use.use_id, use]));
  let previous = "GENESIS";
  const ledgerId = events[0]?.ledger_id;
  const seenIds = new Set();
  const seenUses = new Set();
  const issued = new Set();
  const status = new Map();
  let previousTime = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    validateNfc(event);
    exactFields(event, EVENT_FIELDS, "ledger_event_fields_invalid");
    if (event.schema_version !== document.domains.event || event.hash_profile !== "genesis.hash.fields.v0.1") fail("ledger_event_profile_invalid");
    if (event.ledger_id !== ledgerId || event.guardian_id !== document.guardian_id || event.instance_id !== document.instance_id || event.authority_epoch !== document.authority_epoch) fail("ledger_identity_mismatch");
    if (event.sequence !== index) fail("ledger_sequence_invalid");
    if (event.previous_event_hash !== previous) fail("ledger_chain_broken");
    if (seenIds.has(event.event_id)) fail("ledger_event_id_duplicate");
    seenIds.add(event.event_id);
    if (!EVENT_TYPES.has(event.event_type)) fail("ledger_event_type_invalid");
    const grant = grantsById.get(event.grant_ref);
    if (!grant) fail("ledger_grant_unknown");
    const recorded = parseUtc(event.recorded_at);
    if (previousTime !== null && recorded < previousTime) fail("ledger_time_regression");
    const digest = computeEventHash(event);
    if (event.event_hash !== digest) fail("ledger_event_hash_mismatch");
    const kind = event.event_type;
    if (kind === "grant.consumed") {
      if (event.body_id === null || event.use_id === null) fail("ledger_consumption_subject_missing");
      const use = usesById.get(event.use_id);
      if (!use) fail("ledger_use_unknown");
      if (seenUses.has(event.use_id)) fail("ledger_use_duplicate");
      const decision = evaluateUse(use, grants, events.slice(0, index), new Set(document.registered_body_ids));
      if (decision.status !== "allowed" || decision.grant_ref !== event.grant_ref) fail("ledger_consumed_use_not_authorized");
      if (recorded < parseUtc(use.requested_at)) fail("ledger_consumption_time_invalid");
      if (event.body_id !== use.body_id || event.subject_digest !== use.use_digest) fail("ledger_consumption_binding_invalid");
      const bodyKey = keyResolver ? keyResolver({ envelope: event.signature, signer_type: "body", signer_id: use.body_id }) : document.keys.body;
      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: bodyKey, signerType: "body", signerId: use.body_id, createdAt: event.recorded_at, prefix: "ledger" });
      seenUses.add(event.use_id);
    } else {
      if (event.body_id !== null || event.use_id !== null) fail("ledger_guardian_event_subject_invalid");
      if (recorded < parseUtc(grant.issued_at)) fail("ledger_control_time_invalid");
      if (event.subject_digest !== grant.grant_digest) fail("ledger_grant_digest_binding_invalid");
      const guardianKey = keyResolver ? keyResolver({ envelope: event.signature, signer_type: "guardian", signer_id: document.guardian_id }) : document.keys.guardian;
      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: guardianKey, signerType: "guardian", signerId: document.guardian_id, createdAt: event.recorded_at, prefix: "ledger" });
      const current = status.get(grant.grant_id) ?? "not_issued";
      if (kind === "grant.issued") {
        if (current !== "not_issued") fail("ledger_grant_issued_twice");
        status.set(grant.grant_id, "active");
        issued.add(grant.grant_id);
      } else if (kind === "grant.suspended") {
        if (current !== "active") fail("ledger_suspend_transition_invalid");
        status.set(grant.grant_id, "suspended");
      } else if (kind === "grant.resumed") {
        if (current !== "suspended") fail("ledger_resume_transition_invalid");
        status.set(grant.grant_id, "active");
      } else if (kind === "grant.revoked") {
        if (!new Set(["active", "suspended"]).has(current)) fail("ledger_revoke_transition_invalid");
        status.set(grant.grant_id, "revoked");
      }
    }
    previous = event.event_hash;
    previousTime = recorded;
  }
  if (issued.size !== grantsById.size || [...grantsById.keys()].some((id) => !issued.has(id))) fail("ledger_grant_not_issued");
}

function scopeDigest(grant) { return hashFields("genesis.autonomy.capability.scope.v0.1", [...flattenBodyScope(grant), ...flattenScope(grant.scope), ...flattenBudget(grant.budget)]); }
function controlsDigest(grant) { return hashFields("genesis.autonomy.capability.controls.v0.1", flattenControls(grant.controls)); }

export function buildProjection(document, grants, events) {
  const at = parseUtc(document.expected.projection_at);
  const doors = [];
  for (const grant of [...grants].sort((a, b) => utf8Compare(a.capability, b.capability) || utf8Compare(a.grant_id, b.grant_id))) {
    const state = stateBefore(grant, events, at);
    let status = state.status;
    if (at < parseUtc(grant.not_before)) status = "not_yet_valid";
    else if (grant.expires_at !== null && at >= parseUtc(grant.expires_at)) status = "expired";
    const remaining = grant.use_limit === null ? null : Math.max(0, grant.use_limit - state.consumed.size);
    const door = {
      capability: grant.capability,
      grant_id: grant.grant_id,
      autonomy_level: grant.autonomy_level,
      risk_tier: grant.risk_tier,
      status,
      remaining_uses: remaining,
      expires_at: grant.expires_at,
      scope_digest: scopeDigest(grant),
      controls_digest: controlsDigest(grant),
      last_event_ref: state.last_event_ref,
    };
    door.door_digest = hashFields("genesis.autonomy.capability.door.v0.1", [door.capability, door.grant_id, String(door.autonomy_level), door.risk_tier, door.status, optionalText(door.remaining_uses), optionalText(door.expires_at), door.scope_digest, door.controls_digest, optionalText(door.last_event_ref)]);
    doors.push(door);
  }
  const projection = {
    schema_version: "genesis.autonomy.capability.projection.v0.1",
    hash_profile: "genesis.hash.fields.v0.1",
    projection_profile: "genesis.autonomy.capability.algorithm.v0.1",
    instance_id: document.instance_id,
    guardian_id: document.guardian_id,
    authority_epoch: document.authority_epoch,
    projected_at: document.expected.projection_at,
    source_event_count: events.length,
    source_last_event_hash: events.at(-1).event_hash,
    grant_count: grants.length,
    active_count: doors.filter((door) => door.status === "active").length,
    suspended_count: doors.filter((door) => door.status === "suspended").length,
    revoked_count: doors.filter((door) => door.status === "revoked").length,
    exhausted_count: doors.filter((door) => door.status === "exhausted").length,
    doors,
  };
  const fields = [projection.schema_version, projection.hash_profile, projection.projection_profile, projection.instance_id, projection.guardian_id, String(projection.authority_epoch), projection.projected_at, String(projection.source_event_count), projection.source_last_event_hash, String(projection.grant_count), String(projection.active_count), String(projection.suspended_count), String(projection.revoked_count), String(projection.exhausted_count), ...doors.map((door) => door.door_digest)];
  projection.projection_digest = hashFields("genesis.autonomy.capability.projection.v0.1", fields);
  return projection;
}

export function validateDocument(document) {
  validateNfc(document);
  const expectedTop = new Set(["profile", "status", "domains", "keys", "instance_id", "guardian_id", "authority_epoch", "registered_body_ids", "proposals", "evaluations", "grants", "ledger_events", "use_requests", "expected", "must_reject"]);
  exactFields(document, expectedTop, "document_fields_invalid");
  if (document.profile !== "genesis.autonomy.guided.v0.1" || document.status !== "draft") fail("document_profile_invalid");
  ensureInt(document.authority_epoch, "document_authority_epoch_invalid", 0);
  const registered = ensureSortedUniqueStrings(document.registered_body_ids, "registered_bodies_invalid");
  for (const [keyName, key] of Object.entries(document.keys)) {
    const keyFields = new Set(["warning", "seed_hex", "public_key_hex", "public_key_fingerprint", "signer_id", "key_epoch_id"]);
    exactFields(key, keyFields, "test_key_fields_invalid");
    if (key.signer_id !== (keyName === "guardian" ? document.guardian_id : registered[0])) fail("test_key_signer_mismatch");
    const publicRaw = Buffer.from(key.public_key_hex, "hex");
    if (key.public_key_fingerprint !== `sha256:${crypto.createHash("sha256").update(publicRaw).digest("hex")}`) fail("test_key_fingerprint_mismatch");
    try {
      const derived = rawPublicFromPrivate(privateKeyFromSeed(key.seed_hex));
      if (!derived.equals(publicRaw)) fail("test_key_public_mismatch");
    } catch (error) {
      if (error instanceof ConformanceError) throw error;
      fail("test_key_public_mismatch");
    }
  }
  const proposals = new Map();
  for (const item of document.proposals) {
    validateProposal(item, document);
    if (proposals.has(item.proposal_id)) fail("proposal_id_duplicate");
    proposals.set(item.proposal_id, item);
  }
  const evaluations = new Map();
  for (const item of document.evaluations) {
    const proposal = proposals.get(item.proposal_ref);
    if (!proposal) fail("evaluation_proposal_missing");
    validateEvaluation(item, proposal, document);
    if (evaluations.has(item.evaluation_id)) fail("evaluation_id_duplicate");
    evaluations.set(item.evaluation_id, item);
  }
  const grants = [];
  const grantIds = new Set();
  for (const item of document.grants) {
    const proposal = proposals.get(item.proposal_ref);
    const evaluation = evaluations.get(item.evaluation_ref);
    if (!proposal) fail("grant_proposal_missing");
    if (!evaluation) fail("grant_evaluation_missing");
    validateGrant(item, proposal, evaluation, document);
    if (grantIds.has(item.grant_id)) fail("grant_id_duplicate");
    grantIds.add(item.grant_id);
    grants.push(item);
  }
  const uses = [];
  const useIds = new Set();
  for (const item of document.use_requests) {
    validateUse(item, document);
    if (useIds.has(item.use_id)) fail("use_id_duplicate");
    useIds.add(item.use_id);
    uses.push(item);
  }
  validateLedger(document.ledger_events, grants, uses, document);
  const decisions = uses.map((item) => evaluateUse(item, grants, document.ledger_events, new Set(registered)));
  const projection = buildProjection(document, grants, document.ledger_events);
  exactFields(document.expected, new Set(["projection_at", "projection_digest", "decision_digests", "allowed_count", "denied_count"]), "expected_fields_invalid");
  if (projection.projection_digest !== document.expected.projection_digest) fail("expected_projection_digest_mismatch");
  const decisionMap = Object.fromEntries(decisions.map((item) => [item.use_id, item.decision_digest]));
  if (JSON.stringify(decisionMap) !== JSON.stringify(document.expected.decision_digests)) fail("expected_decision_digest_mismatch");
  const allowed = decisions.filter((item) => item.status === "allowed").length;
  const denied = decisions.filter((item) => item.status === "denied").length;
  if (allowed !== document.expected.allowed_count || denied !== document.expected.denied_count) fail("expected_decision_count_mismatch");
  return { projection, decisions };
}

function setPath(target, pathParts, value) {
  let cursor = target;
  for (const part of pathParts.slice(0, -1)) cursor = cursor[part];
  cursor[pathParts.at(-1)] = value;
}
function resignProposal(document, item) {
  item.proposal_digest = computeProposalDigest(item);
  item.signature = makeSignature({ key: document.keys.body, signerType: "body", signerId: item.body_id, digest: item.proposal_digest, domain: document.domains.proposal_signature, createdAt: item.created_at });
}
function resignEvaluation(document, item) {
  item.evaluation_digest = computeEvaluationDigest(item);
  item.signature = makeSignature({ key: document.keys.guardian, signerType: "guardian", signerId: document.guardian_id, digest: item.evaluation_digest, domain: document.domains.evaluation_signature, createdAt: item.evaluated_at });
}
function resignGrant(document, item) {
  item.grant_digest = computeGrantDigest(item);
  item.signature = makeSignature({ key: document.keys.guardian, signerType: "guardian", signerId: document.guardian_id, digest: item.grant_digest, domain: document.domains.grant_signature, createdAt: item.issued_at });
}
function resignUse(document, item) {
  item.use_digest = computeUseDigest(item);
  item.signature = makeSignature({ key: document.keys.body, signerType: "body", signerId: item.body_id, digest: item.use_digest, domain: item.schema_version === "genesis.autonomy.capability.use.v0.2" ? "genesis.autonomy.capability.use.signature.v0.2" : document.domains.use_signature, createdAt: item.requested_at });
}
function rebuildLedger(document) {
  const grants = new Map(document.grants.map((item) => [item.grant_id, item]));
  const uses = new Map(document.use_requests.map((item) => [item.use_id, item]));
  let previous = "GENESIS";
  for (const event of document.ledger_events) {
    event.previous_event_hash = previous;
    let keyName;
    let signerType;
    let signerId;
    if (event.event_type === "grant.consumed") {
      const use = uses.get(event.use_id);
      if (use) event.subject_digest = use.use_digest;
      keyName = "body";
      signerType = "body";
      signerId = event.body_id;
    } else {
      const grant = grants.get(event.grant_ref);
      if (grant) event.subject_digest = grant.grant_digest;
      keyName = "guardian";
      signerType = "guardian";
      signerId = document.guardian_id;
    }
    event.event_hash = computeEventHash(event);
    event.signature = makeSignature({ key: document.keys[keyName], signerType, signerId, digest: event.event_hash, domain: document.domains.event_signature, createdAt: event.recorded_at });
    previous = event.event_hash;
  }
}
function refreshProposalDependents(document, proposal) {
  const evaluations = new Map();
  for (const evaluation of document.evaluations) {
    if (evaluation.proposal_ref === proposal.proposal_id) {
      evaluation.proposal_digest = proposal.proposal_digest;
      resignEvaluation(document, evaluation);
    }
    evaluations.set(evaluation.evaluation_id, evaluation);
  }
  for (const grant of document.grants) {
    if (grant.proposal_ref === proposal.proposal_id) {
      grant.proposal_digest = proposal.proposal_digest;
      const evaluation = evaluations.get(grant.evaluation_ref);
      if (evaluation) grant.evaluation_digest = evaluation.evaluation_digest;
      resignGrant(document, grant);
    }
  }
  rebuildLedger(document);
}
function refreshEvaluationDependents(document, evaluation) {
  for (const grant of document.grants) {
    if (grant.evaluation_ref === evaluation.evaluation_id) {
      grant.evaluation_digest = evaluation.evaluation_digest;
      resignGrant(document, grant);
    }
  }
  rebuildLedger(document);
}
function recomputeMutated(document, target, item) {
  if (target === "proposal") {
    resignProposal(document, item);
    refreshProposalDependents(document, item);
  } else if (target === "evaluation") {
    resignEvaluation(document, item);
    refreshEvaluationDependents(document, item);
  } else if (target === "grant") {
    resignGrant(document, item);
    rebuildLedger(document);
  } else if (target === "use") {
    resignUse(document, item);
    rebuildLedger(document);
  } else if (target === "event") {
    item.event_hash = computeEventHash(item);
    const keyName = item.event_type === "grant.consumed" ? "body" : "guardian";
    const signerType = keyName;
    const signerId = keyName === "body" ? item.body_id : document.guardian_id;
    item.signature = makeSignature({ key: document.keys[keyName], signerType, signerId, digest: item.event_hash, domain: document.domains.event_signature, createdAt: item.recorded_at });
  }
}
function applyMutation(document, mutation) {
  const target = mutation.target;
  let item;
  if (target === "document") item = document;
  else {
    const collection = { proposal: "proposals", evaluation: "evaluations", grant: "grants", event: "ledger_events", use: "use_requests", key: "keys" }[target];
    item = collection === "keys" ? document.keys[mutation.key_name ?? "guardian"] : document[collection][mutation.index ?? 0];
  }
  setPath(item, mutation.path, mutation.value);
  if (mutation.recompute) recomputeMutated(document, target, item);
}

export function runRejections(document) {
  let rejected = 0;
  for (const test of document.must_reject) {
    const candidate = structuredClone(document);
    applyMutation(candidate, test.mutation);
    try {
      validateDocument(candidate);
    } catch (error) {
      if (!(error instanceof ConformanceError)) throw error;
      if (error.message !== test.expected_error) throw new Error(`${test.case_id}:expected:${test.expected_error}:got:${error.message}`);
      rejected += 1;
      continue;
    }
    throw new Error(`${test.case_id}:mutation_accepted`);
  }
  return rejected;
}

function projectionDigest(projection) {
  const fields = [projection.schema_version, projection.hash_profile, projection.projection_profile, projection.instance_id, projection.guardian_id, String(projection.authority_epoch), projection.projected_at, String(projection.source_event_count), projection.source_last_event_hash, String(projection.grant_count), String(projection.active_count), String(projection.suspended_count), String(projection.revoked_count), String(projection.exhausted_count), ...projection.doors.map((door) => door.door_digest)];
  return hashFields("genesis.autonomy.capability.projection.v0.1", fields);
}
function verifyProjection(projection) {
  const expected = new Set(["schema_version", "hash_profile", "projection_profile", "instance_id", "guardian_id", "authority_epoch", "projected_at", "source_event_count", "source_last_event_hash", "grant_count", "active_count", "suspended_count", "revoked_count", "exhausted_count", "doors", "projection_digest"]);
  exactFields(projection, expected, "projection_fields_invalid");
  if (projection.schema_version !== "genesis.autonomy.capability.projection.v0.1" || projection.projection_profile !== "genesis.autonomy.capability.algorithm.v0.1") fail("projection_profile_invalid");
  if (projection.projection_digest !== projectionDigest(projection)) fail("projection_digest_mismatch");
  return projection;
}
function atomicWrite(output, value) {
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const temp = path.join(path.dirname(output), `.${path.basename(output)}.${process.pid}.tmp`);
  const fd = fs.openSync(temp, "wx", 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, output);
}

function readJson(input) { return JSON.parse(fs.readFileSync(input, "utf8")); }
function usage() {
  console.error("usage: guided_autonomy.mjs validate [vectors.json] | build <vectors.json> <projection.json> | sync <vectors.json> <projection.json> | decide <vectors.json> <use_id> | inspect <projection.json>");
  process.exit(2);
}

function main(argv) {
  const [command = "validate", ...args] = argv;
  if (command === "validate") {
    const source = path.resolve(args[0] ?? DEFAULT_VECTOR);
    const document = readJson(source);
    const { projection, decisions } = validateDocument(document);
    const rejected = runRejections(document);
    console.log(`OK guided autonomy grants (${projection.grant_count} doors, ${projection.source_event_count} ledger events)`);
    console.log(`OK autonomy projection digest ${projection.projection_digest}`);
    console.log(`OK use decisions (${decisions.filter((item) => item.status === "allowed").length} allowed, ${decisions.filter((item) => item.status === "denied").length} denied)`);
    console.log(`OK guided autonomy boundary rejection cases (${rejected})`);
    console.log("NOTE proposals and evaluations never self-authorize; only signed guardian grants open capabilities.");
  } else if (command === "build" || command === "sync") {
    if (args.length !== 2) usage();
    const document = readJson(path.resolve(args[0]));
    const { projection } = validateDocument(document);
    const output = path.resolve(args[1]);
    atomicWrite(output, projection);
    console.log(output);
  } else if (command === "decide") {
    if (args.length !== 2) usage();
    const document = readJson(path.resolve(args[0]));
    const { decisions } = validateDocument(document);
    const decision = decisions.find((item) => item.use_id === args[1]);
    if (!decision) fail("use_request_not_found");
    console.log(JSON.stringify(decision, null, 2));
  } else if (command === "inspect") {
    if (args.length !== 1) usage();
    const projection = verifyProjection(readJson(path.resolve(args[0])));
    console.log(JSON.stringify({ instance_id: projection.instance_id, guardian_id: projection.guardian_id, authority_epoch: projection.authority_epoch, projected_at: projection.projected_at, grant_count: projection.grant_count, active_count: projection.active_count, doors: projection.doors.map(({ capability, grant_id, autonomy_level, risk_tier, status, remaining_uses, expires_at }) => ({ capability, grant_id, autonomy_level, risk_tier, status, remaining_uses, expires_at })), projection_digest: projection.projection_digest }, null, 2));
  } else usage();
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exit(1); }
}

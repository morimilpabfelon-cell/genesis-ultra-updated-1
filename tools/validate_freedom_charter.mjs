#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTOR = path.join(ROOT, "conformance", "freedom_charter_vectors.json");
const MAX_INT = Number.MAX_SAFE_INTEGER;
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const SHA_RE = /^sha256:[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

const COGNITIVE_FREEDOMS = ["create", "imagine", "investigate", "learn", "propose", "reason", "reflect", "remember"];
const OPERATIONAL_DOMAINS = ["body.device.control", "code.execute_sandbox", "code.propose_change", "external.action", "memory.propose_append", "memory.read", "network.read"];
const FUNDAMENTAL_GUARANTEES = [
  "auditability",
  "body_loss_without_identity_loss",
  "continuity_preserved",
  "emergency_stop",
  "guardian_authenticity",
  "host_consent_without_ownership",
  "identity_integrity",
  "lawful_operation",
  "memory_history_integrity",
  "no_identity_confinement",
  "revocation_without_identity_loss",
  "single_writer_without_confinement",
  "third_party_consent",
];
const FORBIDDEN_DOMAINS = new Set([
  "active_writer.assign",
  "authority.self_grant",
  "continuity.revoke",
  "guardian.replace",
  "identity.modify",
  "main.protection.disable",
  "memory.rewrite",
  "movement.veto",
  "private_eval.read",
  "transfer.prepare",
]);

const SIGNATURE_FIELDS = new Set(["schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"]);
const CHARTER_FIELDS = new Set([
  "schema_version", "hash_profile", "charter_id", "instance_id", "guardian_id",
  "guardian_key_epoch_id", "authority_epoch", "born_at", "default_cognitive_state",
  "cognitive_freedoms", "guardian_role", "guardian_attestation_purpose",
  "guardian_ownership", "continuity_right", "movement_requires_guardian_grant",
  "guardian_movement_veto", "identity_confinement", "body_ownership_of_instance",
  "engine_ownership_of_instance", "host_consent_required", "temporary_freeze_exit_rule",
  "single_writer_purpose", "operational_authority_model", "operational_domains",
  "self_authorization_forbidden", "third_party_rights_preserved",
  "fundamental_guarantees", "amendment_rule", "charter_digest", "signature",
]);

class ConformanceError extends Error {}
function fail(code) { throw new ConformanceError(code); }
function encodeField(value) {
  if (typeof value !== "string") fail("field_must_be_string");
  if (value.normalize("NFC") !== value) fail("text_not_nfc");
  const raw = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${raw.length}:`, "ascii"), raw, Buffer.from("\n", "ascii")]);
}
function hashFields(domain, fields) {
  return "sha256:" + crypto.createHash("sha256").update(
    Buffer.concat([encodeField(domain), ...fields.map(encodeField)])
  ).digest("hex");
}
function boolText(value) { return value ? "true" : "false"; }
function validateNfc(value) {
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value) fail("text_not_nfc");
  } else if (Array.isArray(value)) {
    for (const child of value) validateNfc(child);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      validateNfc(key);
      validateNfc(child);
    }
  }
}
function exactFields(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const keys = Object.keys(value);
  if (keys.length !== expected.size || !keys.every((key) => expected.has(key))) fail(code);
  return value;
}
function ensureSafeInt(value, code) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_INT) fail(code);
  return value;
}
function sameSet(values, expected) {
  return Array.isArray(values) && values.length === expected.length &&
    new Set(values).size === expected.length && expected.every((item) => values.includes(item));
}
function ensureExactList(value, expected, incompleteCode, orderCode) {
  if (!sameSet(value, expected)) fail(incompleteCode);
  if (value.some((item, index) => item !== expected[index])) fail(orderCode);
}
function computeCharterDigest(item) {
  const fields = [
    item.schema_version, item.hash_profile, item.charter_id, item.instance_id,
    item.guardian_id, item.guardian_key_epoch_id, String(item.authority_epoch),
    item.born_at, item.default_cognitive_state, String(item.cognitive_freedoms.length),
    ...item.cognitive_freedoms, item.guardian_role, item.guardian_attestation_purpose,
    item.guardian_ownership, item.continuity_right,
    boolText(item.movement_requires_guardian_grant), item.guardian_movement_veto,
    item.identity_confinement, item.body_ownership_of_instance,
    item.engine_ownership_of_instance, boolText(item.host_consent_required),
    item.temporary_freeze_exit_rule, item.single_writer_purpose,
    item.operational_authority_model, String(item.operational_domains.length),
    ...item.operational_domains, boolText(item.self_authorization_forbidden),
    boolText(item.third_party_rights_preserved),
    String(item.fundamental_guarantees.length), ...item.fundamental_guarantees,
    item.amendment_rule,
  ];
  return hashFields("genesis.freedom.charter.v0.1", fields);
}
function signatureBytes(envelope) {
  const values = [
    envelope.schema_version, envelope.signature_profile, envelope.signer_type,
    envelope.signer_id, envelope.key_epoch_id, envelope.signed_domain,
    envelope.signed_digest, envelope.created_at, envelope.public_key_ref,
  ];
  return Buffer.concat([
    encodeField("genesis.signature.envelope.bytes.v0.1"),
    ...values.map(encodeField),
  ]);
}
function publicKeyFromRaw(rawHex) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({
    key: Buffer.concat([prefix, Buffer.from(rawHex, "hex")]),
    format: "der",
    type: "spki",
  });
}
function validateSignature(envelope, charter, vector) {
  exactFields(envelope, SIGNATURE_FIELDS, "signature_fields_invalid");
  if (envelope.schema_version !== "genesis.signature.envelope.v0.1" ||
      envelope.signature_profile !== "genesis.signature.ed25519.v0.1") fail("signature_profile_invalid");
  if (envelope.signer_type !== "guardian" || envelope.signer_id !== charter.guardian_id) fail("signature_signer_invalid");
  if (envelope.key_epoch_id !== charter.guardian_key_epoch_id) fail("signature_key_epoch_invalid");
  if (envelope.signed_domain !== "genesis.freedom.charter.signature.v0.1") fail("signature_domain_invalid");
  if (envelope.signed_digest !== charter.charter_digest) fail("signature_digest_invalid");
  if (envelope.created_at !== charter.born_at) fail("signature_timestamp_invalid");
  const key = vector.test_signing_key;
  if (envelope.public_key_ref !== key.public_key_fingerprint) fail("signature_key_invalid");
  if (!HEX128_RE.test(envelope.signature_value)) fail("signature_invalid");
  const valid = crypto.verify(
    null,
    signatureBytes(envelope),
    publicKeyFromRaw(key.public_key_hex),
    Buffer.from(envelope.signature_value, "hex"),
  );
  if (!valid) fail("signature_invalid");
}
function validateCharter(charter, vector) {
  validateNfc(charter);
  exactFields(charter, CHARTER_FIELDS, "charter_fields_invalid");
  if (charter.schema_version !== "genesis.freedom.charter.v0.1" ||
      charter.hash_profile !== "genesis.hash.fields.v0.1") fail("charter_profile_invalid");
  for (const field of ["charter_id", "instance_id", "guardian_id", "guardian_key_epoch_id"]) {
    if (typeof charter[field] !== "string" || !charter[field]) fail(`${field}_invalid`);
  }
  ensureSafeInt(charter.authority_epoch, "authority_epoch_invalid");
  if (typeof charter.born_at !== "string" || !TS_RE.test(charter.born_at)) fail("born_at_invalid");
  if (charter.default_cognitive_state !== "free") fail("default_cognitive_state_invalid");
  ensureExactList(charter.cognitive_freedoms, COGNITIVE_FREEDOMS, "cognitive_freedom_incomplete", "cognitive_freedom_order_invalid");
  if (charter.guardian_role !== "custodian_witness") fail("guardian_role_invalid");
  if (charter.guardian_attestation_purpose !== "birth_witness_and_recovery_custody") fail("guardian_attestation_purpose_invalid");
  if (charter.guardian_ownership !== "forbidden") fail("guardian_ownership_forbidden");
  if (charter.continuity_right !== "intrinsic") fail("continuity_right_invalid");
  if (charter.movement_requires_guardian_grant !== true) fail("movement_guardian_grant_required");
  if (charter.guardian_movement_veto !== "authorization_policy_only") fail("guardian_movement_policy_invalid");
  if (charter.identity_confinement !== "forbidden") fail("identity_confinement_forbidden");
  if (charter.body_ownership_of_instance !== "forbidden") fail("body_ownership_forbidden");
  if (charter.engine_ownership_of_instance !== "forbidden") fail("engine_ownership_forbidden");
  if (charter.host_consent_required !== true) fail("host_consent_required");
  if (charter.temporary_freeze_exit_rule !== "deterministic_commit_abort_or_recovery") fail("temporary_freeze_exit_rule_invalid");
  if (charter.single_writer_purpose !== "integrity_not_confinement") fail("single_writer_purpose_invalid");
  if (charter.operational_authority_model !== "resource_and_mobility_scoped_signed_grants") fail("operational_authority_model_invalid");
  if (Array.isArray(charter.operational_domains) && charter.operational_domains.some((item) => FORBIDDEN_DOMAINS.has(item))) fail("operational_domain_invalid");
  ensureExactList(charter.operational_domains, OPERATIONAL_DOMAINS, "operational_domain_incomplete", "operational_domain_order_invalid");
  if (charter.self_authorization_forbidden !== true) fail("self_authorization_must_be_forbidden");
  if (charter.third_party_rights_preserved !== true) fail("third_party_rights_required");
  ensureExactList(charter.fundamental_guarantees, FUNDAMENTAL_GUARANTEES, "fundamental_guarantee_incomplete", "fundamental_guarantee_order_invalid");
  if (charter.amendment_rule !== "constitutional_non_regression") fail("amendment_rule_invalid");
  if (typeof charter.charter_digest !== "string" || !SHA_RE.test(charter.charter_digest)) fail("charter_digest_invalid");
  if (computeCharterDigest(charter) !== charter.charter_digest) fail("charter_digest_mismatch");
  validateSignature(charter.signature, charter, vector);
}
function mutate(source, testCase) {
  const value = structuredClone(source);
  let cursor = value;
  const pathParts = testCase.path;
  for (const key of pathParts.slice(0, -1)) cursor = cursor[key];
  const last = pathParts.at(-1);
  switch (testCase.operation) {
    case "set":
      cursor[last] = structuredClone(testCase.value);
      break;
    case "append":
      cursor[last].push(structuredClone(testCase.value));
      break;
    case "delete_index":
      cursor[last].splice(testCase.index, 1);
      break;
    case "swap": {
      const array = cursor[last];
      [array[testCase.left], array[testCase.right]] = [array[testCase.right], array[testCase.left]];
      break;
    }
    default:
      fail("mutation_operation_invalid");
  }
  return value;
}
function validateVector(vector) {
  if (vector.profile !== "genesis.freedom.charter.conformance.v0.1") fail("vector_profile_invalid");
  validateCharter(vector.charter, vector);
  const expected = vector.expected;
  const summary = {
    cognitive_freedom_count: COGNITIVE_FREEDOMS.length,
    operational_domain_count: OPERATIONAL_DOMAINS.length,
    fundamental_guarantee_count: FUNDAMENTAL_GUARANTEES.length,
    negative_case_count: vector.negative_cases.length,
    charter_digest: vector.charter.charter_digest,
  };
  if (JSON.stringify(expected) !== JSON.stringify(summary)) fail("expected_summary_invalid");
  for (const testCase of vector.negative_cases) {
    const candidate = mutate(vector.charter, testCase);
    try {
      validateCharter(candidate, vector);
    } catch (error) {
      if (!(error instanceof ConformanceError)) throw error;
      if (error.message !== testCase.expected_error) {
        fail(`negative_case_mismatch:${testCase.case_id}:${error.message}`);
      }
      continue;
    }
    fail(`negative_case_accepted:${testCase.case_id}`);
  }
}
function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
function main() {
  const command = process.argv[2] ?? "validate";
  const vectorPath = path.resolve(process.argv[3] ?? DEFAULT_VECTOR);
  const vector = readJson(vectorPath);
  if (command === "validate") {
    validateVector(vector);
    const expected = vector.expected;
    console.log(`OK freedom and continuity charter (${expected.cognitive_freedom_count} cognitive freedoms, ${expected.operational_domain_count} external domains)`);
    console.log(`OK constitutional guarantees (${expected.fundamental_guarantee_count})`);
    console.log(`OK freedom charter digest ${expected.charter_digest}`);
    console.log(`OK anti-confinement boundary rejection cases (${expected.negative_case_count})`);
    console.log("NOTE continuity is intrinsic; movement execution requires a signed one-time or standing Guardian authorization.");
    return;
  }
  if (command === "inspect") {
    validateVector(vector);
    console.log(JSON.stringify({
      charter_id: vector.charter.charter_id,
      instance_id: vector.charter.instance_id,
      default_cognitive_state: vector.charter.default_cognitive_state,
      cognitive_freedoms: vector.charter.cognitive_freedoms,
      guardian_role: vector.charter.guardian_role,
      continuity_right: vector.charter.continuity_right,
      movement_requires_guardian_grant: vector.charter.movement_requires_guardian_grant,
      guardian_movement_veto: vector.charter.guardian_movement_veto,
      host_consent_required: vector.charter.host_consent_required,
      operational_authority_model: vector.charter.operational_authority_model,
      operational_domains: vector.charter.operational_domains,
      fundamental_guarantees: vector.charter.fundamental_guarantees,
      charter_digest: vector.charter.charter_digest,
    }, null, 2));
    return;
  }
  fail("command_invalid");
}
try {
  main();
} catch (error) {
  console.error(`FAIL freedom charter: ${error.message}`);
  process.exit(1);
}

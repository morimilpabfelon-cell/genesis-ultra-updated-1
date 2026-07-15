import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/sense_adapter_vectors.json"), "utf8")
);

const MANIFEST_FIELDS = new Set([
  "schema_version", "adapter_id", "adapter_version", "platform_profile", "sense",
  "source_kinds", "verification_state", "permission_model", "capabilities", "boundary"
]);
const RESULT_FIELDS = new Set([
  "schema_version", "hash_profile", "capture_id", "adapter_id", "adapter_version",
  "sense", "source_kind", "status", "captured_at", "payload_digest",
  "payload_media_type", "privacy", "permission_state", "diagnostic_code", "result_digest"
]);
const RESULT_DIGEST_FIELDS = [
  "schema_version", "hash_profile", "capture_id", "adapter_id", "adapter_version",
  "sense", "source_kind", "status", "captured_at", "payload_digest",
  "payload_media_type", "privacy", "permission_state", "diagnostic_code"
];
const OBSERVATION_FIELDS = new Set([
  "schema_version", "hash_profile", "observation_id", "instance_id", "body_id",
  "observation_sequence", "sense", "source_kind", "captured_at", "payload_digest",
  "payload_media_type", "evidence_digest", "privacy", "observation_digest", "signature"
]);
const OBSERVATION_DIGEST_FIELDS = [
  "schema_version", "hash_profile", "observation_id", "instance_id", "body_id",
  "observation_sequence", "sense", "source_kind", "captured_at", "payload_digest",
  "payload_media_type", "evidence_digest", "privacy"
];
const BOUNDARY_RULES = new Map([
  ["emits_raw_payload", "adapter_raw_payload_forbidden"],
  ["exports_platform_handles", "adapter_platform_handle_export_forbidden"],
  ["writes_memory", "adapter_memory_write_forbidden"],
  ["executes_actions", "adapter_action_forbidden"],
  ["mutates_identity", "adapter_identity_mutation_forbidden"]
]);
const SENSES = new Set(["vision", "proprioception", "interoception"]);
const SOURCE_KINDS = new Set([
  "local_sensor", "user_input", "runtime_state", "network_evidence", "clock"
]);

class ConformanceError extends Error {}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function frame(value) {
  if (typeof value !== "string") throw new ConformanceError("field_must_be_string");
  if (value !== value.normalize("NFC")) throw new ConformanceError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([
    Buffer.from(String(bytes.length) + ":", "ascii"),
    bytes,
    Buffer.from("\n", "ascii")
  ]);
}

function optionalText(value) {
  return value === null ? "" : String(value);
}

function hashFields(domain, fields) {
  const payload = Buffer.concat([frame(domain), ...fields.map((value) => frame(value))]);
  return "sha256:" + crypto.createHash("sha256").update(payload).digest("hex");
}

function validateNfc(value) {
  if (typeof value === "string") {
    if (value !== value.normalize("NFC")) throw new ConformanceError("text_not_nfc");
  } else if (Array.isArray(value)) {
    for (const child of value) validateNfc(child);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      validateNfc(key);
      validateNfc(child);
    }
  }
}

function exactFields(value, expected) {
  const fields = Object.keys(value);
  return fields.length === expected.size && fields.every((field) => expected.has(field));
}

function computeResultDigest(result) {
  validateNfc(result);
  if (!exactFields(result, RESULT_FIELDS)) {
    throw new ConformanceError("capture_result_fields_invalid");
  }
  return hashFields(
    vectors.domains.capture_result,
    RESULT_DIGEST_FIELDS.map((field) => optionalText(result[field]))
  );
}

function computeObservationDigest(observation) {
  validateNfc(observation);
  if (!exactFields(observation, OBSERVATION_FIELDS)) {
    throw new ConformanceError("observation_fields_invalid");
  }
  return hashFields(
    vectors.domains.observation,
    OBSERVATION_DIGEST_FIELDS.map((field) => String(observation[field]))
  );
}

function privateKeyFromSeed(seed) {
  if (seed.length !== 32) throw new ConformanceError("sense_adapter_test_seed_length_invalid");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: "der",
    type: "pkcs8"
  });
}

function rawPublicKey(privateKey) {
  const exported = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  if (!exported.subarray(0, prefix.length).equals(prefix)) {
    throw new ConformanceError("sense_adapter_test_public_key_encoding_invalid");
  }
  return exported.subarray(prefix.length);
}

function signatureBytes(envelope) {
  return Buffer.concat([
    frame("genesis.signature.envelope.bytes.v0.1"),
    ...[
      envelope.schema_version,
      envelope.signature_profile,
      envelope.signer_type,
      envelope.signer_id,
      envelope.key_epoch_id,
      envelope.signed_domain,
      envelope.signed_digest,
      envelope.created_at,
      envelope.public_key_ref
    ].map((value) => frame(value))
  ]);
}

function signEnvelope(envelope, digest, domain, privateKey) {
  envelope.signed_domain = domain;
  envelope.signed_digest = digest;
  envelope.signature_value = crypto
    .sign(null, signatureBytes(envelope), privateKey)
    .toString("hex");
}

function validateSignature(envelope, digest, bodyId, keys) {
  const domain = vectors.domains.observation_signature;
  if (envelope.signature_profile !== "genesis.signature.ed25519.v0.1") {
    throw new ConformanceError("observation_signature_profile_invalid");
  }
  if (envelope.signer_type !== "body" || envelope.signer_id !== bodyId) {
    throw new ConformanceError("observation_signer_mismatch");
  }
  if (envelope.signed_domain !== domain) {
    throw new ConformanceError("observation_signature_domain_mismatch");
  }
  if (envelope.signed_digest !== digest) {
    throw new ConformanceError("observation_signature_digest_mismatch");
  }
  if (envelope.public_key_ref !== vectors.test_signing_key.public_key_fingerprint) {
    throw new ConformanceError("observation_signature_key_mismatch");
  }
  let signature;
  try {
    signature = Buffer.from(envelope.signature_value, "hex");
  } catch {
    throw new ConformanceError("observation_signature_invalid");
  }
  if (
    signature.length !== 64
    || !crypto.verify(null, signatureBytes(envelope), keys.publicKey, signature)
  ) {
    throw new ConformanceError("observation_signature_invalid");
  }
}

function validateCapabilities(capabilities, required) {
  if (new Set(capabilities).size !== capabilities.length) {
    throw new ConformanceError("duplicate_adapter_capability");
  }
  const sorted = [...capabilities].sort(compareUtf8);
  if (capabilities.some((value, index) => value !== sorted[index])) {
    throw new ConformanceError("unsorted_adapter_capabilities");
  }
  if (required.some((capability) => !capabilities.includes(capability))) {
    throw new ConformanceError("missing_adapter_capability");
  }
  if (capabilities.some((capability) => !required.includes(capability))) {
    throw new ConformanceError("unsupported_adapter_capability");
  }
}

function validateManifest(manifest) {
  validateNfc(manifest);
  const additional = Object.keys(manifest).filter((field) => !MANIFEST_FIELDS.has(field));
  const forbiddenIdentity = new Set(vectors.forbidden_adapter_identity_fields);
  const forbiddenMemory = new Set(vectors.forbidden_adapter_memory_fields);
  if (additional.some((field) => forbiddenIdentity.has(field))) {
    throw new ConformanceError("adapter_manifest_contains_identity");
  }
  if (additional.some((field) => forbiddenMemory.has(field))) {
    throw new ConformanceError("adapter_manifest_contains_memory");
  }
  if (!exactFields(manifest, MANIFEST_FIELDS)) {
    throw new ConformanceError("adapter_manifest_fields_invalid");
  }
  if (manifest.schema_version !== "genesis.sense.adapter.manifest.v0.1") {
    throw new ConformanceError("adapter_manifest_schema_version_invalid");
  }
  if (!SENSES.has(manifest.sense)) throw new ConformanceError("adapter_sense_invalid");
  if (new Set(manifest.source_kinds).size !== manifest.source_kinds.length) {
    throw new ConformanceError("duplicate_adapter_source");
  }
  const sortedSources = [...manifest.source_kinds].sort(compareUtf8);
  if (manifest.source_kinds.some((value, index) => value !== sortedSources[index])) {
    throw new ConformanceError("unsorted_adapter_sources");
  }
  if (
    manifest.source_kinds.length === 0
    || manifest.source_kinds.some((source) => !SOURCE_KINDS.has(source))
  ) {
    throw new ConformanceError("adapter_source_invalid");
  }
  validateCapabilities(manifest.capabilities, vectors.required_capabilities);
  const boundaryFields = Object.keys(manifest.boundary);
  if (
    boundaryFields.length !== BOUNDARY_RULES.size
    || boundaryFields.some((field) => !BOUNDARY_RULES.has(field))
  ) {
    throw new ConformanceError("adapter_boundary_fields_invalid");
  }
  for (const [field, errorCode] of BOUNDARY_RULES) {
    if (manifest.boundary[field] !== false) throw new ConformanceError(errorCode);
  }
  if (
    manifest.platform_profile === "reference-neutral"
    && manifest.verification_state === "platform_verified"
  ) {
    throw new ConformanceError("reference_adapter_cannot_claim_platform_verification");
  }
  if (!["declaration_only", "simulated", "platform_verified"].includes(manifest.verification_state)) {
    throw new ConformanceError("adapter_verification_state_invalid");
  }
  if (!["os_runtime", "local_runtime", "not_required"].includes(manifest.permission_model)) {
    throw new ConformanceError("adapter_permission_model_invalid");
  }
}

function validateResult(result, manifest) {
  validateNfc(result);
  const additional = Object.keys(result).filter((field) => !RESULT_FIELDS.has(field));
  if (additional.includes("raw_payload")) {
    throw new ConformanceError("capture_result_raw_payload_forbidden");
  }
  const forbiddenIdentity = new Set(vectors.forbidden_adapter_identity_fields);
  if (additional.some((field) => forbiddenIdentity.has(field))) {
    throw new ConformanceError("capture_result_contains_identity");
  }
  const forbiddenMemory = new Set(vectors.forbidden_adapter_memory_fields);
  if (additional.some((field) => forbiddenMemory.has(field))) {
    throw new ConformanceError("capture_result_contains_memory");
  }
  const forbidden = new Set(vectors.forbidden_capture_result_fields);
  if (additional.some((field) => forbidden.has(field))) {
    throw new ConformanceError("capture_result_platform_binding");
  }
  if (!exactFields(result, RESULT_FIELDS)) {
    throw new ConformanceError("capture_result_fields_invalid");
  }
  if (result.schema_version !== vectors.domains.capture_result) {
    throw new ConformanceError("capture_result_schema_version_invalid");
  }
  if (result.hash_profile !== "genesis.hash.fields.v0.1") {
    throw new ConformanceError("capture_result_hash_profile_invalid");
  }
  if (result.adapter_id !== manifest.adapter_id) {
    throw new ConformanceError("capture_result_adapter_mismatch");
  }
  if (result.adapter_version !== manifest.adapter_version) {
    throw new ConformanceError("capture_result_adapter_version_mismatch");
  }
  if (result.sense !== manifest.sense) {
    throw new ConformanceError("capture_result_sense_mismatch");
  }
  if (!manifest.source_kinds.includes(result.source_kind)) {
    throw new ConformanceError("capture_result_source_not_declared");
  }
  if (!["captured", "denied", "unavailable", "failed"].includes(result.status)) {
    throw new ConformanceError("capture_result_status_invalid");
  }
  if (result.status === "captured") {
    if (!["granted", "not_required"].includes(result.permission_state)) {
      throw new ConformanceError("captured_result_permission_invalid");
    }
    if (
      result.captured_at === null
      || result.payload_digest === null
      || result.payload_media_type === null
    ) {
      throw new ConformanceError("captured_result_payload_required");
    }
  } else {
    if (
      result.captured_at !== null
      || result.payload_digest !== null
      || result.payload_media_type !== null
    ) {
      throw new ConformanceError("noncaptured_result_payload_forbidden");
    }
    if (result.status === "denied" && result.permission_state !== "denied") {
      throw new ConformanceError("denied_result_permission_mismatch");
    }
    if (result.status === "unavailable" && result.permission_state !== "unavailable") {
      throw new ConformanceError("unavailable_result_permission_mismatch");
    }
  }
  if (computeResultDigest(result) !== result.result_digest) {
    throw new ConformanceError("capture_result_digest_mismatch");
  }
}

function validateObservation(observation, result, keys) {
  if (result.status !== "captured") {
    if (observation !== null) {
      throw new ConformanceError("noncaptured_result_must_not_emit_observation");
    }
    return;
  }
  if (observation === null) {
    throw new ConformanceError("captured_result_observation_required");
  }
  validateNfc(observation);
  if (!exactFields(observation, OBSERVATION_FIELDS)) {
    throw new ConformanceError("observation_fields_invalid");
  }
  if (observation.schema_version !== vectors.domains.observation) {
    throw new ConformanceError("observation_schema_version_invalid");
  }
  if (observation.hash_profile !== "genesis.hash.fields.v0.1") {
    throw new ConformanceError("observation_hash_profile_invalid");
  }
  if (!Number.isSafeInteger(observation.observation_sequence) || observation.observation_sequence < 0) {
    throw new ConformanceError("observation_sequence_invalid");
  }
  const links = [
    ["sense", "observation_sense_mismatch"],
    ["source_kind", "observation_source_mismatch"],
    ["captured_at", "observation_captured_at_mismatch"],
    ["payload_digest", "observation_payload_digest_mismatch"],
    ["payload_media_type", "observation_media_type_mismatch"],
    ["privacy", "observation_privacy_mismatch"]
  ];
  for (const [field, errorCode] of links) {
    if (observation[field] !== result[field]) throw new ConformanceError(errorCode);
  }
  if (observation.evidence_digest !== result.result_digest) {
    throw new ConformanceError("observation_evidence_digest_mismatch");
  }
  const actual = computeObservationDigest(observation);
  if (actual !== observation.observation_digest) {
    throw new ConformanceError("observation_digest_mismatch");
  }
  validateSignature(observation.signature, actual, observation.body_id, keys);
}

function setPath(target, pathParts, value) {
  let cursor = target;
  for (const part of pathParts.slice(0, -1)) cursor = cursor[part];
  cursor[pathParts.at(-1)] = value;
}

function evaluateRejection(testCase, keys) {
  const fixture = structuredClone(vectors.adapters[0]);
  const manifest = fixture.manifest;
  let result = fixture.capture_result;
  let observation = fixture.observation;
  try {
    let target;
    if (testCase.target === "manifest") {
      target = manifest;
    } else if (testCase.target === "capture_result") {
      target = result;
    } else if (testCase.target === "observation") {
      target = observation;
    } else if (testCase.target === "noncaptured_emission") {
      const noObservation = structuredClone(
        vectors.no_observation_cases[testCase.no_observation_index]
      );
      result = noObservation.capture_result;
      observation = fixture.observation;
      target = result;
    } else {
      throw new ConformanceError("unknown_adapter_rejection_target");
    }
    for (const mutation of testCase.mutations) setPath(target, mutation.path, mutation.value);
    if (testCase.recompute_result_digest) result.result_digest = computeResultDigest(result);
    if (testCase.recompute_observation_digest) {
      observation.observation_digest = computeObservationDigest(observation);
    }
    if (testCase.resign) {
      signEnvelope(
        observation.signature,
        observation.observation_digest,
        vectors.domains.observation_signature,
        keys.privateKey
      );
    }
    validateManifest(manifest);
    validateResult(result, manifest);
    validateObservation(observation, result, keys);
  } catch (error) {
    if (error instanceof ConformanceError) return error.message;
    throw error;
  }
  return null;
}

function main() {
  const failures = [];
  const privateKey = privateKeyFromSeed(Buffer.from(vectors.test_signing_key.seed_hex, "hex"));
  const publicKey = crypto.createPublicKey(privateKey);
  const rawPublic = rawPublicKey(privateKey);
  const keys = { privateKey, publicKey };
  if (vectors.profile !== "genesis.sense.adapters.v0.1") {
    failures.push("sense_adapter_profile_invalid");
  }
  if (rawPublic.toString("hex") !== vectors.test_signing_key.public_key_hex) {
    failures.push("sense_adapter_test_public_key_mismatch");
  }
  const fingerprint =
    "sha256:" + crypto.createHash("sha256").update(rawPublic).digest("hex");
  if (fingerprint !== vectors.test_signing_key.public_key_fingerprint) {
    failures.push("sense_adapter_test_key_fingerprint_mismatch");
  }
  if (!vectors.test_signing_key.warning.includes("TEST ONLY")) {
    failures.push("sense_adapter_test_key_warning_missing");
  }
  try {
    validateCapabilities(vectors.required_capabilities, vectors.required_capabilities);
    for (const field of [
      "forbidden_adapter_identity_fields",
      "forbidden_adapter_memory_fields",
      "forbidden_capture_result_fields"
    ]) {
      const values = vectors[field];
      const sorted = [...values].sort(compareUtf8);
      if (values.some((value, index) => value !== sorted[index])) {
        throw new ConformanceError("unsorted_" + field);
      }
      if (new Set(values).size !== values.length) {
        throw new ConformanceError("duplicate_" + field);
      }
    }
  } catch (error) {
    failures.push(error.message);
  }

  const expectedSenses = ["vision", "proprioception", "interoception"];
  if (
    vectors.adapters.map((fixture) => fixture.manifest.sense).join("|")
    !== expectedSenses.join("|")
  ) {
    failures.push("sense_adapter_fixture_set_invalid");
  }
  for (const fixture of vectors.adapters) {
    try {
      validateManifest(fixture.manifest);
      if (fixture.manifest.verification_state !== "simulated") {
        throw new ConformanceError("reference_fixture_must_be_simulated");
      }
      validateResult(fixture.capture_result, fixture.manifest);
      validateObservation(fixture.observation, fixture.capture_result, keys);
    } catch (error) {
      failures.push(fixture.case_id + ":" + error.message);
    }
  }

  const byCaseId = new Map(vectors.adapters.map((fixture) => [fixture.case_id, fixture]));
  for (const fixture of vectors.no_observation_cases) {
    try {
      const manifest = byCaseId.get(fixture.adapter_ref).manifest;
      validateResult(fixture.capture_result, manifest);
      validateObservation(fixture.observation, fixture.capture_result, keys);
    } catch (error) {
      failures.push(fixture.case_id + ":" + error.message);
    }
  }

  for (const testCase of vectors.must_reject) {
    const actual = evaluateRejection(testCase, keys);
    if (actual !== testCase.expected_error) {
      failures.push(
        testCase.case_id + ":expected=" + testCase.expected_error + ":actual=" + actual
      );
    }
  }
  if (failures.length > 0) {
    for (const failure of failures) console.error("FAIL " + failure);
    process.exitCode = 1;
    return;
  }
  console.log("OK neutral sense adapter manifests (" + vectors.adapters.length + ")");
  console.log("OK captured result -> signed observation links (" + vectors.adapters.length + ")");
  console.log(
    "OK fail-closed no-observation cases (" + vectors.no_observation_cases.length + ")"
  );
  console.log("OK sense adapter boundary rejection cases (" + vectors.must_reject.length + ")");
  console.log("NOTE Reference adapters are simulated, not platform-verified sensors.");
}

main();

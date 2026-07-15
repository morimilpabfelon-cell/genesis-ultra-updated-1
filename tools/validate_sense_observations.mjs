import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/sense_observation_vectors.json"), "utf8")
);

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
const GATE_FIELDS = new Set([
  "schema_version", "hash_profile", "decision_id", "observation_id",
  "observation_digest", "instance_id", "body_id", "decision", "reason_code",
  "policy_profile", "decided_at", "memory_event_ref", "decision_digest", "signature"
]);
const GATE_DIGEST_FIELDS = [
  "schema_version", "hash_profile", "decision_id", "observation_id",
  "observation_digest", "instance_id", "body_id", "decision", "reason_code",
  "policy_profile", "decided_at", "memory_event_ref"
];
const MEMORY_DIGEST_FIELDS = [
  "schema_version", "event_id", "instance_id", "body_id", "sequence",
  "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
  "observed_at", "provenance_digest", "privacy"
];
const SENSES = new Set(["vision", "hearing", "touch", "proprioception", "interoception", "temporal"]);
const SOURCE_KINDS = new Set(["local_sensor", "user_input", "runtime_state", "network_evidence", "clock"]);
const DIRECT_MEMORY_FIELDS = new Set(["memory_event_ref", "memory_event", "event_hash", "write_memory"]);
const PLATFORM_FIELDS = new Set(["absolute_path", "platform_handle", "account_id", "credential", "token"]);

class ConformanceError extends Error {}

function frame(value) {
  if (typeof value !== "string") throw new ConformanceError("field_must_be_string");
  if (value !== value.normalize("NFC")) throw new ConformanceError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}

function hashFields(domain, fields, prefix = "sha256:") {
  const payload = Buffer.concat([frame(domain), ...fields.map((value) => frame(value))]);
  return `${prefix}${crypto.createHash("sha256").update(payload).digest("hex")}`;
}

function optionalText(value) {
  return value === null ? "" : String(value);
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

function computeObservationDigest(observation) {
  validateNfc(observation);
  if (!exactFields(observation, OBSERVATION_FIELDS)) {
    throw new ConformanceError("observation_fields_invalid");
  }
  const fields = OBSERVATION_DIGEST_FIELDS.map((field) => String(observation[field]));
  return hashFields(vectors.domains.observation, fields);
}

function computeGateDigest(decision) {
  validateNfc(decision);
  if (!exactFields(decision, GATE_FIELDS)) throw new ConformanceError("gate_fields_invalid");
  return hashFields(vectors.domains.gate_decision, GATE_DIGEST_FIELDS.map((field) => optionalText(decision[field])));
}

function computeMemoryEventHash(event) {
  validateNfc(event);
  return hashFields(
    "genesis.memory.event.v0.1",
    MEMORY_DIGEST_FIELDS.map((field) => String(event[field])),
    "evsha256:"
  );
}

function privateKeyFromSeed(seed) {
  if (seed.length !== 32) throw new ConformanceError("sense_test_seed_length_invalid");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

function rawPublicKey(privateKey) {
  const exported = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  if (!exported.subarray(0, prefix.length).equals(prefix)) {
    throw new ConformanceError("sense_test_public_key_encoding_invalid");
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
  envelope.signature_value = crypto.sign(null, signatureBytes(envelope), privateKey).toString("hex");
}

function validateSignature(envelope, { digest, domain, bodyId, publicKey, fingerprint, privateKey, prefix }) {
  if (envelope.signature_profile !== "genesis.signature.ed25519.v0.1") {
    throw new ConformanceError(`${prefix}_signature_profile_invalid`);
  }
  if (envelope.signer_type !== "body" || envelope.signer_id !== bodyId) {
    throw new ConformanceError(`${prefix}_signer_mismatch`);
  }
  if (envelope.signed_domain !== domain) {
    throw new ConformanceError(`${prefix}_signature_domain_mismatch`);
  }
  if (envelope.signed_digest !== digest) {
    throw new ConformanceError(`${prefix}_signature_digest_mismatch`);
  }
  if (envelope.public_key_ref !== fingerprint) {
    throw new ConformanceError(`${prefix}_signature_key_mismatch`);
  }
  let signature;
  try {
    signature = Buffer.from(envelope.signature_value, "hex");
  } catch {
    throw new ConformanceError(`${prefix}_signature_invalid`);
  }
  const message = signatureBytes(envelope);
  const expected = crypto.sign(null, message, privateKey);
  if (
    signature.length !== 64
    || !crypto.verify(null, message, publicKey, signature)
    || !signature.equals(expected)
  ) {
    throw new ConformanceError(`${prefix}_signature_invalid`);
  }
}

function validateObservation(observation, keys) {
  validateNfc(observation);
  const extras = Object.keys(observation).filter((field) => !OBSERVATION_FIELDS.has(field));
  if (extras.some((field) => DIRECT_MEMORY_FIELDS.has(field))) {
    throw new ConformanceError("observation_direct_memory_write_forbidden");
  }
  if (extras.some((field) => PLATFORM_FIELDS.has(field))) {
    throw new ConformanceError("observation_platform_binding");
  }
  if (!exactFields(observation, OBSERVATION_FIELDS)) {
    throw new ConformanceError("observation_fields_invalid");
  }
  if (observation.schema_version !== vectors.domains.observation) {
    throw new ConformanceError("observation_schema_version_invalid");
  }
  if (observation.hash_profile !== "genesis.hash.fields.v0.1") {
    throw new ConformanceError("observation_hash_profile_invalid");
  }
  if (!SENSES.has(observation.sense)) throw new ConformanceError("unsupported_sense_profile");
  if (!SOURCE_KINDS.has(observation.source_kind)) {
    throw new ConformanceError("unsupported_observation_source");
  }
  if (!Number.isSafeInteger(observation.observation_sequence) || observation.observation_sequence < 0) {
    throw new ConformanceError("observation_sequence_invalid");
  }
  const actual = computeObservationDigest(observation);
  if (actual !== observation.observation_digest) {
    throw new ConformanceError("observation_digest_mismatch");
  }
  validateSignature(observation.signature, {
    digest: actual,
    domain: vectors.domains.observation_signature,
    bodyId: observation.body_id,
    publicKey: keys.publicKey,
    fingerprint: vectors.test_signing_key.public_key_fingerprint,
    privateKey: keys.privateKey,
    prefix: "observation"
  });
}

function validateGate(decision, observation, keys) {
  validateNfc(decision);
  if (!exactFields(decision, GATE_FIELDS)) throw new ConformanceError("gate_fields_invalid");
  if (decision.observation_id !== observation.observation_id) {
    throw new ConformanceError("gate_observation_id_mismatch");
  }
  if (decision.instance_id !== observation.instance_id) {
    throw new ConformanceError("gate_instance_mismatch");
  }
  if (decision.body_id !== observation.body_id) throw new ConformanceError("gate_body_mismatch");
  if (decision.observation_digest !== observation.observation_digest) {
    throw new ConformanceError("gate_observation_digest_mismatch");
  }
  if (!["accepted", "rejected", "quarantined"].includes(decision.decision)) {
    throw new ConformanceError("gate_decision_invalid");
  }
  if (decision.decision === "accepted" && !decision.memory_event_ref) {
    throw new ConformanceError("gate_memory_event_ref_required");
  }
  if (decision.decision !== "accepted" && decision.memory_event_ref !== null) {
    throw new ConformanceError("gate_memory_event_ref_forbidden");
  }
  const actual = computeGateDigest(decision);
  if (actual !== decision.decision_digest) throw new ConformanceError("gate_decision_digest_mismatch");
  validateSignature(decision.signature, {
    digest: actual,
    domain: vectors.domains.gate_signature,
    bodyId: decision.body_id,
    publicKey: keys.publicKey,
    fingerprint: vectors.test_signing_key.public_key_fingerprint,
    privateKey: keys.privateKey,
    prefix: "gate"
  });
}

function validateMemoryLink(event, observation, decision) {
  if (event.event_id !== decision.memory_event_ref) {
    throw new ConformanceError("gate_memory_event_ref_mismatch");
  }
  if (event.instance_id !== observation.instance_id) throw new ConformanceError("memory_instance_mismatch");
  if (event.body_id !== observation.body_id) throw new ConformanceError("memory_body_mismatch");
  if (event.actor !== "body") throw new ConformanceError("memory_actor_invalid_for_observation");
  if (event.event_type !== `sense.${observation.sense}.observation`) {
    throw new ConformanceError("memory_event_type_mismatch");
  }
  if (event.content_digest !== observation.payload_digest) {
    throw new ConformanceError("memory_content_digest_mismatch");
  }
  if (event.content_type !== observation.payload_media_type) {
    throw new ConformanceError("memory_content_type_mismatch");
  }
  if (event.observed_at !== observation.captured_at) {
    throw new ConformanceError("memory_observed_at_mismatch");
  }
  if (event.provenance_digest !== observation.observation_digest) {
    throw new ConformanceError("memory_provenance_digest_mismatch");
  }
  if (event.privacy !== observation.privacy) throw new ConformanceError("memory_privacy_mismatch");
  if (computeMemoryEventHash(event) !== event.event_hash) {
    throw new ConformanceError("memory_event_hash_mismatch");
  }
}

function setPath(target, pathParts, value) {
  let cursor = target;
  for (const part of pathParts.slice(0, -1)) cursor = cursor[part];
  cursor[pathParts.at(-1)] = value;
}

function evaluateRejection(testCase, keys) {
  const observations = structuredClone(vectors.sense_observations);
  const decision = structuredClone(vectors.accepted_pipeline.gate_decision);
  const event = structuredClone(vectors.accepted_pipeline.memory_event);
  let observation = observations[0];
  try {
    let target;
    if (testCase.target === "observation") {
      target = observations[testCase.observation_index];
      observation = target;
    } else if (testCase.target === "gate") {
      target = decision;
    } else if (testCase.target === "memory_event") {
      target = event;
    } else {
      throw new ConformanceError("unknown_sense_rejection_target");
    }
    for (const mutation of testCase.mutations) setPath(target, mutation.path, mutation.value);
    if (testCase.recompute_digest) {
      if (testCase.target === "observation") {
        target.observation_digest = computeObservationDigest(target);
      } else {
        target.decision_digest = computeGateDigest(target);
      }
    }
    if (testCase.resign) {
      if (testCase.target === "observation") {
        signEnvelope(target.signature, target.observation_digest, vectors.domains.observation_signature, keys.privateKey);
      } else {
        signEnvelope(target.signature, target.decision_digest, vectors.domains.gate_signature, keys.privateKey);
      }
    }
    if (testCase.recompute_event_hash) event.event_hash = computeMemoryEventHash(event);
    validateObservation(observation, keys);
    validateGate(decision, observation, keys);
    validateMemoryLink(event, observation, decision);
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
  if (rawPublic.toString("hex") !== vectors.test_signing_key.public_key_hex) {
    failures.push("sense_test_public_key_mismatch");
  }
  if (!vectors.test_signing_key.warning.includes("TEST ONLY")) {
    failures.push("sense_test_key_warning_missing");
  }
  const fingerprint = `sha256:${crypto.createHash("sha256").update(rawPublic).digest("hex")}`;
  if (fingerprint !== vectors.test_signing_key.public_key_fingerprint) {
    failures.push("sense_test_key_fingerprint_mismatch");
  }
  const expected = ["vision", "hearing", "touch", "proprioception", "interoception", "temporal"];
  if (vectors.sense_observations.map((item) => item.sense).join("|") !== expected.join("|")) {
    failures.push("sense_fixture_set_invalid");
  }
  if (vectors.sense_observations.some((item, index) => item.observation_sequence !== index)) {
    failures.push("sense_fixture_sequence_invalid");
  }
  for (const observation of vectors.sense_observations) {
    try {
      validateObservation(observation, keys);
    } catch (error) {
      failures.push(`${observation.observation_id}:${error.message}`);
    }
  }
  const accepted = vectors.accepted_pipeline;
  const observation = vectors.sense_observations.find(
    (item) => item.observation_id === accepted.observation_ref
  );
  if (!observation) {
    failures.push("accepted_observation_ref_missing");
  } else {
    try {
      validateGate(accepted.gate_decision, observation, keys);
      validateMemoryLink(accepted.memory_event, observation, accepted.gate_decision);
    } catch (error) {
      failures.push(`accepted_pipeline:${error.message}`);
    }
  }
  for (const testCase of vectors.must_reject) {
    const actual = evaluateRejection(testCase, keys);
    if (actual !== testCase.expected_error) {
      failures.push(`${testCase.case_id}:expected=${testCase.expected_error}:actual=${actual}`);
    }
  }
  if (failures.length > 0) {
    for (const failure of failures) console.error(`FAIL ${failure}`);
    process.exitCode = 1;
    return;
  }
  console.log(`OK signed neutral sense observations (${vectors.sense_observations.length})`);
  console.log("OK observation -> signed gate -> append-only memory link");
  console.log(`OK sense boundary rejection cases (${vectors.must_reject.length})`);
  console.log("NOTE Fixtures do not certify real sensors, permissions, or observation truth.");
}

main();

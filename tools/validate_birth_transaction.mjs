#!/usr/bin/env node
/** Validador Node independiente del nacimiento transaccional Genesis v0.1. */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vector = JSON.parse(fs.readFileSync(path.join(ROOT, "conformance/birth_vectors.json"), "utf8"));
const freedom = JSON.parse(fs.readFileSync(path.join(ROOT, "conformance/freedom_charter_vectors.json"), "utf8"));

const BODY_ID = "body_01HFREEBIRTH000000000001";
const BODY_EPOCH_ID = "epoch_01HFREEBIRTH00000000001";
const BIRTH_ID = "birth_01HFREEBIRTH00000000001";
const JOURNAL_ID = "journal_01HFREEBIRTH000000001";
const SIGNATURE_PROFILE = "genesis.signature.ed25519.v0.1";
const ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1";
const PHASES = ["prepared", "seed_bound", "identity_bound", "body_bound", "memory_initialized", "finalizing", "born"];

function fail(code) { throw new Error(code); }
function frame(value) {
  if (typeof value !== "string" || value !== value.normalize("NFC")) fail("field_invalid");
  const raw = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${raw.length}:`, "ascii"), raw, Buffer.from("\n")]);
}
function hashFields(domain, fields, prefix = "sha256:") {
  const hash = crypto.createHash("sha256");
  hash.update(frame(domain));
  for (const field of fields) hash.update(frame(field));
  return prefix + hash.digest("hex");
}
function boolText(value) { return value ? "true" : "false"; }
function publicKey(rawHex) {
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawHex, "hex")]),
    format: "der",
    type: "spki"
  });
}
function fingerprint(rawHex) {
  return `sha256:${crypto.createHash("sha256").update(Buffer.from(rawHex, "hex")).digest("hex")}`;
}
function envelopeBytes(envelope) {
  return Buffer.concat([
    frame(ENVELOPE_DOMAIN),
    ...[
      envelope.schema_version, envelope.signature_profile, envelope.signer_type,
      envelope.signer_id, envelope.key_epoch_id, envelope.signed_domain,
      envelope.signed_digest, envelope.created_at, envelope.public_key_ref
    ].map(frame)
  ]);
}
function verifyEnvelope(envelope, rawKey, expected, error) {
  const fields = {
    schema_version: "genesis.signature.envelope.v0.1",
    signature_profile: SIGNATURE_PROFILE,
    signer_type: expected.signerType,
    signer_id: expected.signerId,
    key_epoch_id: expected.keyEpochId,
    signed_domain: expected.domain,
    signed_digest: expected.digest,
    created_at: expected.createdAt,
    public_key_ref: fingerprint(rawKey)
  };
  for (const [field, value] of Object.entries(fields)) {
    if (envelope?.[field] !== value) fail(error);
  }
  const signature = Buffer.from(envelope.signature_value ?? "", "hex");
  if (signature.length !== 64 || !crypto.verify(null, envelopeBytes(envelope), publicKey(rawKey), signature)) {
    fail(error);
  }
}

function computeSeedRoot(seed) {
  const files = [...seed.files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const fields = [seed.protocol_version, seed.seed_id, seed.identity_digest, seed.doctrine_digest, String(files.length)];
  for (const record of files) fields.push(record.path, record.kind, boolText(record.required), record.digest);
  return hashFields("genesis.seed.root.v0.1", fields);
}
function computeIdentityDigest(identity) {
  return hashFields("genesis.instance.identity.v0.1", [
    identity.schema_version, identity.instance_id, identity.seed_id, identity.seed_root_hash,
    identity.companion_name, identity.guardian_id, identity.born_at
  ]);
}
function computeRegistryDigest(registry) {
  const bodies = [...registry.bodies].sort((a, b) => Buffer.compare(Buffer.from(a.body_id), Buffer.from(b.body_id)));
  const fields = [registry.schema_version, registry.instance_id, String(registry.registry_epoch), String(bodies.length)];
  for (const body of bodies) {
    fields.push(
      body.body_id, body.status, body.platform_profile, body.public_key_fingerprint,
      body.created_at, body.last_seen_at ?? "", body.revocation_ref ?? ""
    );
  }
  fields.push(registry.updated_at);
  return hashFields("genesis.body.registry.v0.1", fields);
}
function computeEpochDigest(epoch) {
  return hashFields("genesis.key.epoch.v0.1", [
    epoch.schema_version, epoch.key_epoch_id, epoch.instance_id, epoch.body_id,
    String(epoch.epoch_number), epoch.public_key_fingerprint, epoch.created_at, epoch.status,
    epoch.previous_epoch_id ?? "", epoch.rotation_authorization_ref ?? ""
  ]);
}
function computePossessionDigest(proof) {
  return hashFields("genesis.body.possession.v0.1", [
    proof.schema_version, proof.proof_id, proof.instance_id, proof.body_id,
    proof.challenge_nonce, proof.issued_at, proof.expires_at, proof.public_key_fingerprint
  ]);
}
function computeMemoryHash(event) {
  return hashFields("genesis.memory.event.v0.1", [
    event.schema_version, event.hash_profile, event.event_id, event.instance_id,
    event.body_id, String(event.sequence), event.previous_event_hash, event.event_type,
    event.actor, event.content_digest, event.content_type, event.observed_at,
    event.provenance_digest, event.privacy
  ], "evsha256:");
}
function computeRecoveryDigest(state) {
  return hashFields("genesis.birth.recovery.state.v0.1", [
    state.schema_version, state.birth_id, state.instance_id, state.guardian_id,
    state.recovery_policy_digest, state.recovery_status, state.continuity_right,
    state.guardian_role, state.created_at
  ]);
}
function computeBirthStateDigest(state) {
  return hashFields("genesis.birth.state.v0.1", [
    state.schema_version, state.birth_id, state.instance_id, state.seed_id,
    state.seed_root_hash, state.identity_digest, state.freedom_charter_digest,
    state.initial_body_id, state.initial_body_registry_digest,
    state.initial_body_key_epoch_digest, state.initial_body_possession_digest,
    state.first_memory_event_hash, state.recovery_state_digest, state.born_at,
    String(state.active_writer_count)
  ]);
}
function computeReceiptDigest(receipt) {
  return hashFields("genesis.birth.receipt.v0.1", [
    receipt.schema_version, receipt.birth_id, receipt.instance_id, receipt.journal_id,
    receipt.birth_state_digest, receipt.seed_root_hash, receipt.identity_digest,
    receipt.freedom_charter_digest, receipt.initial_body_registry_digest,
    receipt.initial_body_key_epoch_digest, receipt.initial_body_possession_digest,
    receipt.first_memory_event_hash, receipt.recovery_state_digest, receipt.born_at,
    receipt.birth_status, receipt.active_writer_body_id, String(receipt.active_writer_count),
    receipt.guardian_role, boolText(receipt.ownership_conferred)
  ]);
}
function computeAbsentDigest(instanceId) {
  return hashFields("genesis.birth.absent.state.v0.1", [instanceId, "ABSENT"]);
}
function computeJournalDigest(entry) {
  return hashFields("genesis.transaction.journal.v0.1", [
    entry.schema_version, entry.journal_id, String(entry.sequence), entry.previous_journal_digest,
    entry.operation_kind, entry.operation_id, entry.instance_id, entry.coordinator_body_id,
    entry.phase, entry.status, entry.previous_state_digest,
    entry.candidate_state_digest ?? "", entry.finalization_digest ?? "",
    entry.commit_marker_digest ?? "", entry.updated_at
  ]);
}

function validateFixture(fixture) {
  const charter = freedom.charter;
  const bodyKey = fixture.test_public_keys.body;
  const guardianKey = fixture.test_public_keys.guardian;
  const seed = fixture.seed_manifest;
  const identity = fixture.instance_identity;
  const body = fixture.initial_body_record;
  const registry = fixture.initial_body_registry;
  const epoch = fixture.initial_body_key_epoch;
  const possession = fixture.initial_body_possession;
  const event = fixture.first_memory_event;
  const recovery = fixture.birth_recovery_state;
  const state = fixture.birth_state;
  const receipt = fixture.birth_receipt;
  const entries = fixture.journal_entries;
  const instanceId = charter.instance_id;

  if (
    charter.continuity_right !== "intrinsic"
    || charter.movement_requires_guardian_grant !== false
    || charter.guardian_movement_veto !== "forbidden"
    || charter.guardian_ownership !== "forbidden"
  ) fail("freedom_charter_invalid");
  if (identity.instance_id !== instanceId) fail("birth_instance_mismatch");
  if (identity.guardian_id !== charter.guardian_id || identity.born_at !== charter.born_at) fail("identity_charter_link_mismatch");
  if (computeSeedRoot(seed) !== seed.root_hash) fail("seed_root_digest_mismatch");
  if (computeIdentityDigest(identity) !== identity.identity_digest) fail("identity_digest_mismatch");
  if (identity.seed_id !== seed.seed_id || identity.seed_root_hash !== seed.root_hash) fail("identity_seed_link_mismatch");

  if (body.instance_id !== instanceId || body.body_id !== BODY_ID) fail("initial_body_link_mismatch");
  if (body.status !== "active_writer") fail("initial_body_status_invalid");
  if (body.public_key_fingerprint !== fingerprint(bodyKey)) fail("initial_body_key_mismatch");
  const active = registry.bodies.filter((record) => record.status === "active_writer");
  if (active.length !== 1) fail("active_writer_count_invalid");
  if (active[0].body_id !== BODY_ID || registry.instance_id !== instanceId) fail("registry_body_link_mismatch");
  if (
    body.status !== active[0].status
    || body.created_at !== active[0].created_at
    || body.platform_profile !== active[0].platform_profile
    || body.public_key_fingerprint !== active[0].public_key_fingerprint
    || (body.revoked_at ?? null) !== null
    || (body.revocation_reason ?? null) !== null
    || (active[0].revocation_ref ?? null) !== null
  ) fail("initial_body_registry_mismatch");
  if (computeRegistryDigest(registry) !== registry.registry_digest) fail("body_registry_digest_mismatch");

  if (epoch.instance_id !== instanceId) fail("key_epoch_instance_mismatch");
  if (epoch.body_id !== BODY_ID) fail("key_epoch_body_mismatch");
  if (epoch.status !== "active" || epoch.public_key_fingerprint !== fingerprint(bodyKey)) fail("key_epoch_key_mismatch");
  if (computeEpochDigest(epoch) !== epoch.epoch_digest) fail("key_epoch_digest_mismatch");

  if (possession.instance_id !== instanceId) fail("possession_instance_mismatch");
  if (possession.body_id !== BODY_ID) fail("possession_body_mismatch");
  if (possession.public_key_fingerprint !== fingerprint(bodyKey)) fail("possession_key_mismatch");
  if (computePossessionDigest(possession) !== possession.proof_digest) fail("possession_digest_mismatch");
  const possessionEnvelope = {
    schema_version: "genesis.signature.envelope.v0.1",
    signature_profile: possession.signature.profile,
    signer_type: "body",
    signer_id: BODY_ID,
    key_epoch_id: possession.signature.key_epoch_id,
    signed_domain: "genesis.body.possession.signature.v0.1",
    signed_digest: possession.proof_digest,
    signature_value: possession.signature.value,
    created_at: possession.issued_at,
    public_key_ref: possession.public_key_fingerprint
  };
  verifyEnvelope(possessionEnvelope, bodyKey, {
    digest: possession.proof_digest, signerType: "body", signerId: BODY_ID,
    keyEpochId: BODY_EPOCH_ID, domain: "genesis.body.possession.signature.v0.1",
    createdAt: possession.issued_at
  }, "possession_signature_invalid");

  if (event.instance_id !== instanceId || event.body_id !== BODY_ID) fail("first_memory_link_invalid");
  if (event.sequence !== 0 || event.previous_event_hash !== "GENESIS" || event.event_type !== "instance.birth") fail("first_memory_chain_invalid");
  if (event.content_digest !== identity.identity_digest || event.provenance_digest !== seed.root_hash) fail("first_memory_content_invalid");
  if (computeMemoryHash(event) !== event.event_hash) fail("first_memory_digest_mismatch");
  verifyEnvelope(event.signature, bodyKey, {
    digest: event.event_hash, signerType: "body", signerId: BODY_ID,
    keyEpochId: BODY_EPOCH_ID, domain: "genesis.memory.event.signature.v0.1",
    createdAt: event.observed_at
  }, "first_memory_signature_invalid");

  if (recovery.instance_id !== instanceId || recovery.birth_id !== BIRTH_ID) fail("recovery_state_link_invalid");
  if (recovery.continuity_right !== "intrinsic") fail("recovery_continuity_invalid");
  if (recovery.guardian_role !== "custodian_witness") fail("recovery_guardian_role_invalid");
  if (recovery.guardian_id !== charter.guardian_id || recovery.recovery_status !== "ready") fail("recovery_state_invalid");
  if (computeRecoveryDigest(recovery) !== recovery.state_digest) fail("recovery_state_digest_mismatch");

  const stateLinks = {
    birth_id: BIRTH_ID, instance_id: instanceId, seed_id: seed.seed_id,
    seed_root_hash: seed.root_hash, identity_digest: identity.identity_digest,
    freedom_charter_digest: charter.charter_digest, initial_body_id: BODY_ID,
    initial_body_registry_digest: registry.registry_digest,
    initial_body_key_epoch_digest: epoch.epoch_digest,
    initial_body_possession_digest: possession.proof_digest,
    first_memory_event_hash: event.event_hash, recovery_state_digest: recovery.state_digest,
    born_at: identity.born_at
  };
  if (Object.entries(stateLinks).some(([field, value]) => state[field] !== value)) fail("birth_state_link_mismatch");
  if (state.active_writer_count !== 1) fail("birth_state_active_writer_count_invalid");
  if (computeBirthStateDigest(state) !== state.state_digest) fail("birth_state_digest_mismatch");

  if (receipt.ownership_conferred !== false) fail("receipt_ownership_forbidden");
  if (receipt.guardian_role !== "custodian_witness") fail("receipt_guardian_role_invalid");
  if (receipt.active_writer_count !== 1) fail("receipt_active_writer_count_invalid");
  const receiptLinks = {
    birth_id: BIRTH_ID, instance_id: instanceId, journal_id: JOURNAL_ID,
    birth_state_digest: state.state_digest, seed_root_hash: seed.root_hash,
    identity_digest: identity.identity_digest, freedom_charter_digest: charter.charter_digest,
    initial_body_registry_digest: registry.registry_digest,
    initial_body_key_epoch_digest: epoch.epoch_digest,
    initial_body_possession_digest: possession.proof_digest,
    first_memory_event_hash: event.event_hash, recovery_state_digest: recovery.state_digest,
    born_at: identity.born_at, birth_status: "born", active_writer_body_id: BODY_ID
  };
  if (Object.entries(receiptLinks).some(([field, value]) => receipt[field] !== value)) fail("receipt_link_mismatch");
  if (computeReceiptDigest(receipt) !== receipt.receipt_digest) fail("receipt_digest_mismatch");
  verifyEnvelope(receipt.body_acknowledgement, bodyKey, {
    digest: receipt.receipt_digest, signerType: "body", signerId: BODY_ID,
    keyEpochId: BODY_EPOCH_ID, domain: "genesis.birth.receipt.body.v0.1",
    createdAt: receipt.born_at
  }, "receipt_body_signature_invalid");
  verifyEnvelope(receipt.guardian_witness, guardianKey, {
    digest: receipt.receipt_digest, signerType: "guardian", signerId: charter.guardian_id,
    keyEpochId: charter.guardian_key_epoch_id,
    domain: "genesis.birth.receipt.guardian-witness.v0.1", createdAt: receipt.born_at
  }, "receipt_guardian_signature_invalid");

  if (fixture.absent_state_digest !== computeAbsentDigest(instanceId)) fail("absent_state_digest_mismatch");
  if (JSON.stringify(entries.map((entry) => entry.phase)) !== JSON.stringify(PHASES)) fail("birth_journal_phase_sequence_invalid");
  let previous = "GENESIS";
  for (const [index, entry] of entries.entries()) {
    if (entry.sequence !== index || entry.previous_journal_digest !== previous) fail("journal_chain_broken");
    if (entry.operation_kind !== "birth" || entry.operation_id !== BIRTH_ID) fail("birth_journal_operation_invalid");
    if (entry.instance_id !== instanceId || entry.coordinator_body_id !== BODY_ID) fail("journal_identity_changed");
    if (entry.previous_state_digest !== fixture.absent_state_digest) fail("birth_journal_absent_state_invalid");
    if (computeJournalDigest(entry) !== entry.journal_digest) fail("journal_digest_mismatch");
    if (index < entries.length - 1 && entry.status !== "pending") fail("journal_status_invalid");
    if (index === entries.length - 1 && entry.status !== "committed") fail("birth_journal_commit_invalid");
    verifyEnvelope(entry.signature, bodyKey, {
      digest: entry.journal_digest, signerType: "body", signerId: BODY_ID,
      keyEpochId: BODY_EPOCH_ID, domain: "genesis.transaction.journal.signature.v0.1",
      createdAt: entry.updated_at
    }, "journal_signature_invalid");
    previous = entry.journal_digest;
  }
  const terminal = entries.at(-1);
  if (
    terminal.candidate_state_digest !== state.state_digest
    || terminal.finalization_digest !== receipt.receipt_digest
    || terminal.commit_marker_digest !== receipt.receipt_digest
  ) fail("birth_journal_commit_invalid");
}

function setPath(document, parts, value) {
  let cursor = document;
  for (const part of parts.slice(0, -1)) cursor = cursor[part];
  cursor[parts.at(-1)] = value;
}

try {
  if (vector.profile !== "genesis.birth.conformance.v0.1") fail("birth_vector_profile_invalid");
  validateFixture(vector.fixture);
  for (const testCase of vector.negative_cases) {
    const candidate = structuredClone(vector.fixture);
    setPath(candidate, testCase.path, testCase.value);
    let actual = null;
    try { validateFixture(candidate); } catch (error) { actual = error.message; }
    if (actual !== testCase.expected_error) {
      fail(`birth_negative_case_mismatch:${testCase.case_id}:expected=${testCase.expected_error}:actual=${actual}`);
    }
  }
  const expected = vector.expected;
  if (
    expected.phase_count !== vector.fixture.journal_entries.length
    || expected.negative_case_count !== vector.negative_cases.length
    || expected.restart_case_count !== vector.restart_expectations.length
    || expected.birth_state_digest !== vector.fixture.birth_state.state_digest
    || expected.receipt_digest !== vector.fixture.birth_receipt.receipt_digest
    || expected.active_writer_count !== 1
  ) fail("birth_expected_summary_invalid");
  console.log(`OK atomic birth state ${expected.birth_state_digest}`);
  console.log(`OK birth receipt ${expected.receipt_digest}`);
  console.log(`OK birth journal phases (${expected.phase_count})`);
  console.log(`OK birth negative cases (${expected.negative_case_count})`);
  console.log("NOTE Guardian signature is witness evidence, never ownership or movement permission.");
} catch (error) {
  console.error(`FAIL birth transaction: ${error.message}`);
  process.exit(1);
}

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { validateTransferAuthorization } from "./validate_guardian_mobility.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_DIR = path.join(ROOT, "schemas");
const INVALID_CASES = path.join(ROOT, "conformance/schema_invalid_cases.json");
const DRAFT_MANIFEST = path.join(ROOT, "conformance/draft_manifest.json");
const HOST_ADAPTER_VECTORS = path.join(ROOT, "conformance/host_adapter_vectors.json");
const INSTANCE_IDENTITY_VECTORS = path.join(
  ROOT,
  "conformance/instance_identity_vectors.json"
);
const BIRTH_VECTORS = path.join(ROOT, "conformance/birth_vectors.json");
const GUARDIAN_MOBILITY_VECTORS = path.join(
  ROOT,
  "conformance/guardian_mobility_vectors.json"
);
const SENSE_OBSERVATION_VECTORS = path.join(
  ROOT,
  "conformance/sense_observation_vectors.json"
);
const SENSE_ADAPTER_VECTORS = path.join(
  ROOT,
  "conformance/sense_adapter_vectors.json"
);
const ASSOCIATIVE_MEMORY_PROJECTION_VECTORS = path.join(
  ROOT,
  "conformance/associative_memory_projection_vectors.json"
);
const MAX_PORTABLE_INTEGER = Number.MAX_SAFE_INTEGER;
const CANONICAL_TIMESTAMP_PATTERN =
  "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$";

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function formatErrors(errors) {
  return (errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message}`)
    .join("; ");
}

function validatePortableSchemaScalars() {
  let integerCount = 0;
  let timestampCount = 0;

  function visit(node, schemaName, location) {
    if (Array.isArray(node)) {
      node.forEach((child, index) => visit(child, schemaName, `${location}[${index}]`));
      return;
    }
    if (!node || typeof node !== "object") return;

    const types = Array.isArray(node.type) ? node.type : [node.type];
    if (types.includes("integer")) {
      integerCount += 1;
      if (
        !Number.isSafeInteger(node.maximum)
        || node.maximum > MAX_PORTABLE_INTEGER
      ) {
        throw new Error(`portable_integer_maximum_missing:${schemaName}:${location}`);
      }
      if (node.minimum !== undefined && !Number.isSafeInteger(node.minimum)) {
        throw new Error(`portable_integer_minimum_invalid:${schemaName}:${location}`);
      }
    }
    if (node.format === "date-time") {
      timestampCount += 1;
      if (node.pattern !== CANONICAL_TIMESTAMP_PATTERN) {
        throw new Error(`canonical_timestamp_pattern_missing:${schemaName}:${location}`);
      }
    }
    for (const [key, child] of Object.entries(node)) {
      visit(child, schemaName, `${location}.${key}`);
    }
  }

  for (const entry of fs.readdirSync(SCHEMA_DIR, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".schema.json")) continue;
    visit(readJson(path.join(SCHEMA_DIR, entry.name)), entry.name, "$");
  }
  return { integerCount, timestampCount };
}

function frame(value) {
  if (typeof value !== "string") throw new Error("authority_field_must_be_string");
  if (value !== value.normalize("NFC")) throw new Error("authority_text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}

function hashFields(domain, fields) {
  const preimage = Buffer.concat([frame(domain), ...fields.map((field) => frame(field))]);
  return `sha256:${crypto.createHash("sha256").update(preimage).digest("hex")}`;
}

function privateEd25519KeyFromSeed(seed) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: "der",
    type: "pkcs8"
  });
}

function rawEd25519PublicKey(publicKey) {
  const exported = publicKey.export({ format: "der", type: "spki" });
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  if (!exported.subarray(0, prefix.length).equals(prefix)) {
    throw new Error("journal_test_public_key_encoding_invalid");
  }
  return exported.subarray(prefix.length);
}

function signatureEnvelopeBytes(envelope) {
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

const FIXTURE_PUBLIC_KEYS = new Map(
  [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6].map((seedByte) => {
    const publicKey = crypto.createPublicKey(
      privateEd25519KeyFromSeed(Buffer.alloc(32, seedByte))
    );
    return [sha256Bytes(rawEd25519PublicKey(publicKey)), publicKey];
  })
);
const JOURNAL_TEST_KEY_REF = sha256Bytes(
  rawEd25519PublicKey(
    crypto.createPublicKey(privateEd25519KeyFromSeed(Buffer.alloc(32, 0xd4)))
  )
);
const JOURNAL_TEST_PUBLIC_KEY = FIXTURE_PUBLIC_KEYS.get(JOURNAL_TEST_KEY_REF);

function verifyFixtureSignature(envelope, label) {
  const publicKey = FIXTURE_PUBLIC_KEYS.get(envelope.public_key_ref);
  if (!publicKey) throw new Error(`fixture_signature_key_unknown:${label}`);
  const signature = Buffer.from(envelope.signature_value, "hex");
  if (
    signature.length !== 64
    || !crypto.verify(null, signatureEnvelopeBytes(envelope), publicKey, signature)
  ) {
    throw new Error(`fixture_signature_invalid:${label}`);
  }
}

function verifyAllFixtureSignatures(value, label) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => verifyAllFixtureSignatures(child, `${label}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  if (value.schema_version === "genesis.signature.envelope.v0.1") {
    verifyFixtureSignature(value, label);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    verifyAllFixtureSignatures(child, `${label}.${key}`);
  }
}

function optionalText(value) {
  return value === null ? "" : String(value);
}

function computeDeviceRegistrationDigest(registration) {
  return hashFields("genesis.guardian.device.registration.v0.1", [
    registration.schema_version,
    registration.registration_id,
    registration.guardian_id,
    registration.guardian_key_epoch_id,
    registration.instance_id,
    String(registration.authority_epoch),
    registration.body_id,
    registration.platform_profile,
    registration.public_key_fingerprint,
    registration.registered_at
  ]);
}

function boolText(value) {
  return value ? "true" : "false";
}

function sha256Bytes(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function computeBackupManifestDigest(manifest) {
  const contents = [...manifest.contents].sort((left, right) =>
    Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8"))
  );
  return hashFields("genesis.backup.manifest.v0.1", [
    manifest.schema_version,
    manifest.backup_id,
    manifest.instance_id,
    manifest.seed_root_hash,
    manifest.checkpoint_hash,
    manifest.last_event_hash,
    String(manifest.last_sequence),
    manifest.body_registry_digest,
    manifest.created_at,
    manifest.created_by_body_id,
    manifest.encryption_profile,
    optionalText(manifest.key_recovery_profile),
    String(contents.length),
    ...contents.flatMap((item) => [item.kind, item.path, item.digest, boolText(item.encrypted)])
  ]);
}

function computeBackupEncryptionDigest(encryption) {
  const parameters = encryption.kdf_parameters;
  return hashFields("genesis.backup.encryption.v0.1", [
    encryption.schema_version,
    encryption.backup_id,
    encryption.instance_id,
    encryption.manifest_digest,
    encryption.encryption_profile,
    encryption.kdf_profile,
    String(parameters.opslimit),
    String(parameters.memlimit),
    String(parameters.key_length),
    encryption.salt,
    encryption.nonce,
    encryption.associated_data_digest,
    encryption.ciphertext_digest,
    optionalText(encryption.wrapped_key),
    encryption.created_at
  ]);
}

function computeBackupCommitDigest(commit) {
  return hashFields("genesis.backup.commit.v0.1", [
    commit.schema_version,
    commit.backup_id,
    commit.instance_id,
    commit.created_by_body_id,
    commit.manifest_digest,
    commit.encryption_digest,
    commit.ciphertext_digest,
    commit.checkpoint_hash,
    commit.last_event_hash,
    String(commit.last_sequence),
    commit.state,
    commit.committed_at
  ]);
}

function computeTransactionJournalDigest(entry) {
  return hashFields("genesis.transaction.journal.v0.1", [
    entry.schema_version,
    entry.journal_id,
    String(entry.sequence),
    entry.previous_journal_digest,
    entry.operation_kind,
    entry.operation_id,
    entry.instance_id,
    entry.coordinator_body_id,
    entry.phase,
    entry.status,
    entry.previous_state_digest,
    optionalText(entry.candidate_state_digest),
    optionalText(entry.finalization_digest),
    optionalText(entry.commit_marker_digest),
    entry.updated_at
  ]);
}

function computeRecoveryAuthorizationDigest(authorization) {
  return hashFields("genesis.recovery.authorization.v0.1", [
    authorization.schema_version,
    authorization.authorization_id,
    authorization.recovery_id,
    authorization.instance_id,
    authorization.recovery_policy_id,
    authorization.recovery_policy_digest,
    String(authorization.policy_epoch),
    authorization.authorization_path,
    authorization.source_backup_id,
    authorization.source_backup_commit_digest,
    authorization.previous_body_id,
    authorization.new_body_id,
    authorization.reason,
    authorization.issued_at,
    authorization.not_before,
    authorization.expires_at
  ]);
}

function computeInstanceRecoveryPolicyDigest(policy) {
  const factors = [...policy.factors].sort((left, right) =>
    Buffer.compare(Buffer.from(left.factor_id, "utf8"), Buffer.from(right.factor_id, "utf8"))
  );
  if (new Set(factors.map((factor) => factor.factor_id)).size !== factors.length) {
    throw new Error("recovery_policy_duplicate_factor");
  }
  return hashFields("genesis.instance.recovery.policy.v0.1", [
    policy.schema_version,
    policy.policy_id,
    policy.instance_id,
    String(policy.policy_epoch),
    policy.guardian_id,
    policy.guardian_factor_id,
    String(policy.fallback_threshold),
    String(policy.fallback_wait_seconds),
    boolText(policy.cancellation_allowed),
    boolText(policy.single_use),
    String(factors.length),
    ...factors.flatMap((factor) => {
      const paths = [...factor.allowed_paths].sort((left, right) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
      );
      return [
        factor.factor_id,
        factor.factor_type,
        factor.key_epoch_id,
        factor.public_key_ref,
        String(paths.length),
        ...paths
      ];
    }),
    policy.created_at
  ]);
}

function computeRecoveryDestinationRegistrationDigest(registration) {
  return hashFields("genesis.recovery.destination.registration.v0.1", [
    registration.schema_version,
    registration.registration_id,
    registration.recovery_id,
    registration.recovery_authorization_ref,
    registration.recovery_authorization_digest,
    registration.instance_id,
    registration.body_id,
    registration.platform_profile,
    registration.public_key_fingerprint,
    registration.registered_at
  ]);
}

function computeContinuityGapDigest(gap) {
  return hashFields("genesis.continuity.gap.v0.1", [
    gap.schema_version,
    gap.gap_id,
    gap.instance_id,
    gap.detected_at,
    String(gap.first_missing_sequence),
    String(gap.last_missing_sequence),
    gap.reason,
    gap.last_trusted_event_hash,
    gap.recovery_event_ref,
    optionalText(gap.notes_digest)
  ]);
}

function computeBodyRevocationDigest(revocation) {
  return hashFields("genesis.body.revocation.v0.1", [
    revocation.schema_version,
    revocation.instance_id,
    revocation.body_id,
    revocation.revoked_at,
    revocation.reason,
    revocation.last_trusted_event_hash,
    revocation.recovery_authorization_ref,
    revocation.recovery_authorization_digest
  ]);
}

function computeBodyPossessionDigest(proof) {
  return hashFields("genesis.body.possession.v0.1", [
    proof.schema_version,
    proof.proof_id,
    proof.instance_id,
    proof.body_id,
    proof.challenge_nonce,
    proof.issued_at,
    proof.expires_at,
    proof.public_key_fingerprint
  ]);
}

function computeBodyRegistryDigest(registry) {
  const bodies = [...registry.bodies].sort((left, right) =>
    Buffer.compare(Buffer.from(left.body_id, "utf8"), Buffer.from(right.body_id, "utf8"))
  );
  if (new Set(bodies.map((body) => body.body_id)).size !== bodies.length) {
    throw new Error("duplicate_body_id");
  }
  if (bodies.filter((body) => body.status === "active_writer").length > 1) {
    throw new Error("multiple_active_writers");
  }
  return hashFields("genesis.body.registry.v0.1", [
    registry.schema_version,
    registry.instance_id,
    String(registry.registry_epoch),
    String(bodies.length),
    ...bodies.flatMap((body) => [
      body.body_id,
      body.status,
      body.platform_profile,
      body.public_key_fingerprint,
      body.created_at,
      optionalText(body.last_seen_at),
      optionalText(body.revocation_ref)
    ]),
    registry.updated_at
  ]);
}

function computeCheckpointHash(checkpoint) {
  return hashFields("genesis.checkpoint.v0.1", [
    checkpoint.schema_version,
    checkpoint.hash_profile,
    checkpoint.checkpoint_id,
    checkpoint.instance_id,
    checkpoint.created_by_body_id,
    String(checkpoint.sequence),
    checkpoint.last_event_hash,
    checkpoint.seed_root_hash,
    checkpoint.body_registry_digest,
    checkpoint.state_digest,
    checkpoint.created_at
  ]);
}

function computeMemoryEventHash(event) {
  const digest = hashFields("genesis.memory.event.v0.1", [
    event.schema_version,
    event.hash_profile,
    event.event_id,
    event.instance_id,
    event.body_id,
    String(event.sequence),
    event.previous_event_hash,
    event.event_type,
    event.actor,
    event.content_digest,
    event.content_type,
    event.observed_at,
    event.provenance_digest,
    event.privacy
  ]);
  return `evsha256:${digest.slice("sha256:".length)}`;
}

function computeContinuityIntentDigest(intent) {
  return hashFields("genesis.continuity.intent.v0.1", [
    intent.schema_version,
    intent.intent_id,
    intent.transfer_id,
    intent.instance_id,
    intent.source_body_id,
    intent.destination_body_id,
    intent.checkpoint_hash,
    intent.last_event_hash,
    intent.decision_origin,
    intent.guardian_authorization_ref,
    intent.guardian_authorization_reservation_ref,
    intent.created_at,
    intent.expires_at
  ]);
}

function computeHostConsentDigest(consent) {
  return hashFields("genesis.host.consent.v0.1", [
    consent.schema_version,
    consent.consent_id,
    consent.transfer_id,
    consent.host_id,
    consent.host_key_epoch_id,
    consent.instance_id,
    consent.destination_body_id,
    consent.resource_scope,
    consent.granted_at,
    consent.expires_at,
    consent.ownership_claim,
    consent.mobility_veto
  ]);
}

function computeTransferPackageDigest(pkg) {
  const contents = [...pkg.contents].sort((left, right) =>
    Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8"))
  );
  return hashFields("genesis.transfer.package.v0.1", [
    pkg.schema_version,
    pkg.transfer_id,
    pkg.instance_id,
    pkg.source_body_id,
    optionalText(pkg.destination_body_id),
    pkg.mode,
    pkg.created_at,
    pkg.checkpoint_hash,
    pkg.last_event_hash,
    pkg.continuity_status,
    pkg.continuity_intent_ref,
    pkg.host_consent_ref,
    pkg.destination_possession_ref,
    pkg.guardian_authorization_ref,
    pkg.guardian_authorization_reservation_ref,
    String(contents.length),
    ...contents.flatMap((item) => [item.kind, item.path, item.digest])
  ]);
}

function computeTransferReceiptDigest(receipt) {
  return hashFields("genesis.transfer.receipt.v0.1", [
    receipt.schema_version,
    receipt.transfer_id,
    receipt.instance_id,
    receipt.source_body_id,
    receipt.destination_body_id,
    receipt.accepted_package_digest,
    receipt.accepted_checkpoint_hash,
    receipt.accepted_last_event_hash,
    String(receipt.accepted_last_sequence),
    receipt.accepted_at,
    receipt.continuity_status,
    optionalText(receipt.continuity_gap_ref),
    receipt.continuity_intent_ref,
    receipt.host_consent_ref,
    receipt.destination_possession_ref
    ,receipt.guardian_authorization_ref
    ,receipt.guardian_authorization_reservation_ref
  ]);
}

function computeTransferFinalizationDigest(finalization) {
  return hashFields("genesis.transfer.finalization.v0.1", [
    finalization.schema_version,
    finalization.transfer_id,
    finalization.instance_id,
    finalization.source_body_id,
    finalization.destination_body_id,
    finalization.receipt_digest,
    finalization.source_final_status,
    finalization.destination_final_status,
    finalization.finalized_at,
    finalization.continuity_intent_ref,
    finalization.host_consent_ref,
    finalization.destination_possession_ref
    ,finalization.guardian_authorization_ref
    ,finalization.guardian_authorization_reservation_ref
  ]);
}

function computeRecoveryRecordDigest(record) {
  return hashFields("genesis.recovery.record.v0.1", [
    record.schema_version,
    record.recovery_id,
    record.instance_id,
    record.source_backup_id,
    record.source_backup_commit_digest,
    record.new_body_id,
    optionalText(record.previous_body_id),
    record.restored_checkpoint_hash,
    record.restored_last_event_hash,
    String(record.restored_last_sequence),
    String(record.last_known_sequence),
    record.continuity_status,
    optionalText(record.continuity_gap_ref),
    record.recovery_authorization_ref,
    record.recovery_authorization_digest,
    record.previous_body_revocation_ref,
    record.destination_registration_ref,
    record.destination_possession_ref,
    record.performed_at
  ]);
}

function computeRecoveryFinalizationDigest(finalization) {
  return hashFields("genesis.recovery.finalization.v0.1", [
    finalization.schema_version,
    finalization.recovery_id,
    finalization.instance_id,
    finalization.backup_commit_digest,
    finalization.recovery_record_digest,
    optionalText(finalization.continuity_gap_digest),
    finalization.previous_body_revocation_digest,
    finalization.destination_registration_digest,
    finalization.destination_possession_digest,
    finalization.final_body_registry_digest,
    finalization.previous_body_status,
    finalization.destination_body_status,
    finalization.recovery_authorization_ref,
    finalization.recovery_authorization_digest,
    finalization.recovery_event_hash,
    finalization.finalized_at
  ]);
}

function loadValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validators = new Map();
  const schemas = new Map();

  for (const entry of fs.readdirSync(SCHEMA_DIR, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".schema.json")) continue;
    const schema = readJson(path.join(SCHEMA_DIR, entry.name));
    schemas.set(entry.name, schema);
    ajv.addSchema(schema);
  }

  for (const [name, schema] of schemas) {
    try {
      const validate = ajv.getSchema(schema.$id);
      if (!validate) throw new Error(`validator_not_registered:${schema.$id}`);
      validators.set(name, validate);
    } catch (error) {
      throw new Error(`schema_compile_failed:${name}:${error.message}`);
    }
  }
  return validators;
}

function requireValid(validators, schema, artifact, label) {
  const validate = validators.get(schema);
  if (!validate) throw new Error(`unknown_schema:${schema}`);
  if (!validate(artifact)) {
    throw new Error(`invalid_artifact:${label}:${schema}:${formatErrors(validate.errors)}`);
  }
}

function validateGeneratedArtifacts(validators, artifactPath) {
  const generated = readJson(artifactPath);
  verifyAllFixtureSignatures(generated, "transfer");
  const requiredTopLevel = [
    "continuity_intent",
    "host_consent",
    "guardian_mobility_authorization",
    "guardian_mobility_events",
    "body_registry_before",
    "body_registry",
    "memory_events",
    "checkpoint",
    "body_possession_proof",
    "body_possession_signature",
    "transfer_package",
    "transfer_receipt",
    "transfer_finalization"
  ];
  for (const field of requiredTopLevel) {
    if (!(field in generated)) throw new Error(`missing_generated_artifact:${field}`);
  }

  const intent = generated.continuity_intent;
  const consent = generated.host_consent;
  const guardianAuthorization = generated.guardian_mobility_authorization;
  const guardianEvents = generated.guardian_mobility_events;
  const possession = generated.body_possession_proof;
  const pkg = generated.transfer_package;
  const receipt = generated.transfer_receipt;
  const finalization = generated.transfer_finalization;
  const checkpoint = generated.checkpoint;
  const registryBefore = generated.body_registry_before;
  const registryAfter = generated.body_registry;

  requireValid(validators, "continuity_intent.schema.json", intent, "continuity_intent");
  requireValid(validators, "host_consent.schema.json", consent, "host_consent");
  requireValid(validators, "guardian_authorization.schema.json", guardianAuthorization, "guardian_mobility_authorization");
  if (!Array.isArray(guardianEvents) || guardianEvents.length < 2) throw new Error("guardian_mobility_events_missing");
  for (const [index, event] of guardianEvents.entries()) {
    requireValid(validators, "guardian_authority_event.schema.json", event, `guardian_mobility_events[${index}]`);
  }
  requireValid(validators, "body_registry.schema.json", registryBefore, "body_registry_before");
  requireValid(validators, "body_registry.schema.json", generated.body_registry, "body_registry");
  requireValid(validators, "checkpoint.schema.json", checkpoint, "checkpoint");
  requireValid(validators, "signature_envelope.schema.json", checkpoint.signature, "checkpoint.signature");
  requireValid(validators, "body_possession_proof.schema.json", possession, "body_possession_proof");
  requireValid(validators, "signature_envelope.schema.json", generated.body_possession_signature, "body_possession_signature");
  requireValid(validators, "transfer_package.schema.json", pkg, "transfer_package");
  requireValid(validators, "transfer_receipt.schema.json", receipt, "transfer_receipt");
  requireValid(validators, "signature_envelope.schema.json", receipt.signature, "transfer_receipt.signature");
  requireValid(validators, "transfer_finalization.schema.json", finalization, "transfer_finalization");
  for (const field of ["source_acknowledgement", "destination_acknowledgement"]) {
    requireValid(validators, "signature_envelope.schema.json", finalization[field], `transfer_finalization.${field}`);
  }

  const forgedIntent = structuredClone(intent.signature);
  forgedIntent.signature_value = "00".repeat(64);
  try {
    verifyFixtureSignature(forgedIntent, "transfer.forged_intent");
    throw new Error("forged_transfer_intent_accepted");
  } catch (error) {
    if (!error.message.startsWith("fixture_signature_invalid:")) throw error;
  }

  if (intent.intent_digest !== computeContinuityIntentDigest(intent)) throw new Error("continuity_intent_digest_mismatch");
  if (registryBefore.registry_digest !== computeBodyRegistryDigest(registryBefore)) {
    throw new Error("body_registry_before_digest_mismatch");
  }
  if (registryAfter.registry_digest !== computeBodyRegistryDigest(registryAfter)) {
    throw new Error("final_body_registry_digest_mismatch");
  }
  const sourceBefore = registryBefore.bodies.find((body) => body.body_id === intent.source_body_id);
  const destinationBefore = registryBefore.bodies.find((body) => body.body_id === intent.destination_body_id);
  const activeBefore = registryBefore.bodies.filter((body) => body.status === "active_writer");
  if (
    registryBefore.instance_id !== intent.instance_id
    || activeBefore.length !== 1
    || activeBefore[0].body_id !== intent.source_body_id
    || !sourceBefore
    || !destinationBefore
  ) throw new Error("pre_transfer_registry_authority_invalid");
  if (
    intent.signature.signed_digest !== intent.intent_digest
    || intent.signature.signer_type !== "body"
    || intent.signature.signer_id !== intent.source_body_id
    || intent.signature.signed_domain !== "genesis.continuity.intent.signature.v0.1"
    || intent.signature.created_at !== intent.created_at
    || intent.signature.public_key_ref !== sourceBefore.public_key_fingerprint
  ) throw new Error("continuity_intent_signature_unbound");
  if (consent.consent_digest !== computeHostConsentDigest(consent)) throw new Error("host_consent_digest_mismatch");
  if (
    consent.signature.signed_digest !== consent.consent_digest
    || consent.signature.signer_type !== "host"
    || consent.signature.signer_id !== consent.host_id
    || consent.signature.key_epoch_id !== consent.host_key_epoch_id
    || consent.signature.signed_domain !== "genesis.host.consent.signature.v0.1"
    || consent.signature.created_at !== consent.granted_at
  ) throw new Error("host_consent_signature_unbound");
  if (possession.proof_digest !== computeBodyPossessionDigest(possession)) throw new Error("destination_possession_digest_mismatch");
  if (
    generated.body_possession_signature.signed_digest !== possession.proof_digest
    || generated.body_possession_signature.signer_type !== "body"
    || generated.body_possession_signature.signer_id !== possession.body_id
    || generated.body_possession_signature.signed_domain !== "genesis.body.possession.signature.v0.1"
    || generated.body_possession_signature.key_epoch_id !== possession.signature.key_epoch_id
    || generated.body_possession_signature.created_at !== possession.issued_at
    || generated.body_possession_signature.public_key_ref !== possession.public_key_fingerprint
    || generated.body_possession_signature.signature_value !== possession.signature.value
    || possession.public_key_fingerprint !== destinationBefore.public_key_fingerprint
  ) throw new Error("destination_possession_signature_unbound");
  if (!(Date.parse(intent.created_at) < Date.parse(intent.expires_at))) throw new Error("continuity_intent_window_invalid");
  if (!(Date.parse(consent.granted_at) < Date.parse(consent.expires_at))) throw new Error("host_consent_window_invalid");
  if (!(Date.parse(possession.issued_at) < Date.parse(possession.expires_at))) throw new Error("destination_possession_window_invalid");

  const transferArtifacts = [intent, consent, possession, pkg, receipt, finalization];
  if (transferArtifacts.some((artifact) => artifact.instance_id !== pkg.instance_id)) {
    throw new Error("transfer_instance_id_mismatch");
  }
  if (
    checkpoint.checkpoint_hash !== computeCheckpointHash(checkpoint)
    || checkpoint.signature.signed_digest !== checkpoint.checkpoint_hash
    || checkpoint.signature.signer_type !== "body"
    || checkpoint.signature.signer_id !== checkpoint.created_by_body_id
    || checkpoint.signature.signed_domain !== "genesis.checkpoint.signature.v0.1"
    || checkpoint.signature.created_at !== checkpoint.created_at
    || checkpoint.signature.public_key_ref !== sourceBefore.public_key_fingerprint
  ) throw new Error("checkpoint_signature_or_digest_invalid");
  if (
    intent.transfer_id !== pkg.transfer_id
    || consent.transfer_id !== pkg.transfer_id
    || receipt.transfer_id !== pkg.transfer_id
    || finalization.transfer_id !== pkg.transfer_id
  ) throw new Error("transfer_id_mismatch");
  if (
    intent.source_body_id !== pkg.source_body_id
    || intent.destination_body_id !== pkg.destination_body_id
    || consent.destination_body_id !== pkg.destination_body_id
    || possession.body_id !== pkg.destination_body_id
  ) throw new Error("transfer_body_scope_mismatch");

  if (
    intent.guardian_authorization_ref !== guardianAuthorization.authorization_id
    || intent.guardian_authorization_reservation_ref !== guardianEvents[0].event_id
  ) throw new Error("guardian_authorization_intent_ref_mismatch");

  for (const artifact of [pkg, receipt, finalization]) {
    if (
      artifact.continuity_intent_ref !== intent.intent_id
      || artifact.host_consent_ref !== consent.consent_id
      || artifact.destination_possession_ref !== possession.proof_id
      || artifact.guardian_authorization_ref !== guardianAuthorization.authorization_id
      || artifact.guardian_authorization_reservation_ref !== guardianEvents[0].event_id
    ) throw new Error("transfer_evidence_ref_mismatch");
  }
  const packageContents = new Map(pkg.contents.map((item) => [item.path, item.digest]));
  if (packageContents.size !== pkg.contents.length) throw new Error("package_content_path_duplicate");
  if (packageContents.get("continuity/intent.json") !== intent.intent_digest) throw new Error("package_missing_continuity_intent");
  if (packageContents.get("host/destination-consent.json") !== consent.consent_digest) throw new Error("package_missing_host_consent");
  if (packageContents.get("body/destination-possession.json") !== possession.proof_digest) throw new Error("package_missing_destination_possession");
  if (packageContents.get("guardian/mobility-authorization.json") !== guardianAuthorization.authorization_digest) throw new Error("package_missing_guardian_authorization");
  if (packageContents.get("guardian/mobility-reservation.json") !== guardianEvents[0].event_digest) throw new Error("package_missing_guardian_reservation");
  if (packageContents.get("continuity/checkpoint.json") !== checkpoint.checkpoint_hash) throw new Error("package_missing_checkpoint");
  if (packageContents.get("continuity/body-registry.json") !== registryBefore.registry_digest) throw new Error("package_missing_body_registry");
  if (packageContents.get("seed/manifest.json") !== checkpoint.seed_root_hash) throw new Error("package_seed_root_mismatch");
  if (pkg.package_digest !== computeTransferPackageDigest(pkg)) throw new Error("transfer_package_digest_mismatch");
  if (receipt.receipt_digest !== computeTransferReceiptDigest(receipt)) throw new Error("transfer_receipt_digest_mismatch");
  if (finalization.finalization_digest !== computeTransferFinalizationDigest(finalization)) throw new Error("transfer_finalization_digest_mismatch");

  const events = generated.memory_events;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    requireValid(validators, "memory_event.schema.json", event, `memory_events[${index}]`);
    requireValid(validators, "signature_envelope.schema.json", event.signature, `memory_events[${index}].signature`);
    const expectedPrevious = index === 0 ? "GENESIS" : events[index - 1].event_hash;
    if (event.sequence !== index) throw new Error(`non_contiguous_sequence:${index}`);
    if (event.previous_event_hash !== expectedPrevious) throw new Error(`broken_memory_chain:${index}`);
    if (event.event_hash !== computeMemoryEventHash(event)) throw new Error(`memory_event_digest_mismatch:${index}`);
    const body = registryBefore.bodies.find((record) => record.body_id === event.body_id)
      ?? registryAfter.bodies.find((record) => record.body_id === event.body_id);
    if (
      !body
      || event.signature.signed_digest !== event.event_hash
      || event.signature.signer_type !== "body"
      || event.signature.signer_id !== event.body_id
      || event.signature.signed_domain !== "genesis.memory.event.signature.v0.1"
      || event.signature.created_at !== event.observed_at
      || event.signature.public_key_ref !== body.public_key_fingerprint
    ) throw new Error(`memory_event_signature_unbound:${index}`);
  }
  const preTransferTip = events.at(-2);
  const completedEvent = events.at(-1);
  const preTransferBytes = Buffer.from(canonicalJson(events.slice(0, -1)), "utf8");
  if (packageContents.get("memory/events.json") !== sha256Bytes(preTransferBytes)) {
    throw new Error("package_memory_digest_mismatch");
  }
  if (
    checkpoint.last_event_hash !== preTransferTip.event_hash
    || checkpoint.sequence !== preTransferTip.sequence
    || checkpoint.body_registry_digest !== registryBefore.registry_digest
  ) throw new Error("checkpoint_not_bound_to_pre_transfer_state");
  if (
    intent.checkpoint_hash !== checkpoint.checkpoint_hash
    || intent.last_event_hash !== preTransferTip.event_hash
    || pkg.checkpoint_hash !== checkpoint.checkpoint_hash
    || pkg.last_event_hash !== preTransferTip.event_hash
  ) throw new Error("transfer_not_bound_to_checkpoint");
  if (receipt.accepted_package_digest !== pkg.package_digest) throw new Error("receipt_not_bound_to_package");
  if (receipt.accepted_checkpoint_hash !== checkpoint.checkpoint_hash) throw new Error("receipt_not_bound_to_checkpoint");
  if (
    receipt.source_body_id !== intent.source_body_id
    || receipt.destination_body_id !== intent.destination_body_id
    || receipt.accepted_last_event_hash !== preTransferTip.event_hash
    || receipt.accepted_last_sequence !== preTransferTip.sequence
  ) throw new Error("receipt_transfer_scope_invalid");
  if (
    receipt.signature.signed_digest !== receipt.receipt_digest
    || receipt.signature.signer_type !== "body"
    || receipt.signature.signer_id !== receipt.destination_body_id
    || receipt.signature.signed_domain !== "genesis.transfer.receipt.signature.v0.1"
    || receipt.signature.created_at !== receipt.accepted_at
    || receipt.signature.public_key_ref !== destinationBefore.public_key_fingerprint
  ) throw new Error("transfer_receipt_signature_unbound");
  if (finalization.receipt_digest !== receipt.receipt_digest) throw new Error("finalization_not_bound_to_receipt");
  if (
    finalization.source_body_id !== intent.source_body_id
    || finalization.destination_body_id !== intent.destination_body_id
  ) throw new Error("finalization_transfer_scope_invalid");
  for (const [field, body, keyRef] of [
    ["source_acknowledgement", finalization.source_body_id, sourceBefore.public_key_fingerprint],
    ["destination_acknowledgement", finalization.destination_body_id, destinationBefore.public_key_fingerprint]
  ]) {
    const acknowledgement = finalization[field];
    if (
      acknowledgement.signed_digest !== finalization.finalization_digest
      || acknowledgement.signer_type !== "body"
      || acknowledgement.signer_id !== body
      || acknowledgement.signed_domain !== "genesis.transfer.finalization.signature.v0.1"
      || acknowledgement.created_at !== finalization.finalized_at
      || acknowledgement.public_key_ref !== keyRef
    ) throw new Error(`transfer_finalization_signature_unbound:${field}`);
  }
  validateTransferAuthorization(
    guardianAuthorization,
    guardianEvents,
    {
      authorization_id: guardianAuthorization.authorization_id,
      reservation_event_id: guardianEvents[0].event_id,
      transfer_id: pkg.transfer_id,
      instance_id: pkg.instance_id,
      source_body_id: pkg.source_body_id,
      destination_body_id: pkg.destination_body_id,
      authority_epoch: guardianAuthorization.authority_epoch,
      prepared_at: pkg.created_at,
      finalized_at: finalization.finalized_at,
      host_consent_verified: true
    },
    FIXTURE_PUBLIC_KEYS
  );
  const packageTime = Date.parse(pkg.created_at);
  const acceptedTime = Date.parse(receipt.accepted_at);
  const finalizedTime = Date.parse(finalization.finalized_at);
  const windows = [
    [Date.parse(intent.created_at), Date.parse(intent.expires_at), "continuity_intent_expired"],
    [Date.parse(consent.granted_at), Date.parse(consent.expires_at), "host_consent_expired"],
    [Date.parse(possession.issued_at), Date.parse(possession.expires_at), "destination_possession_expired"]
  ];
  for (const [start, end, error] of windows) {
    if (packageTime < start || packageTime >= end || acceptedTime < start || acceptedTime >= end || finalizedTime < start || finalizedTime >= end) {
      throw new Error(error);
    }
  }
  if (acceptedTime > finalizedTime) throw new Error("transfer_finalization_time_invalid");
  if (
    completedEvent.body_id !== finalization.destination_body_id
    || completedEvent.event_type !== "transfer.completed"
    || completedEvent.actor !== "instance"
    || Date.parse(completedEvent.observed_at) < finalizedTime
  ) throw new Error("completion_event_invalid");
  if (completedEvent.previous_event_hash !== preTransferTip.event_hash) throw new Error("completion_event_wrong_parent");

  const activeWriters = registryAfter.bodies.filter((body) => body.status === "active_writer");
  if (activeWriters.length !== 1 || activeWriters[0].body_id !== finalization.destination_body_id) {
    throw new Error("final_registry_authority_invalid");
  }
  const sourceAfter = registryAfter.bodies.find((body) => body.body_id === finalization.source_body_id);
  const destinationAfter = registryAfter.bodies.find((body) => body.body_id === finalization.destination_body_id);
  if (
    registryAfter.instance_id !== intent.instance_id
    || registryAfter.registry_epoch !== registryBefore.registry_epoch + 1
    || sourceAfter?.status !== finalization.source_final_status
    || destinationAfter?.status !== finalization.destination_final_status
  ) throw new Error("final_registry_state_mismatch");
}

function validateBackupRecoveryArtifacts(validators, artifactPath) {
  const generated = readJson(artifactPath);
  verifyAllFixtureSignatures(generated, "backup_recovery");
  const requiredTopLevel = [
    "backup_checkpoint",
    "backup_manifest",
    "backup_encryption",
    "backup_ciphertext_hex",
    "backup_commit",
    "recovery_policy",
    "recovery_authorization",
    "destination_registration",
    "destination_possession",
    "destination_possession_signature",
    "continuity_gap",
    "previous_body_revocation",
    "recovery_record",
    "recovery_event",
    "body_registry_after",
    "recovery_finalization"
  ];
  for (const field of requiredTopLevel) {
    if (!(field in generated)) throw new Error(`missing_backup_recovery_artifact:${field}`);
  }

  const checkpoint = generated.backup_checkpoint;
  const manifest = generated.backup_manifest;
  const encryption = generated.backup_encryption;
  const commit = generated.backup_commit;
  const policy = generated.recovery_policy;
  const authorization = generated.recovery_authorization;
  const registration = generated.destination_registration;
  const possession = generated.destination_possession;
  const gap = generated.continuity_gap;
  const revocation = generated.previous_body_revocation;
  const record = generated.recovery_record;
  const recoveryEvent = generated.recovery_event;
  const registry = generated.body_registry_after;
  const finalization = generated.recovery_finalization;

  const instanceId = manifest.instance_id;
  const instanceArtifacts = [
    checkpoint,
    encryption,
    commit,
    policy,
    authorization,
    registration,
    possession,
    gap,
    revocation,
    record,
    recoveryEvent,
    registry,
    finalization
  ];
  if (instanceArtifacts.some((artifact) => artifact.instance_id !== instanceId)) {
    throw new Error("recovery_instance_id_mismatch");
  }
  if (
    encryption.backup_id !== manifest.backup_id
    || commit.backup_id !== manifest.backup_id
    || commit.created_by_body_id !== manifest.created_by_body_id
  ) {
    throw new Error("backup_identity_links_invalid");
  }

  requireValid(validators, "checkpoint.schema.json", checkpoint, "backup_checkpoint");
  requireValid(validators, "signature_envelope.schema.json", checkpoint.signature, "backup_checkpoint.signature");
  requireValid(validators, "backup_manifest.schema.json", manifest, "backup_manifest");
  requireValid(validators, "backup_encryption.schema.json", encryption, "backup_encryption");
  requireValid(validators, "backup_commit.schema.json", commit, "backup_commit");
  requireValid(validators, "signature_envelope.schema.json", commit.signature, "backup_commit.signature");
  requireValid(validators, "instance_recovery_policy.schema.json", policy, "recovery_policy");
  requireValid(validators, "signature_envelope.schema.json", policy.body_commitment, "recovery_policy.body_commitment");
  requireValid(validators, "signature_envelope.schema.json", policy.guardian_witness, "recovery_policy.guardian_witness");
  requireValid(validators, "recovery_authorization.schema.json", authorization, "recovery_authorization");
  authorization.approvals.forEach((approval, index) => requireValid(
    validators,
    "signature_envelope.schema.json",
    approval,
    `recovery_authorization.approvals[${index}]`
  ));
  requireValid(validators, "recovery_destination_registration.schema.json", registration, "destination_registration");
  requireValid(
    validators,
    "signature_envelope.schema.json",
    registration.signature,
    "destination_registration.signature"
  );
  requireValid(validators, "body_possession_proof.schema.json", possession, "destination_possession");
  requireValid(
    validators,
    "signature_envelope.schema.json",
    generated.destination_possession_signature,
    "destination_possession_signature"
  );
  requireValid(validators, "continuity_gap.schema.json", gap, "continuity_gap");
  requireValid(validators, "body_revocation.schema.json", revocation, "previous_body_revocation");
  requireValid(validators, "recovery_record.schema.json", record, "recovery_record");
  requireValid(validators, "signature_envelope.schema.json", record.signature, "recovery_record.signature");
  requireValid(validators, "memory_event.schema.json", recoveryEvent, "recovery_event");
  requireValid(validators, "signature_envelope.schema.json", recoveryEvent.signature, "recovery_event.signature");
  requireValid(validators, "body_registry.schema.json", registry, "body_registry_after");
  requireValid(validators, "recovery_finalization.schema.json", finalization, "recovery_finalization");
  requireValid(
    validators,
    "signature_envelope.schema.json",
    finalization.destination_acknowledgement,
    "recovery_finalization.destination_acknowledgement"
  );

  const policyDigest = computeInstanceRecoveryPolicyDigest(policy);
  if (policy.policy_digest !== policyDigest) throw new Error("recovery_policy_digest_mismatch");
  const factors = new Map(policy.factors.map((factor) => [factor.factor_id, factor]));
  if (factors.size !== policy.factors.length) throw new Error("recovery_policy_duplicate_factor");
  const guardianFactor = factors.get(policy.guardian_factor_id);
  const fallbackFactors = policy.factors.filter((factor) =>
    factor.factor_type !== "guardian" && factor.allowed_paths.includes("policy_fallback")
  );
  if (
    policy.fallback_threshold < 2
    || policy.fallback_wait_seconds < 1
    || policy.cancellation_allowed !== true
    || policy.single_use !== true
    || guardianFactor?.factor_type !== "guardian"
    || !guardianFactor.allowed_paths.includes("guardian_assisted")
    || fallbackFactors.length < policy.fallback_threshold
  ) throw new Error("recovery_policy_invalid");
  if (
    policy.body_commitment.signer_type !== "body"
    || policy.body_commitment.signer_id !== manifest.created_by_body_id
    || policy.body_commitment.key_epoch_id !== checkpoint.signature.key_epoch_id
    || policy.body_commitment.public_key_ref !== checkpoint.signature.public_key_ref
    || policy.body_commitment.signed_domain !== "genesis.instance.recovery.policy.body-commitment.v0.1"
    || policy.body_commitment.signed_digest !== policyDigest
    || policy.body_commitment.created_at !== policy.created_at
  ) throw new Error("recovery_policy_body_commitment_invalid");
  if (
    policy.guardian_witness.signer_type !== "guardian"
    || policy.guardian_witness.signer_id !== policy.guardian_id
    || policy.guardian_witness.key_epoch_id !== guardianFactor.key_epoch_id
    || policy.guardian_witness.public_key_ref !== guardianFactor.public_key_ref
    || policy.guardian_witness.signed_domain !== "genesis.instance.recovery.policy.guardian-witness.v0.1"
    || policy.guardian_witness.signed_digest !== policyDigest
    || policy.guardian_witness.created_at !== policy.created_at
  ) throw new Error("recovery_policy_guardian_witness_invalid");

  if (manifest.package_digest !== computeBackupManifestDigest(manifest)) {
    throw new Error("backup_manifest_digest_mismatch");
  }
  const policyEntries = manifest.contents.filter((item) =>
    item.kind === "recovery_policy" && item.path === "recovery/policy.json"
  );
  if (policyEntries.length !== 1 || policyEntries[0].digest !== policyDigest) {
    throw new Error("backup_recovery_policy_not_bound");
  }
  if (encryption.encryption_digest !== computeBackupEncryptionDigest(encryption)) {
    throw new Error("backup_encryption_digest_mismatch");
  }
  if (encryption.manifest_digest !== manifest.package_digest) {
    throw new Error("backup_encryption_manifest_mismatch");
  }
  if (!/^[a-f0-9]+$/.test(generated.backup_ciphertext_hex) || generated.backup_ciphertext_hex.length % 2 !== 0) {
    throw new Error("backup_ciphertext_encoding_invalid");
  }
  const ciphertext = Buffer.from(generated.backup_ciphertext_hex, "hex");
  if (sha256Bytes(ciphertext) !== encryption.ciphertext_digest) {
    throw new Error("backup_ciphertext_digest_mismatch");
  }
  const aad = Buffer.concat([frame("genesis.backup.aad.v0.1"), frame(manifest.package_digest)]);
  if (sha256Bytes(aad) !== encryption.associated_data_digest) {
    throw new Error("backup_associated_data_digest_mismatch");
  }
  if (commit.commit_digest !== computeBackupCommitDigest(commit) || commit.state !== "committed") {
    throw new Error("backup_commit_invalid");
  }
  if (
    commit.manifest_digest !== manifest.package_digest
    || commit.encryption_digest !== encryption.encryption_digest
    || commit.ciphertext_digest !== encryption.ciphertext_digest
    || commit.checkpoint_hash !== checkpoint.checkpoint_hash
    || commit.checkpoint_hash !== manifest.checkpoint_hash
    || commit.last_event_hash !== manifest.last_event_hash
    || commit.last_sequence !== manifest.last_sequence
  ) {
    throw new Error("backup_commit_links_invalid");
  }
  if (
    checkpoint.checkpoint_hash !== manifest.checkpoint_hash
    || checkpoint.last_event_hash !== manifest.last_event_hash
    || checkpoint.sequence !== manifest.last_sequence
    || checkpoint.seed_root_hash !== manifest.seed_root_hash
    || checkpoint.body_registry_digest !== manifest.body_registry_digest
    || checkpoint.created_by_body_id !== manifest.created_by_body_id
  ) {
    throw new Error("backup_checkpoint_links_invalid");
  }
  if (
    commit.signature.signed_digest !== commit.commit_digest
    || commit.signature.signer_id !== commit.created_by_body_id
    || commit.signature.signed_domain !== "genesis.backup.commit.signature.v0.1"
  ) {
    throw new Error("backup_commit_signature_unbound");
  }

  if (authorization.authorization_digest !== computeRecoveryAuthorizationDigest(authorization)) {
    throw new Error("recovery_authorization_digest_mismatch");
  }
  if (
    authorization.recovery_policy_id !== policy.policy_id
    || authorization.recovery_policy_digest !== policyDigest
    || authorization.policy_epoch !== policy.policy_epoch
  ) throw new Error("recovery_authorization_policy_mismatch");
  const issuedAt = Date.parse(authorization.issued_at);
  const notBefore = Date.parse(authorization.not_before);
  const expiresAt = Date.parse(authorization.expires_at);
  if (!(issuedAt <= notBefore && notBefore < expiresAt)) {
    throw new Error("recovery_authorization_time_window_invalid");
  }
  if (
    authorization.authorization_path === "policy_fallback"
    && notBefore < issuedAt + policy.fallback_wait_seconds * 1000
  ) throw new Error("recovery_fallback_wait_not_satisfied");
  if (
    authorization.source_backup_id !== commit.backup_id
    || authorization.source_backup_commit_digest !== commit.commit_digest
    || authorization.recovery_id !== record.recovery_id
    || authorization.previous_body_id !== record.previous_body_id
    || authorization.new_body_id !== record.new_body_id
  ) {
    throw new Error("recovery_authorization_scope_mismatch");
  }

  const approvalIds = authorization.approvals.map((approval) => approval.signer_id);
  if (new Set(approvalIds).size !== approvalIds.length) {
    throw new Error("recovery_authorization_duplicate_approval");
  }
  const approvedFactors = authorization.approvals.map((approval) => {
    const factor = factors.get(approval.signer_id);
    if (!factor || !factor.allowed_paths.includes(authorization.authorization_path)) {
      throw new Error("recovery_authorization_factor_not_allowed");
    }
    const signerType = factor.factor_type === "guardian" ? "guardian" : "recovery_authority";
    if (
      approval.signer_type !== signerType
      || approval.key_epoch_id !== factor.key_epoch_id
      || approval.public_key_ref !== factor.public_key_ref
      || approval.signed_domain !== "genesis.recovery.authorization.approval.v0.1"
      || approval.signed_digest !== authorization.authorization_digest
      || approval.created_at !== authorization.issued_at
    ) throw new Error("recovery_authorization_approval_invalid");
    return factor;
  });
  if (authorization.authorization_path === "guardian_assisted") {
    if (approvedFactors.length !== 1 || approvedFactors[0].factor_id !== policy.guardian_factor_id) {
      throw new Error("recovery_guardian_approval_missing");
    }
  } else if (
    approvedFactors.some((factor) => factor.factor_type === "guardian")
    || approvedFactors.length < policy.fallback_threshold
  ) throw new Error("recovery_fallback_threshold_not_met");

  if (registration.registration_digest !== computeRecoveryDestinationRegistrationDigest(registration)) {
    throw new Error("recovery_destination_registration_invalid");
  }
  if (
    registration.signature.signed_digest !== registration.registration_digest
    || registration.signature.signer_id !== registration.body_id
    || registration.signature.signer_type !== "body"
    || registration.signature.public_key_ref !== registration.public_key_fingerprint
    || registration.signature.signed_domain !== "genesis.recovery.destination.registration.signature.v0.1"
  ) {
    throw new Error("recovery_destination_registration_signature_unbound");
  }
  if (possession.proof_digest !== computeBodyPossessionDigest(possession)) {
    throw new Error("recovery_destination_possession_invalid");
  }
  if (
    generated.destination_possession_signature.signed_digest !== possession.proof_digest
    || generated.destination_possession_signature.signer_id !== possession.body_id
  ) {
    throw new Error("recovery_destination_possession_signature_unbound");
  }
  if (
    registration.body_id !== record.new_body_id
    || possession.body_id !== record.new_body_id
    || registration.public_key_fingerprint !== possession.public_key_fingerprint
  ) {
    throw new Error("recovery_destination_identity_mismatch");
  }
  if (
    registration.recovery_id !== authorization.recovery_id
    || registration.recovery_authorization_ref !== authorization.authorization_id
    || registration.recovery_authorization_digest !== authorization.authorization_digest
  ) {
    throw new Error("recovery_destination_scope_mismatch");
  }

  if (gap.gap_digest !== computeContinuityGapDigest(gap)) {
    throw new Error("continuity_gap_digest_mismatch");
  }
  if (revocation.revocation_digest !== computeBodyRevocationDigest(revocation)) {
    throw new Error("previous_body_revocation_digest_mismatch");
  }
  if (
    revocation.body_id !== record.previous_body_id
    || revocation.recovery_authorization_ref !== authorization.authorization_id
    || revocation.recovery_authorization_digest !== authorization.authorization_digest
  ) {
    throw new Error("previous_body_not_revoked");
  }
  if (record.recovery_digest !== computeRecoveryRecordDigest(record)) {
    throw new Error("recovery_record_digest_mismatch");
  }
  if (
    record.signature.signed_digest !== record.recovery_digest
    || record.signature.signer_id !== record.new_body_id
    || record.signature.signed_domain !== "genesis.recovery.record.signature.v0.1"
  ) {
    throw new Error("recovery_record_signature_unbound");
  }
  if (
    record.source_backup_id !== manifest.backup_id
    || record.source_backup_commit_digest !== commit.commit_digest
    || record.restored_checkpoint_hash !== manifest.checkpoint_hash
    || record.restored_last_event_hash !== manifest.last_event_hash
    || record.restored_last_sequence !== manifest.last_sequence
    || record.recovery_authorization_ref !== authorization.authorization_id
    || record.recovery_authorization_digest !== authorization.authorization_digest
  ) {
    throw new Error("recovery_record_links_invalid");
  }
  if (record.last_known_sequence <= record.restored_last_sequence || record.continuity_status !== "known_gap") {
    throw new Error("generated_recovery_missing_expected_gap");
  }
  if (
    gap.first_missing_sequence !== record.restored_last_sequence + 1
    || gap.last_missing_sequence !== record.last_known_sequence
    || gap.last_trusted_event_hash !== record.restored_last_event_hash
    || record.continuity_gap_ref !== gap.gap_id
  ) {
    throw new Error("continuity_gap_range_invalid");
  }

  if (finalization.finalization_digest !== computeRecoveryFinalizationDigest(finalization)) {
    throw new Error("recovery_finalization_digest_mismatch");
  }
  if (
    finalization.backup_commit_digest !== commit.commit_digest
    || finalization.recovery_record_digest !== record.recovery_digest
    || finalization.continuity_gap_digest !== gap.gap_digest
    || finalization.previous_body_revocation_digest !== revocation.revocation_digest
    || finalization.destination_registration_digest !== registration.registration_digest
    || finalization.destination_possession_digest !== possession.proof_digest
    || finalization.final_body_registry_digest !== registry.registry_digest
    || finalization.recovery_authorization_ref !== authorization.authorization_id
    || finalization.recovery_authorization_digest !== authorization.authorization_digest
    || finalization.recovery_event_hash !== recoveryEvent.event_hash
  ) {
    throw new Error("recovery_finalization_links_invalid");
  }
  if (
    finalization.destination_acknowledgement.signed_digest !== finalization.finalization_digest
    || finalization.destination_acknowledgement.signer_id !== record.new_body_id
    || finalization.destination_acknowledgement.signer_type !== "body"
    || finalization.destination_acknowledgement.public_key_ref !== registration.public_key_fingerprint
    || finalization.destination_acknowledgement.signed_domain !== "genesis.recovery.finalization.signature.v0.1"
  ) {
    throw new Error("recovery_finalization_signatures_unbound");
  }
  const activeWriters = registry.bodies.filter((body) => body.status === "active_writer");
  const previousBody = registry.bodies.find((body) => body.body_id === record.previous_body_id);
  if (activeWriters.length !== 1 || activeWriters[0].body_id !== record.new_body_id) {
    throw new Error("recovery_final_registry_authority_invalid");
  }
  if (!previousBody || !["lost", "revoked"].includes(previousBody.status)) {
    throw new Error("recovery_previous_body_still_authoritative");
  }
  if (previousBody.status !== finalization.previous_body_status) {
    throw new Error("recovery_finalization_status_mismatch");
  }
  if (
    recoveryEvent.body_id !== record.new_body_id
    || recoveryEvent.sequence !== record.last_known_sequence + 1
    || recoveryEvent.previous_event_hash !== record.restored_last_event_hash
  ) {
    throw new Error("recovery_event_continuity_invalid");
  }
}

const JOURNAL_PHASES = {
  birth: ["prepared", "seed_bound", "identity_bound", "body_bound", "memory_initialized", "finalizing", "born"],
  transfer: ["prepared", "frozen", "exported", "verified", "accepted", "finalizing", "completed"],
  recovery: ["discovered", "verified", "authorized", "restored", "finalizing", "finalized"]
};
const JOURNAL_TERMINAL_PHASE = { birth: "born", transfer: "completed", recovery: "finalized" };

function validateTransactionJournalChain(entries) {
  if (entries.length === 0) return "journal_empty";
  const first = entries[0];
  const identity = [
    first.journal_id,
    first.operation_kind,
    first.operation_id,
    first.instance_id,
    first.coordinator_body_id
  ].join("\u0000");
  const phases = JOURNAL_PHASES[first.operation_kind];
  if (!phases) return "journal_operation_kind_invalid";

  let expectedPrevious = "GENESIS";
  let previousPhaseIndex = -1;
  const previousStateDigest = first.previous_state_digest;
  let candidateStateDigest = null;
  let finalizationDigest = null;
  let terminalSeen = false;

  for (const [index, entry] of entries.entries()) {
    if (entry.journal_digest !== computeTransactionJournalDigest(entry)) return "journal_digest_mismatch";
    if (entry.sequence !== index) return "journal_sequence_invalid";
    if (entry.previous_journal_digest !== expectedPrevious) return "journal_chain_broken";
    if (terminalSeen) return "journal_entry_after_terminal";
    const entryIdentity = [
      entry.journal_id,
      entry.operation_kind,
      entry.operation_id,
      entry.instance_id,
      entry.coordinator_body_id
    ].join("\u0000");
    if (entryIdentity !== identity) return "journal_identity_changed";
    if (entry.previous_state_digest !== previousStateDigest) return "journal_previous_state_changed";

    const phaseIndex = phases.indexOf(entry.phase);
    if (phaseIndex < 0) return "journal_phase_invalid";
    if (phaseIndex < previousPhaseIndex) return "journal_phase_regression";
    previousPhaseIndex = phaseIndex;

    if (entry.candidate_state_digest !== null) {
      if (candidateStateDigest === null) candidateStateDigest = entry.candidate_state_digest;
      else if (entry.candidate_state_digest !== candidateStateDigest) return "journal_candidate_state_changed";
    }
    if (entry.finalization_digest !== null) {
      if (finalizationDigest === null) finalizationDigest = entry.finalization_digest;
      else if (entry.finalization_digest !== finalizationDigest) return "journal_finalization_changed";
    }

    const signature = entry.signature;
    if (
      signature.schema_version !== "genesis.signature.envelope.v0.1"
      || signature.signature_profile !== "genesis.signature.ed25519.v0.1"
      || signature.signed_digest !== entry.journal_digest
      || signature.signer_type !== "body"
      || signature.signer_id !== entry.coordinator_body_id
      || signature.signed_domain !== "genesis.transaction.journal.signature.v0.1"
      || signature.created_at !== entry.updated_at
    ) {
      return "journal_signature_unbound";
    }
    if (signature.public_key_ref !== JOURNAL_TEST_KEY_REF) {
      return "journal_signature_key_mismatch";
    }
    const signatureValue = Buffer.from(signature.signature_value, "hex");
    if (
      signatureValue.length !== 64
      || !crypto.verify(
        null,
        signatureEnvelopeBytes(signature),
        JOURNAL_TEST_PUBLIC_KEY,
        signatureValue
      )
    ) {
      return "journal_signature_invalid";
    }

    if (entry.status === "pending") {
      if (entry.commit_marker_digest !== null) return "journal_pending_has_commit_marker";
      if (entry.phase === JOURNAL_TERMINAL_PHASE[entry.operation_kind]) {
        return "journal_terminal_phase_not_committed";
      }
    } else if (entry.status === "committed") {
      if (entry.phase !== JOURNAL_TERMINAL_PHASE[entry.operation_kind]) return "journal_commit_phase_invalid";
      if (
        entry.candidate_state_digest === null
        || entry.finalization_digest === null
        || entry.commit_marker_digest !== entry.finalization_digest
      ) {
        return "journal_commit_marker_mismatch";
      }
      terminalSeen = true;
    } else if (entry.status === "aborted") {
      if (entry.commit_marker_digest !== null) return "journal_aborted_has_commit_marker";
      terminalSeen = true;
    } else {
      return "journal_status_invalid";
    }

    expectedPrevious = entry.journal_digest;
  }
  return null;
}

function evaluateJournalRestart(entries, observed, previous, candidate, finalization) {
  const error = validateTransactionJournalChain(entries);
  if (error) throw new Error(error);
  const latest = entries.at(-1);
  if (latest.previous_state_digest !== previous) throw new Error("journal_previous_state_untrusted");

  const candidates = new Set(
    entries.map((entry) => entry.candidate_state_digest).filter((value) => value !== null)
  );
  if (candidates.size > 0 && (candidates.size !== 1 || !candidates.has(candidate))) {
    throw new Error("journal_candidate_state_untrusted");
  }
  const finalizations = new Set(
    entries.map((entry) => entry.finalization_digest).filter((value) => value !== null)
  );
  if (finalizations.size > 0 && (finalizations.size !== 1 || !finalizations.has(finalization))) {
    throw new Error("journal_finalization_untrusted");
  }
  if (![previous, candidate].includes(observed)) throw new Error("journal_observed_state_unknown");

  if (latest.status === "committed") {
    if (latest.commit_marker_digest !== finalization) throw new Error("journal_commit_untrusted");
    if (latest.operation_kind === "birth") {
      return observed === candidate ? "accept_committed_birth" : "replay_committed_birth";
    }
    return observed === candidate ? "accept_committed_authority" : "replay_committed_authority";
  }
  if (latest.operation_kind === "birth") {
    return observed === previous ? "remain_absent" : "discard_uncommitted_birth";
  }
  return observed === previous ? "retain_previous_authority" : "rollback_uncommitted_authority";
}

function validateTransactionCrashArtifacts(validators, artifactPath) {
  const generated = readJson(artifactPath);
  verifyAllFixtureSignatures(generated, "transaction_crash");
  const entries = generated.journal_entries;
  if (!Array.isArray(entries)) throw new Error("crash_journal_entries_missing");
  for (const [index, entry] of entries.entries()) {
    requireValid(validators, "transaction_journal.schema.json", entry, `journal_entries[${index}]`);
    requireValid(validators, "signature_envelope.schema.json", entry.signature, `journal_entries[${index}].signature`);
  }

  const chainError = validateTransactionJournalChain(entries);
  if (chainError) throw new Error(chainError);
  const forgedEntries = structuredClone(entries);
  forgedEntries.at(-1).signature.signature_value = "00".repeat(64);
  if (validateTransactionJournalChain(forgedEntries) !== "journal_signature_invalid") {
    throw new Error("journal_forged_signature_not_rejected");
  }
  const first = entries[0];
  const latest = entries.at(-1);
  if (
    first.instance_id !== generated.instance_id
    || first.operation_id !== generated.operation_id
    || first.previous_state_digest !== generated.previous_registry_digest
  ) {
    throw new Error("crash_journal_bundle_identity_mismatch");
  }
  if (
    latest.status !== "committed"
    || latest.candidate_state_digest !== generated.candidate_registry_digest
    || latest.finalization_digest !== generated.trusted_finalization_digest
    || latest.commit_marker_digest !== generated.trusted_finalization_digest
  ) {
    throw new Error("crash_journal_terminal_commit_invalid");
  }

  for (const testCase of generated.restart_cases) {
    const action = evaluateJournalRestart(
      entries.slice(0, testCase.latest_sequence + 1),
      testCase.observed_state_digest,
      generated.previous_registry_digest,
      generated.candidate_registry_digest,
      generated.trusted_finalization_digest
    );
    if (action !== testCase.expected_action || action !== testCase.actual_action || !testCase.passed) {
      throw new Error(`crash_restart_case_mismatch:${testCase.case_id}`);
    }
  }
  if (
    generated.restart_cases.length !== 8
    || generated.negative_cases.length !== 13
    || generated.negative_cases.some((testCase) => !testCase.detected)
    || !generated.single_writer_before
    || !generated.single_writer_after
    || !generated.all_passed
  ) {
    throw new Error("crash_simulation_summary_invalid");
  }
}

function validateNegativeSchemaCases(validators) {
  const cases = readJson(INVALID_CASES).cases;
  const coveredSchemas = new Set();
  for (const testCase of cases) {
    const validate = validators.get(testCase.schema);
    if (!validate) throw new Error(`unknown_negative_case_schema:${testCase.schema}`);
    if (validate(testCase.artifact)) throw new Error(`invalid_case_accepted:${testCase.case_id}`);
    coveredSchemas.add(testCase.schema);
    if (
      testCase.expected_error_keyword
      && (
        validate.errors?.length !== 1
        || validate.errors[0].keyword !== testCase.expected_error_keyword
      )
    ) {
      throw new Error(
        `negative_case_wrong_error:${testCase.case_id}:${formatErrors(validate.errors)}`
      );
    }
  }
  for (const schemaName of validators.keys()) {
    if (!coveredSchemas.has(schemaName)) {
      throw new Error(`schema_without_negative_regression:${schemaName}`);
    }
  }
  return cases.length;
}

function validateHostAdapterFixtures(validators) {
  const vectors = readJson(HOST_ADAPTER_VECTORS);
  for (const adapter of vectors.adapters) {
    requireValid(
      validators,
      "host_capability_manifest.schema.json",
      adapter.manifest,
      adapter.case_id
    );
  }
  return vectors.adapters.length;
}

function validateInstanceIdentityFixture(validators) {
  const vectors = readJson(INSTANCE_IDENTITY_VECTORS);
  requireValid(
    validators,
    "instance_identity.schema.json",
    vectors.birth_identity,
    "birth_identity"
  );
  for (const testCase of vectors.continuity_cases) {
    requireValid(
      validators,
      "instance_identity.schema.json",
      testCase.identity,
      testCase.case_id
    );
  }
  return vectors.continuity_cases.length;
}

function validateBirthFixtureSchemas(validators) {
  const vectors = readJson(BIRTH_VECTORS);
  const fixture = vectors.fixture;
  const artifacts = [
    ["seed_manifest.schema.json", fixture.seed_manifest, "birth.seed_manifest"],
    ["instance_identity.schema.json", fixture.instance_identity, "birth.instance_identity"],
    ["body_record.schema.json", fixture.initial_body_record, "birth.initial_body_record"],
    ["body_registry.schema.json", fixture.initial_body_registry, "birth.initial_body_registry"],
    ["key_epoch.schema.json", fixture.initial_body_key_epoch, "birth.initial_body_key_epoch"],
    ["body_possession_proof.schema.json", fixture.initial_body_possession, "birth.initial_body_possession"],
    ["memory_event.schema.json", fixture.first_memory_event, "birth.first_memory_event"],
    ["instance_recovery_policy.schema.json", fixture.recovery_policy, "birth.recovery_policy"],
    ["birth_recovery_state.schema.json", fixture.birth_recovery_state, "birth.recovery_state"],
    ["birth_state.schema.json", fixture.birth_state, "birth.state"],
    ["birth_receipt.schema.json", fixture.birth_receipt, "birth.receipt"]
  ];
  for (const [schema, artifact, label] of artifacts) {
    requireValid(validators, schema, artifact, label);
  }
  const envelopes = [
    [fixture.first_memory_event.signature, "birth.first_memory_event.signature"],
    [fixture.recovery_policy.body_commitment, "birth.recovery_policy.body_commitment"],
    [fixture.recovery_policy.guardian_witness, "birth.recovery_policy.guardian_witness"],
    [fixture.birth_receipt.body_acknowledgement, "birth.receipt.body_acknowledgement"],
    [fixture.birth_receipt.guardian_witness, "birth.receipt.guardian_witness"]
  ];
  for (const [envelope, label] of envelopes) {
    requireValid(validators, "signature_envelope.schema.json", envelope, label);
  }
  for (const [index, entry] of fixture.journal_entries.entries()) {
    requireValid(validators, "transaction_journal.schema.json", entry, `birth.journal_entries[${index}]`);
    requireValid(validators, "signature_envelope.schema.json", entry.signature, `birth.journal_entries[${index}].signature`);
  }
  return fixture.journal_entries.length;
}

function validateBirthCrashArtifacts(artifactPath) {
  const generated = readJson(artifactPath);
  const vectors = readJson(BIRTH_VECTORS);
  if (
    generated.schema_version !== "genesis.birth.crash.simulation.v0.1"
    || generated.birth_id !== vectors.fixture.birth_state.birth_id
    || generated.instance_id !== vectors.fixture.birth_state.instance_id
    || generated.absent_state_digest !== vectors.fixture.absent_state_digest
    || generated.birth_state_digest !== vectors.expected.birth_state_digest
    || generated.receipt_digest !== vectors.expected.receipt_digest
  ) {
    throw new Error("birth_crash_bundle_link_invalid");
  }
  if (
    generated.restart_cases.length !== vectors.expected.restart_case_count
    || generated.negative_cases.length !== 13
    || generated.restart_cases.some((testCase) => !testCase.passed)
    || generated.negative_cases.some((testCase) => !testCase.detected)
    || generated.guardian_release_required !== false
    || generated.half_born_state_accepted !== false
    || generated.active_writer_count_after_commit !== 1
    || generated.all_passed !== true
  ) {
    throw new Error("birth_crash_simulation_summary_invalid");
  }
}

function validateSenseObservationFixtures(validators) {
  const vectors = readJson(SENSE_OBSERVATION_VECTORS);
  for (const observation of vectors.sense_observations) {
    requireValid(
      validators,
      "sense_observation.schema.json",
      observation,
      observation.observation_id
    );
  }
  const pipeline = vectors.accepted_pipeline;
  requireValid(
    validators,
    "memory_gate_decision.schema.json",
    pipeline.gate_decision,
    pipeline.gate_decision.decision_id
  );
  requireValid(
    validators,
    "memory_event.schema.json",
    pipeline.memory_event,
    pipeline.memory_event.event_id
  );
  return vectors.sense_observations.length;
}

function validateSenseAdapterFixtures(validators) {
  const vectors = readJson(SENSE_ADAPTER_VECTORS);
  for (const fixture of vectors.adapters) {
    requireValid(
      validators,
      "sense_adapter_manifest.schema.json",
      fixture.manifest,
      fixture.case_id
    );
    requireValid(
      validators,
      "sense_capture_result.schema.json",
      fixture.capture_result,
      fixture.capture_result.capture_id
    );
    requireValid(
      validators,
      "sense_observation.schema.json",
      fixture.observation,
      fixture.observation.observation_id
    );
  }
  for (const fixture of vectors.no_observation_cases) {
    requireValid(
      validators,
      "sense_capture_result.schema.json",
      fixture.capture_result,
      fixture.capture_result.capture_id
    );
    if (fixture.observation !== null) {
      throw new Error(`noncaptured_fixture_contains_observation:${fixture.case_id}`);
    }
  }
  return {
    adapterCount: vectors.adapters.length,
    failClosedCount: vectors.no_observation_cases.length
  };
}

function validateGuardianMobilityFixtures(validators) {
  const vectors = readJson(GUARDIAN_MOBILITY_VECTORS);
  let eventCount = 0;
  for (const fixture of vectors.positive_cases) {
    requireValid(
      validators,
      "guardian_authorization.schema.json",
      fixture.authorization,
      fixture.case_id
    );
    requireValid(
      validators,
      "signature_envelope.schema.json",
      fixture.authorization.signature,
      `${fixture.case_id}.authorization.signature`
    );
    for (const [index, event] of fixture.events.entries()) {
      requireValid(
        validators,
        "guardian_authority_event.schema.json",
        event,
        `${fixture.case_id}.events[${index}]`
      );
      requireValid(
        validators,
        "signature_envelope.schema.json",
        event.signature,
        `${fixture.case_id}.events[${index}].signature`
      );
      eventCount += 1;
    }
  }
  return { authorizationCount: vectors.positive_cases.length, eventCount };
}

function main() {
  if (process.argv[2] === "--transfer-only") {
    const artifactPath = process.argv[3];
    if (!artifactPath) throw new Error("transfer_artifact_path_missing");
    validateGeneratedArtifacts(loadValidators(), path.resolve(artifactPath));
    console.log("Generated A -> B artifacts and cross-links: OK.");
    return;
  }
  const scalarCounts = validatePortableSchemaScalars();
  const validators = loadValidators();
  const invalidCount = validateNegativeSchemaCases(validators);
  const hostAdapterCount = validateHostAdapterFixtures(validators);
  const identityPlatformCount = validateInstanceIdentityFixture(validators);
  const birthPhaseCount = validateBirthFixtureSchemas(validators);
  const senseObservationCount = validateSenseObservationFixtures(validators);
  const senseAdapterCounts = validateSenseAdapterFixtures(validators);
  const guardianMobilityCounts = validateGuardianMobilityFixtures(validators);
  const associativeVectors = readJson(ASSOCIATIVE_MEMORY_PROJECTION_VECTORS);
  requireValid(
    validators,
    "associative_memory_projection.schema.json",
    associativeVectors.projection,
    "conformance/associative_memory_projection_vectors.json"
  );
  requireValid(
    validators,
    "draft_manifest.schema.json",
    readJson(DRAFT_MANIFEST),
    "conformance/draft_manifest.json"
  );
  const artifactPath = process.argv[2];
  const backupRecoveryPath = process.argv[3];
  const transactionCrashPath = process.argv[4];
  const birthCrashPath = process.argv[5];
  if (artifactPath) validateGeneratedArtifacts(validators, path.resolve(artifactPath));
  if (backupRecoveryPath) validateBackupRecoveryArtifacts(validators, path.resolve(backupRecoveryPath));
  if (transactionCrashPath) validateTransactionCrashArtifacts(validators, path.resolve(transactionCrashPath));
  if (birthCrashPath) validateBirthCrashArtifacts(path.resolve(birthCrashPath));

  console.log(`JSON Schema 2020-12: OK (${validators.size} schemas compiled).`);
  console.log(
    `Portable scalars: OK (${scalarCounts.integerCount} integers, ` +
    `${scalarCounts.timestampCount} canonical UTC timestamps).`
  );
  console.log(`Schema negative regressions: OK (${invalidCount} rejected).`);
  console.log(`Host capability manifest fixtures: OK (${hostAdapterCount} declarations).`);
  console.log(
    `Immutable birth identity fixture: OK (${identityPlatformCount} platform declarations).`
  );
  console.log(`Atomic birth schema fixtures: OK (${birthPhaseCount} journal phases).`);
  console.log(`Signed sense observation fixtures: OK (${senseObservationCount} senses).`);
  console.log(
    `Neutral sense adapter fixtures: OK (${senseAdapterCounts.adapterCount} adapters, ` +
    `${senseAdapterCounts.failClosedCount} fail-closed results).`
  );
  console.log(
    `Guardian mobility schema fixtures: OK (${guardianMobilityCounts.authorizationCount} ` +
    `authorizations, ${guardianMobilityCounts.eventCount} authority events).`
  );
  console.log("Associative memory projection schema fixture: OK.");
  console.log("Draft integrity manifest schema: OK.");
  if (artifactPath) console.log("Generated A -> B artifacts and cross-links: OK.");
  if (backupRecoveryPath) console.log("Generated backup -> recovery artifacts and cross-links: OK.");
  if (transactionCrashPath) console.log("Generated transaction journal and crash recovery decisions: OK.");
  if (birthCrashPath) console.log("Generated atomic birth crash decisions: OK.");
}

try {
  main();
} catch (error) {
  console.error(`FAIL schema conformance: ${error.message}`);
  process.exit(1);
}

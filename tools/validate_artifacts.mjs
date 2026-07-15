import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_DIR = path.join(ROOT, "schemas");
const INVALID_CASES = path.join(ROOT, "conformance/schema_invalid_cases.json");
const DRAFT_MANIFEST = path.join(ROOT, "conformance/draft_manifest.json");
const HOST_ADAPTER_VECTORS = path.join(ROOT, "conformance/host_adapter_vectors.json");
const INSTANCE_IDENTITY_VECTORS = path.join(
  ROOT,
  "conformance/instance_identity_vectors.json"
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
  [0xa1, 0xb2, 0xc3, 0xd4].map((seedByte) => {
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

function computeAuthorizationDigest(authorization) {
  const destinations = [...authorization.destination_body_ids].sort((left, right) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
  );
  return hashFields("genesis.guardian.authorization.v0.1", [
    authorization.schema_version,
    authorization.authorization_id,
    authorization.guardian_id,
    authorization.guardian_key_epoch_id,
    authorization.instance_id,
    String(authorization.authority_epoch),
    authorization.permission,
    authorization.mode,
    optionalText(authorization.source_body_id),
    authorization.destination_scope,
    String(destinations.length),
    ...destinations,
    authorization.issued_at,
    authorization.not_before,
    optionalText(authorization.expires_at),
    optionalText(authorization.use_limit)
  ]);
}

function computeAuthorityEventHash(event) {
  return hashFields("genesis.guardian.authority.event.v0.1", [
    event.schema_version,
    event.ledger_id,
    event.event_id,
    String(event.sequence),
    event.previous_event_hash,
    event.guardian_id,
    event.instance_id,
    String(event.authority_epoch),
    event.event_type,
    optionalText(event.authorization_ref),
    optionalText(event.body_id),
    optionalText(event.transfer_id),
    event.subject_digest,
    event.recorded_at
  ]);
}

function computeAuthorizationUseDigest(authorizationId, transferId, sourceBodyId, destinationBodyId) {
  return hashFields("genesis.guardian.authorization.use.v0.1", [
    authorizationId,
    transferId,
    sourceBodyId,
    destinationBodyId
  ]);
}

function boolText(value) {
  return value ? "true" : "false";
}

function sha256Bytes(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
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
    authorization.guardian_id,
    authorization.guardian_key_epoch_id,
    authorization.instance_id,
    String(authorization.authority_epoch),
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
    revocation.guardian_authorization_ref
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
    record.guardian_authorization_ref,
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
    finalization.guardian_authorization_ref,
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
  const forgedAuthorization = structuredClone(generated.guardian_authorization.signature);
  forgedAuthorization.signature_value = "00".repeat(64);
  try {
    verifyFixtureSignature(forgedAuthorization, "transfer.forged_authorization");
    throw new Error("forged_transfer_signature_accepted");
  } catch (error) {
    if (!error.message.startsWith("fixture_signature_invalid:")) throw error;
  }
  const requiredTopLevel = [
    "guardian_device_registrations",
    "guardian_authorization",
    "guardian_authority_events",
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

  for (const [index, registration] of generated.guardian_device_registrations.entries()) {
    requireValid(
      validators,
      "guardian_device_registration.schema.json",
      registration,
      `guardian_device_registrations[${index}]`
    );
    requireValid(
      validators,
      "signature_envelope.schema.json",
      registration.signature,
      `guardian_device_registrations[${index}].signature`
    );
    if (registration.registration_digest !== computeDeviceRegistrationDigest(registration)) {
      throw new Error(`device_registration_digest_mismatch:${index}`);
    }
    if (
      registration.signature.signed_digest !== registration.registration_digest
      || registration.signature.signer_id !== registration.guardian_id
      || registration.signature.key_epoch_id !== registration.guardian_key_epoch_id
      || registration.signature.signed_domain !== "genesis.guardian.device.registration.signature.v0.1"
    ) {
      throw new Error(`device_registration_signature_unbound:${index}`);
    }
  }
  requireValid(
    validators,
    "guardian_authorization.schema.json",
    generated.guardian_authorization,
    "guardian_authorization"
  );
  requireValid(
    validators,
    "signature_envelope.schema.json",
    generated.guardian_authorization.signature,
    "guardian_authorization.signature"
  );
  if (generated.guardian_authorization.authorization_digest !== computeAuthorizationDigest(generated.guardian_authorization)) {
    throw new Error("guardian_authorization_digest_mismatch");
  }
  if (
    generated.guardian_authorization.signature.signed_digest
      !== generated.guardian_authorization.authorization_digest
    || generated.guardian_authorization.signature.signer_id !== generated.guardian_authorization.guardian_id
    || generated.guardian_authorization.signature.key_epoch_id
      !== generated.guardian_authorization.guardian_key_epoch_id
    || generated.guardian_authorization.signature.signed_domain
      !== "genesis.guardian.authorization.signature.v0.1"
  ) {
    throw new Error("guardian_authorization_signature_unbound");
  }
  let previousAuthorityEpoch = -1;
  for (const [index, event] of generated.guardian_authority_events.entries()) {
    requireValid(validators, "guardian_authority_event.schema.json", event, `guardian_authority_events[${index}]`);
    requireValid(
      validators,
      "signature_envelope.schema.json",
      event.signature,
      `guardian_authority_events[${index}].signature`
    );
    const expectedPrevious = index === 0 ? "GENESIS" : generated.guardian_authority_events[index - 1].event_hash;
    if (event.sequence !== index) throw new Error(`authority_ledger_sequence_invalid:${index}`);
    if (event.previous_event_hash !== expectedPrevious) throw new Error(`authority_ledger_chain_broken:${index}`);
    if (event.event_hash !== computeAuthorityEventHash(event)) throw new Error(`authority_event_hash_mismatch:${index}`);
    if (event.signature.signed_digest !== event.event_hash) throw new Error(`authority_event_signature_unbound:${index}`);
    if (event.signature.signed_domain !== "genesis.guardian.authority.event.signature.v0.1") {
      throw new Error(`authority_event_signature_domain_invalid:${index}`);
    }
    if (event.guardian_id !== generated.guardian_authorization.guardian_id) {
      throw new Error(`authority_event_guardian_mismatch:${index}`);
    }
    if (event.instance_id !== generated.guardian_authorization.instance_id) {
      throw new Error(`authority_event_instance_mismatch:${index}`);
    }
    if (event.authority_epoch < previousAuthorityEpoch) {
      throw new Error(`authority_epoch_regression:${index}`);
    }
    if (previousAuthorityEpoch >= 0 && event.authority_epoch > previousAuthorityEpoch) {
      if (event.event_type !== "authority.epoch.rotated" || event.authority_epoch !== previousAuthorityEpoch + 1) {
        throw new Error(`authority_epoch_change_without_rotation:${index}`);
      }
    }
    if (event.event_type === "authorization.consumed") {
      if (event.signature.signer_id !== event.body_id) throw new Error(`authority_consumption_signer_invalid:${index}`);
    } else if (event.signature.signer_id !== event.guardian_id) {
      throw new Error(`authority_guardian_signer_invalid:${index}`);
    }
    previousAuthorityEpoch = event.authority_epoch;
  }

  requireValid(validators, "body_registry.schema.json", generated.body_registry_before, "body_registry_before");
  requireValid(validators, "body_registry.schema.json", generated.body_registry, "body_registry");
  for (const [index, event] of generated.memory_events.entries()) {
    requireValid(validators, "memory_event.schema.json", event, `memory_events[${index}]`);
    if (event.signature) {
      requireValid(validators, "signature_envelope.schema.json", event.signature, `memory_events[${index}].signature`);
    }
  }
  requireValid(validators, "checkpoint.schema.json", generated.checkpoint, "checkpoint");
  if (generated.checkpoint.signature) {
    requireValid(validators, "signature_envelope.schema.json", generated.checkpoint.signature, "checkpoint.signature");
  }
  requireValid(validators, "body_possession_proof.schema.json", generated.body_possession_proof, "body_possession_proof");
  requireValid(
    validators,
    "signature_envelope.schema.json",
    generated.body_possession_signature,
    "body_possession_signature"
  );
  requireValid(validators, "transfer_package.schema.json", generated.transfer_package, "transfer_package");
  requireValid(validators, "transfer_receipt.schema.json", generated.transfer_receipt, "transfer_receipt");
  if (generated.transfer_receipt.signature) {
    requireValid(validators, "signature_envelope.schema.json", generated.transfer_receipt.signature, "transfer_receipt.signature");
  }
  requireValid(validators, "transfer_finalization.schema.json", generated.transfer_finalization, "transfer_finalization");
  for (const field of ["source_acknowledgement", "destination_acknowledgement"]) {
    const acknowledgement = generated.transfer_finalization[field];
    if (acknowledgement) {
      requireValid(validators, "signature_envelope.schema.json", acknowledgement, `transfer_finalization.${field}`);
    }
  }

  const events = generated.memory_events;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.sequence !== index) throw new Error(`non_contiguous_sequence:${index}`);
    const expectedPrevious = index === 0 ? "GENESIS" : events[index - 1].event_hash;
    if (event.previous_event_hash !== expectedPrevious) throw new Error(`broken_memory_chain:${index}`);
  }

  const preTransferTip = events.at(-2);
  const completedEvent = events.at(-1);
  const pkg = generated.transfer_package;
  const receipt = generated.transfer_receipt;
  const finalization = generated.transfer_finalization;
  const checkpoint = generated.checkpoint;
  const registryBefore = generated.body_registry_before;
  const authorization = generated.guardian_authorization;
  const registrations = generated.guardian_device_registrations;
  const authorityEvents = generated.guardian_authority_events;

  if (
    pkg.authorization_ref !== authorization.authorization_id
    || receipt.guardian_authorization_ref !== authorization.authorization_id
    || finalization.guardian_authorization_ref !== authorization.authorization_id
  ) {
    throw new Error("transfer_authorization_ref_mismatch");
  }
  if (authorization.mode !== "standing" || authorization.destination_scope !== "registered_guardian_devices") {
    throw new Error("generated_scenario_not_standing_mobility");
  }
  const activeAuthorityEpoch = Math.max(...authorityEvents.map((event) => event.authority_epoch));
  if (authorization.authority_epoch !== activeAuthorityEpoch) {
    throw new Error("authorization_epoch_inactive");
  }
  const destinationRegistration = registrations.find((item) => item.body_id === pkg.destination_body_id);
  if (!destinationRegistration) throw new Error("destination_not_registered");
  if (
    destinationRegistration.guardian_id !== authorization.guardian_id
    || destinationRegistration.instance_id !== authorization.instance_id
    || destinationRegistration.authority_epoch !== authorization.authority_epoch
  ) {
    throw new Error("destination_registration_authority_mismatch");
  }
  const destinationBody = registryBefore.bodies.find((item) => item.body_id === pkg.destination_body_id);
  if (!destinationBody) throw new Error("destination_missing_from_body_registry");
  if (destinationRegistration.public_key_fingerprint !== destinationBody.public_key_fingerprint) {
    throw new Error("destination_registration_key_mismatch");
  }
  if (destinationRegistration.public_key_fingerprint !== generated.body_possession_proof.public_key_fingerprint) {
    throw new Error("destination_possession_key_mismatch");
  }
  const packageContents = new Map(pkg.contents.map((item) => [item.path, item.digest]));
  if (packageContents.get("authority/guardian-authorization.json") !== authorization.authorization_digest) {
    throw new Error("package_missing_bound_authorization");
  }
  if (
    packageContents.get("authority/destination-device-registration.json")
      !== destinationRegistration.registration_digest
  ) {
    throw new Error("package_missing_bound_destination_registration");
  }
  if (packageContents.get("authority/ledger-tip.json") !== authorityEvents.at(-1).event_hash) {
    throw new Error("package_missing_bound_authority_ledger_tip");
  }
  const registrationEvent = authorityEvents.find(
    (event) => event.event_type === "device.registered"
      && event.body_id === pkg.destination_body_id
      && event.subject_digest === destinationRegistration.registration_digest
  );
  if (!registrationEvent) throw new Error("destination_registration_not_recorded");
  if (authorityEvents.some((event) => event.event_type === "device.revoked" && event.body_id === pkg.destination_body_id)) {
    throw new Error("destination_device_revoked");
  }
  const grant = authorityEvents.find(
    (event) => event.event_type === "authorization.granted"
      && event.authorization_ref === authorization.authorization_id
      && event.subject_digest === authorization.authorization_digest
  );
  if (!grant) throw new Error("authorization_grant_not_recorded");
  if (
    authorityEvents.some(
      (event) => event.event_type === "authorization.revoked"
        && event.authorization_ref === authorization.authorization_id
    )
  ) {
    throw new Error("authorization_revoked");
  }
  const consumptions = authorityEvents.filter(
    (event) => event.event_type === "authorization.consumed"
      && event.authorization_ref === authorization.authorization_id
      && event.transfer_id === pkg.transfer_id
  );
  if (consumptions.length !== 1 || consumptions[0].body_id !== pkg.source_body_id) {
    throw new Error("authorization_consumption_not_recorded");
  }
  const [consumption] = consumptions;
  const expectedUseDigest = computeAuthorizationUseDigest(
    authorization.authorization_id,
    pkg.transfer_id,
    pkg.source_body_id,
    pkg.destination_body_id
  );
  if (consumption.subject_digest !== expectedUseDigest) throw new Error("authorization_use_digest_mismatch");

  if (checkpoint.last_event_hash !== preTransferTip.event_hash || checkpoint.sequence !== preTransferTip.sequence) {
    throw new Error("checkpoint_not_bound_to_pre_transfer_tip");
  }
  if (checkpoint.body_registry_digest !== registryBefore.registry_digest) {
    throw new Error("checkpoint_not_bound_to_pre_transfer_registry");
  }
  if (pkg.checkpoint_hash !== checkpoint.checkpoint_hash || pkg.last_event_hash !== preTransferTip.event_hash) {
    throw new Error("package_not_bound_to_checkpoint");
  }
  if (receipt.accepted_package_digest !== pkg.package_digest) throw new Error("receipt_not_bound_to_package");
  if (receipt.accepted_checkpoint_hash !== checkpoint.checkpoint_hash) throw new Error("receipt_not_bound_to_checkpoint");
  if (finalization.receipt_digest !== receipt.receipt_digest) throw new Error("finalization_not_bound_to_receipt");
  if (completedEvent.body_id !== finalization.destination_body_id) throw new Error("completion_event_wrong_body");
  if (completedEvent.previous_event_hash !== preTransferTip.event_hash) throw new Error("completion_event_wrong_parent");

  const activeWriters = generated.body_registry.bodies.filter((body) => body.status === "active_writer");
  if (activeWriters.length !== 1 || activeWriters[0].body_id !== finalization.destination_body_id) {
    throw new Error("final_registry_authority_invalid");
  }
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
  requireValid(validators, "recovery_authorization.schema.json", authorization, "recovery_authorization");
  requireValid(
    validators,
    "signature_envelope.schema.json",
    authorization.signature,
    "recovery_authorization.signature"
  );
  requireValid(
    validators,
    "guardian_device_registration.schema.json",
    registration,
    "destination_registration"
  );
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
    finalization.guardian_acknowledgement,
    "recovery_finalization.guardian_acknowledgement"
  );
  requireValid(
    validators,
    "signature_envelope.schema.json",
    finalization.destination_acknowledgement,
    "recovery_finalization.destination_acknowledgement"
  );

  if (manifest.package_digest !== computeBackupManifestDigest(manifest)) {
    throw new Error("backup_manifest_digest_mismatch");
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
  const issuedAt = Date.parse(authorization.issued_at);
  const notBefore = Date.parse(authorization.not_before);
  const expiresAt = Date.parse(authorization.expires_at);
  if (!(issuedAt <= notBefore && notBefore < expiresAt)) {
    throw new Error("recovery_authorization_time_window_invalid");
  }
  if (
    authorization.signature.signed_digest !== authorization.authorization_digest
    || authorization.signature.signer_id !== authorization.guardian_id
    || authorization.signature.key_epoch_id !== authorization.guardian_key_epoch_id
    || authorization.signature.signed_domain !== "genesis.recovery.authorization.signature.v0.1"
  ) {
    throw new Error("recovery_authorization_signature_unbound");
  }
  if (
    authorization.source_backup_id !== commit.backup_id
    || authorization.source_backup_commit_digest !== commit.commit_digest
    || authorization.recovery_id !== record.recovery_id
    || authorization.previous_body_id !== record.previous_body_id
    || authorization.new_body_id !== record.new_body_id
  ) {
    throw new Error("recovery_authorization_scope_mismatch");
  }

  if (registration.registration_digest !== computeDeviceRegistrationDigest(registration)) {
    throw new Error("recovery_destination_registration_invalid");
  }
  if (
    registration.signature.signed_digest !== registration.registration_digest
    || registration.signature.signer_id !== registration.guardian_id
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
    registration.guardian_id !== authorization.guardian_id
    || registration.guardian_key_epoch_id !== authorization.guardian_key_epoch_id
    || registration.authority_epoch !== authorization.authority_epoch
  ) {
    throw new Error("recovery_guardian_scope_mismatch");
  }

  if (gap.gap_digest !== computeContinuityGapDigest(gap)) {
    throw new Error("continuity_gap_digest_mismatch");
  }
  if (revocation.revocation_digest !== computeBodyRevocationDigest(revocation)) {
    throw new Error("previous_body_revocation_digest_mismatch");
  }
  if (
    revocation.body_id !== record.previous_body_id
    || revocation.guardian_authorization_ref !== authorization.authorization_id
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
    || record.guardian_authorization_ref !== authorization.authorization_id
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
    || finalization.guardian_authorization_ref !== authorization.authorization_id
    || finalization.recovery_event_hash !== recoveryEvent.event_hash
  ) {
    throw new Error("recovery_finalization_links_invalid");
  }
  if (
    finalization.guardian_acknowledgement.signed_digest !== finalization.finalization_digest
    || finalization.guardian_acknowledgement.signer_id !== authorization.guardian_id
    || finalization.destination_acknowledgement.signed_digest !== finalization.finalization_digest
    || finalization.destination_acknowledgement.signer_id !== record.new_body_id
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
  transfer: ["prepared", "frozen", "exported", "verified", "accepted", "finalizing", "completed"],
  recovery: ["discovered", "verified", "authorized", "restored", "finalizing", "finalized"]
};
const JOURNAL_TERMINAL_PHASE = { transfer: "completed", recovery: "finalized" };

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
    return observed === candidate ? "accept_committed_authority" : "replay_committed_authority";
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

function main() {
  const scalarCounts = validatePortableSchemaScalars();
  const validators = loadValidators();
  const invalidCount = validateNegativeSchemaCases(validators);
  const hostAdapterCount = validateHostAdapterFixtures(validators);
  const identityPlatformCount = validateInstanceIdentityFixture(validators);
  const senseObservationCount = validateSenseObservationFixtures(validators);
  const senseAdapterCounts = validateSenseAdapterFixtures(validators);
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
  if (artifactPath) validateGeneratedArtifacts(validators, path.resolve(artifactPath));
  if (backupRecoveryPath) validateBackupRecoveryArtifacts(validators, path.resolve(backupRecoveryPath));
  if (transactionCrashPath) validateTransactionCrashArtifacts(validators, path.resolve(transactionCrashPath));

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
  console.log(`Signed sense observation fixtures: OK (${senseObservationCount} senses).`);
  console.log(
    `Neutral sense adapter fixtures: OK (${senseAdapterCounts.adapterCount} adapters, ` +
    `${senseAdapterCounts.failClosedCount} fail-closed results).`
  );
  console.log("Associative memory projection schema fixture: OK.");
  console.log("Draft integrity manifest schema: OK.");
  if (artifactPath) console.log("Generated A -> B artifacts and cross-links: OK.");
  if (backupRecoveryPath) console.log("Generated backup -> recovery artifacts and cross-links: OK.");
  if (transactionCrashPath) console.log("Generated transaction journal and crash recovery decisions: OK.");
}

try {
  main();
} catch (error) {
  console.error(`FAIL schema conformance: ${error.message}`);
  process.exit(1);
}

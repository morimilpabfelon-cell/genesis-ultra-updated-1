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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function formatErrors(errors) {
  return (errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message}`)
    .join("; ");
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

function validateNegativeSchemaCases(validators) {
  const cases = readJson(INVALID_CASES).cases;
  for (const testCase of cases) {
    const validate = validators.get(testCase.schema);
    if (!validate) throw new Error(`unknown_negative_case_schema:${testCase.schema}`);
    if (validate(testCase.artifact)) throw new Error(`invalid_case_accepted:${testCase.case_id}`);
  }
  return cases.length;
}

function main() {
  const validators = loadValidators();
  const invalidCount = validateNegativeSchemaCases(validators);
  const artifactPath = process.argv[2];
  if (artifactPath) validateGeneratedArtifacts(validators, path.resolve(artifactPath));

  console.log(`JSON Schema 2020-12: OK (${validators.size} schemas compiled).`);
  console.log(`Schema negative regressions: OK (${invalidCount} rejected).`);
  if (artifactPath) console.log("Generated A -> B artifacts and cross-links: OK.");
}

try {
  main();
} catch (error) {
  console.error(`FAIL schema conformance: ${error.message}`);
  process.exit(1);
}

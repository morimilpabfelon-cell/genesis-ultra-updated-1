import fs from "node:fs";
import path from "node:path";
import process from "node:process";
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

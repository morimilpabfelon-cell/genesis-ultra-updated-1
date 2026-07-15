import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/host_adapter_vectors.json"), "utf8")
);

const MANIFEST_FIELDS = new Set([
  "schema_version",
  "adapter_id",
  "adapter_version",
  "platform_profile",
  "protocol_versions",
  "verification_state",
  "capabilities",
  "portability"
]);
const PORTABLE_IDENTITY_FIELDS = new Set([
  "seed_id",
  "seed_root_hash",
  "instance_id",
  "memory",
  "checkpoint",
  "guardian_id"
]);
const ANCHOR_FIELDS = [
  "protocol_version",
  "seed_root_hash",
  "instance_id",
  "checkpoint_hash",
  "last_event_hash",
  "last_sequence",
  "continuity_status",
  "authority_ledger_head"
];
const PORTABILITY_RULES = new Map([
  ["neutral_export", [true, "neutral_export_required"]],
  ["neutral_import", [true, "neutral_import_required"]],
  ["platform_account_required", [false, "platform_account_required"]],
  ["private_body_keys_exported", [false, "private_body_key_export_forbidden"]],
  ["engine_bound_to_identity", [false, "engine_identity_binding_forbidden"]],
  ["source_deactivation_required", [true, "source_deactivation_required"]]
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
    Buffer.from(`${bytes.length}:`, "ascii"),
    bytes,
    Buffer.from("\n", "ascii")
  ]);
}

function hashFields(domain, fields) {
  const preimage = Buffer.concat([frame(domain), ...fields.map((value) => frame(value))]);
  return `sha256:${crypto.createHash("sha256").update(preimage).digest("hex")}`;
}

function validateCapabilities(capabilities, required) {
  if (new Set(capabilities).size !== capabilities.length) {
    throw new ConformanceError("duplicate_host_capability");
  }
  const sorted = [...capabilities].sort(compareUtf8);
  if (capabilities.some((value, index) => value !== sorted[index])) {
    throw new ConformanceError("unsorted_host_capabilities");
  }
  if (required.some((capability) => !capabilities.includes(capability))) {
    throw new ConformanceError("missing_required_capability");
  }
  if (capabilities.some((capability) => !required.includes(capability))) {
    throw new ConformanceError("unsupported_host_capability");
  }
}

function validatePortability(portability) {
  const fields = Object.keys(portability);
  if ([...PORTABILITY_RULES.keys()].some((field) => !fields.includes(field))) {
    throw new ConformanceError("missing_portability_rule");
  }
  if (fields.some((field) => !PORTABILITY_RULES.has(field))) {
    throw new ConformanceError("unexpected_portability_rule");
  }
  for (const [field, [expected, errorCode]] of PORTABILITY_RULES) {
    if (portability[field] !== expected) throw new ConformanceError(errorCode);
  }
}

function validateManifest(manifest, required) {
  const additional = Object.keys(manifest).filter((field) => !MANIFEST_FIELDS.has(field));
  if (additional.some((field) => PORTABLE_IDENTITY_FIELDS.has(field))) {
    throw new ConformanceError("host_manifest_contains_portable_identity");
  }
  if (additional.length > 0) throw new ConformanceError("unexpected_host_manifest_field");
  if ([...MANIFEST_FIELDS].some((field) => !(field in manifest))) {
    throw new ConformanceError("missing_host_manifest_field");
  }
  if (manifest.schema_version !== "genesis.host.capability.manifest.v0.1") {
    throw new ConformanceError("host_manifest_schema_version_invalid");
  }
  if (!manifest.protocol_versions.includes("genesis.protocol.v0.1")) {
    throw new ConformanceError("protocol_version_not_supported");
  }
  if (!["declaration_only", "simulated", "storage_verified"].includes(manifest.verification_state)) {
    throw new ConformanceError("host_verification_state_invalid");
  }
  validateCapabilities(manifest.capabilities, required);
  validatePortability(manifest.portability);
}

function validateAnchor(anchor, forbiddenFields) {
  if (Object.keys(anchor).some((field) => forbiddenFields.has(field))) {
    throw new ConformanceError("platform_binding_in_portable_anchor");
  }
  const actualFields = Object.keys(anchor);
  if (
    actualFields.length !== ANCHOR_FIELDS.length
    || ANCHOR_FIELDS.some((field) => !actualFields.includes(field))
  ) {
    throw new ConformanceError("portable_anchor_fields_invalid");
  }
}

function computeAnchor(vector, forbiddenFields) {
  const anchor = vector.input;
  validateAnchor(anchor, forbiddenFields);
  return hashFields(vector.domain, [
    anchor.protocol_version,
    anchor.seed_root_hash,
    anchor.instance_id,
    anchor.checkpoint_hash,
    anchor.last_event_hash,
    String(anchor.last_sequence),
    anchor.continuity_status,
    anchor.authority_ledger_head
  ]);
}

function evaluateRejection(testCase) {
  const mutation = testCase.input;
  const manifest = structuredClone(vectors.adapters[0].manifest);
  try {
    if (testCase.category === "required_capabilities") {
      const capabilities = [...manifest.capabilities];
      if (mutation.remove) capabilities.splice(capabilities.indexOf(mutation.remove), 1);
      if (mutation.duplicate) capabilities.push(mutation.duplicate);
      if (mutation.reverse) capabilities.reverse();
      validateCapabilities(capabilities, vectors.required_capabilities);
    } else if (testCase.category === "host_manifest_fields") {
      for (const field of mutation.additional_fields) manifest[field] = "forbidden";
      validateManifest(manifest, vectors.required_capabilities);
    } else if (testCase.category === "portability") {
      manifest.portability[mutation.field] = mutation.value;
      validateManifest(manifest, vectors.required_capabilities);
    } else if (testCase.category === "portable_anchor_fields") {
      const anchor = structuredClone(vectors.portable_anchor.input);
      for (const field of mutation.additional_fields) anchor[field] = "forbidden";
      validateAnchor(anchor, new Set(vectors.forbidden_portable_fields));
    } else {
      throw new ConformanceError(`unknown_host_rejection_category:${testCase.category}`);
    }
  } catch (error) {
    if (error instanceof ConformanceError) return error.message;
    throw error;
  }
  return null;
}

function main() {
  const failures = [];
  if (vectors.profile !== "genesis.host.adapter.v0.1") failures.push("host_adapter_profile_invalid");

  try {
    validateCapabilities(vectors.required_capabilities, vectors.required_capabilities);
    const sortedForbidden = [...vectors.forbidden_portable_fields].sort(compareUtf8);
    if (vectors.forbidden_portable_fields.some((value, index) => value !== sortedForbidden[index])) {
      throw new ConformanceError("unsorted_forbidden_portable_fields");
    }
    if (new Set(vectors.forbidden_portable_fields).size !== vectors.forbidden_portable_fields.length) {
      throw new ConformanceError("duplicate_forbidden_portable_field");
    }
  } catch (error) {
    failures.push(error.message);
  }

  const expectedProfiles = new Set(["android-kotlin", "apple-swift", "windows-dotnet"]);
  const actualProfiles = new Set(vectors.adapters.map((adapter) => adapter.manifest.platform_profile));
  if (
    actualProfiles.size !== expectedProfiles.size
    || [...expectedProfiles].some((profile) => !actualProfiles.has(profile))
  ) {
    failures.push("host_fixture_platform_set_invalid");
  }

  const forbiddenFields = new Set(vectors.forbidden_portable_fields);
  for (const adapter of vectors.adapters) {
    try {
      validateManifest(adapter.manifest, vectors.required_capabilities);
      if (adapter.manifest.verification_state !== "declaration_only") {
        throw new ConformanceError("fixture_must_not_claim_storage_verification");
      }
      const actualAnchor = computeAnchor(vectors.portable_anchor, forbiddenFields);
      if (actualAnchor !== vectors.portable_anchor.expected_digest) {
        throw new ConformanceError("portable_anchor_digest_mismatch");
      }
    } catch (error) {
      failures.push(`${adapter.case_id}:${error.message}`);
    }
  }

  for (const testCase of vectors.must_reject) {
    const actualError = evaluateRejection(testCase);
    if (actualError !== testCase.expected_error) {
      failures.push(
        `${testCase.case_id}:expected=${testCase.expected_error}:actual=${actualError}`
      );
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) console.error(`FAIL ${failure}`);
    process.exitCode = 1;
    return;
  }
  console.log("OK portable anchor is identical across Android, Apple, and Windows declarations");
  console.log(`OK host capability manifests (${vectors.adapters.length})`);
  console.log(`OK anti-lock-in rejection cases (${vectors.must_reject.length})`);
  console.log("NOTE Declaration fixtures are not real platform storage certification.");
}

main();

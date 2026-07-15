import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(
  fs.readFileSync(path.join(ROOT, "conformance/instance_identity_vectors.json"), "utf8")
);

const IDENTITY_FIELDS = new Set([
  "schema_version",
  "instance_id",
  "seed_id",
  "seed_root_hash",
  "companion_name",
  "guardian_id",
  "born_at",
  "identity_digest"
]);
const DIGEST_FIELDS = [
  "schema_version",
  "instance_id",
  "seed_id",
  "seed_root_hash",
  "companion_name",
  "guardian_id",
  "born_at"
];
const CONTINUITY_ERRORS = [
  ["instance_id", "instance_id_mismatch"],
  ["seed_id", "seed_id_mismatch"],
  ["seed_root_hash", "seed_root_hash_mismatch"],
  ["companion_name", "canonical_name_mismatch"],
  ["guardian_id", "guardian_id_mismatch"],
  ["born_at", "birth_timestamp_mismatch"]
];

class ConformanceError extends Error {}

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

function validateText(identity) {
  for (const value of Object.values(identity)) {
    if (typeof value === "string" && value !== value.normalize("NFC")) {
      throw new ConformanceError("text_not_nfc");
    }
  }
}

function validateIdentityFields(identity) {
  validateText(identity);
  const fields = Object.keys(identity);
  if (fields.some((field) => !IDENTITY_FIELDS.has(field))) {
    throw new ConformanceError("identity_additional_field");
  }
  if ([...IDENTITY_FIELDS].some((field) => !(field in identity))) {
    throw new ConformanceError("identity_missing_field");
  }
}

function computeIdentityDigest(identity, domain) {
  validateIdentityFields(identity);
  return hashFields(domain, DIGEST_FIELDS.map((field) => identity[field]));
}

function validateBirthIdentity(identity, domain) {
  if (identity.schema_version !== domain) {
    throw new ConformanceError("identity_schema_version_invalid");
  }
  if (computeIdentityDigest(identity, domain) !== identity.identity_digest) {
    throw new ConformanceError("identity_digest_mismatch");
  }
}

function validateContinuity(trustedBirth, candidate, domain) {
  validateBirthIdentity(trustedBirth, domain);
  validateIdentityFields(candidate);
  for (const [field, errorCode] of CONTINUITY_ERRORS) {
    if (candidate[field] !== trustedBirth[field]) throw new ConformanceError(errorCode);
  }
  if (computeIdentityDigest(candidate, domain) !== candidate.identity_digest) {
    throw new ConformanceError("identity_digest_mismatch");
  }
  if (candidate.identity_digest !== trustedBirth.identity_digest) {
    throw new ConformanceError("identity_digest_mismatch");
  }
}

function evaluateRejection(testCase, trustedBirth, domain) {
  const candidate = structuredClone(trustedBirth);
  const mutation = testCase.mutation;
  try {
    if (mutation.additional_field) {
      candidate[mutation.additional_field] = mutation.value;
    } else {
      candidate[mutation.field] = mutation.value;
      if (mutation.recompute_digest) {
        candidate.identity_digest = computeIdentityDigest(candidate, domain);
      }
    }
    validateContinuity(trustedBirth, candidate, domain);
  } catch (error) {
    if (error instanceof ConformanceError) return error.message;
    throw error;
  }
  return null;
}

function setsEqual(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function main() {
  const failures = [];
  const domain = vectors.domain;
  const trustedBirth = vectors.birth_identity;

  if (vectors.profile !== "genesis.instance.identity.v0.1") {
    failures.push("identity_profile_invalid");
  }
  if (domain !== "genesis.instance.identity.v0.1") failures.push("identity_domain_invalid");

  try {
    validateBirthIdentity(trustedBirth, domain);
  } catch (error) {
    failures.push(`birth:${error.message}`);
  }

  const expectedProfiles = new Set(["android-kotlin", "apple-swift", "windows-dotnet"]);
  const actualProfiles = new Set(vectors.continuity_cases.map((entry) => entry.platform_profile));
  if (!setsEqual(expectedProfiles, actualProfiles)) {
    failures.push("identity_fixture_platform_set_invalid");
  }
  for (const testCase of vectors.continuity_cases) {
    try {
      validateContinuity(trustedBirth, testCase.identity, domain);
    } catch (error) {
      failures.push(`${testCase.case_id}:${error.message}`);
    }
  }

  for (const testCase of vectors.must_reject) {
    const actualError = evaluateRejection(testCase, trustedBirth, domain);
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
  console.log("OK canonical birth name and identity digest");
  console.log(
    "OK identical identity across Android, Apple, and Windows declarations "
    + `(${vectors.continuity_cases.length})`
  );
  console.log(`OK immutable identity rejection cases (${vectors.must_reject.length})`);
  console.log("NOTE Draft fixtures do not certify platform secure storage.");
}

main();

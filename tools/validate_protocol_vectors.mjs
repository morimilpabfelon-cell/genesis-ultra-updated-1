import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { argon2id } from "hash-wasm";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

class VectorError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function frame(value) {
  if (typeof value !== "string") throw new VectorError("field_must_be_string");
  if (value !== value.normalize("NFC")) throw new VectorError("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([
    Buffer.from(`${bytes.length}:`, "ascii"),
    bytes,
    Buffer.from("\n", "ascii")
  ]);
}

function hashFields(domain, fields) {
  const preimage = Buffer.concat([frame(domain), ...fields.map((field) => frame(field))]);
  return `sha256:${crypto.createHash("sha256").update(preimage).digest("hex")}`;
}

function optionalText(value) {
  return value === null || value === undefined ? "" : String(value);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function safeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\u0000")) return false;
  if (value !== value.normalize("NFC")) return false;
  if (value.startsWith("/") || value.includes("\\") || /^[A-Za-z]:/.test(value)) return false;
  return !value.split("/").some((segment) => ["", ".", ".."].includes(segment));
}

function computeBodyRegistry(testCase) {
  const data = testCase.input;
  const ids = data.bodies.map((body) => body.body_id);
  if (new Set(ids).size !== ids.length) throw new VectorError("duplicate_body_id");
  if (data.bodies.filter((body) => body.status === "active_writer").length > 1) {
    throw new VectorError("multiple_active_writers");
  }

  const fields = [
    data.schema_version,
    data.instance_id,
    String(data.registry_epoch),
    String(data.bodies.length)
  ];
  for (const body of [...data.bodies].sort((left, right) => compareUtf8(left.body_id, right.body_id))) {
    fields.push(
      body.body_id,
      body.status,
      body.platform_profile,
      body.public_key_fingerprint,
      body.created_at,
      optionalText(body.last_seen_at),
      optionalText(body.revocation_ref)
    );
  }
  fields.push(data.updated_at);
  return hashFields(testCase.domain, fields);
}

function computeContinuityIntent(testCase) {
  const data = testCase.input;
  if (data.decision_origin !== "instance") throw new VectorError("continuity_intent_origin_invalid");
  return hashFields(testCase.domain, [
    data.schema_version,
    data.intent_id,
    data.transfer_id,
    data.instance_id,
    data.source_body_id,
    data.destination_body_id,
    data.checkpoint_hash,
    data.last_event_hash,
    data.decision_origin,
    data.created_at,
    data.expires_at
  ]);
}

function computeHostConsent(testCase) {
  const data = testCase.input;
  if (data.resource_scope !== "destination_body_runtime") throw new VectorError("host_consent_scope_invalid");
  if (data.ownership_claim !== "none" || data.mobility_veto !== "none") {
    throw new VectorError("host_consent_claim_invalid");
  }
  return hashFields(testCase.domain, [
    data.schema_version,
    data.consent_id,
    data.transfer_id,
    data.host_id,
    data.host_key_epoch_id,
    data.instance_id,
    data.destination_body_id,
    data.resource_scope,
    data.granted_at,
    data.expires_at,
    data.ownership_claim,
    data.mobility_veto
  ]);
}

function computeTransferPackage(testCase) {
  const data = testCase.input;
  const paths = data.contents.map((item) => item.path);
  if (new Set(paths).size !== paths.length) throw new VectorError("duplicate_package_path");
  if (paths.some((item) => !safeRelativePath(item))) throw new VectorError("invalid_relative_path");

  const fields = [
    data.schema_version,
    data.transfer_id,
    data.instance_id,
    data.source_body_id,
    optionalText(data.destination_body_id),
    data.mode,
    data.created_at,
    data.checkpoint_hash,
    data.last_event_hash,
    data.continuity_status,
    data.continuity_intent_ref,
    data.host_consent_ref,
    data.destination_possession_ref,
    String(data.contents.length)
  ];
  for (const item of [...data.contents].sort((left, right) => compareUtf8(left.path, right.path))) {
    fields.push(item.kind, item.path, item.digest);
  }
  return hashFields(testCase.domain, fields);
}

function computeTransferReceipt(testCase) {
  const data = testCase.input;
  if (data.continuity_status === "known_gap" && !data.continuity_gap_ref) {
    throw new VectorError("missing_continuity_gap_ref");
  }
  return hashFields(testCase.domain, [
    data.schema_version,
    data.transfer_id,
    data.instance_id,
    data.source_body_id,
    data.destination_body_id,
    data.accepted_package_digest,
    data.accepted_checkpoint_hash,
    data.accepted_last_event_hash,
    String(data.accepted_last_sequence),
    data.accepted_at,
    data.continuity_status,
    optionalText(data.continuity_gap_ref),
    data.continuity_intent_ref,
    data.host_consent_ref,
    data.destination_possession_ref
  ]);
}

function computeTransferFinalization(testCase) {
  const data = testCase.input;
  if (data.destination_final_status !== "active_writer") {
    throw new VectorError("destination_not_active_writer");
  }
  if (!["read_only", "revoked", "lost"].includes(data.source_final_status)) {
    throw new VectorError("invalid_source_final_status");
  }
  if (data.source_body_id === data.destination_body_id) {
    throw new VectorError("source_destination_same_body");
  }
  return hashFields(testCase.domain, [
    data.schema_version,
    data.transfer_id,
    data.instance_id,
    data.source_body_id,
    data.destination_body_id,
    data.receipt_digest,
    data.source_final_status,
    data.destination_final_status,
    data.finalized_at,
    data.continuity_intent_ref,
    data.host_consent_ref,
    data.destination_possession_ref
  ]);
}

function expectDigest(label, actual, expected) {
  if (actual !== expected) {
    throw new VectorError(`${label}:expected=${expected}:actual=${actual}`);
  }
}

function expectError(label, expectedCode, operation) {
  try {
    operation();
  } catch (error) {
    if (error instanceof VectorError && error.code === expectedCode) return;
    throw new VectorError(`${label}:expected_error=${expectedCode}:actual=${error.message}`);
  }
  throw new VectorError(`${label}:expected_error=${expectedCode}:actual=accepted`);
}

function clone(value) {
  return structuredClone(value);
}

function verifyContinuityVectors() {
  const vectors = readJson("conformance/continuity_vectors.json");
  if (vectors.profile !== "genesis.hash.fields.v0.1") {
    throw new VectorError(`continuity_profile_invalid:${vectors.profile}`);
  }

  const intentDigest = computeContinuityIntent(vectors.continuity_intent);
  const consentDigest = computeHostConsent(vectors.host_consent);
  const registryDigest = computeBodyRegistry(vectors.body_registry);
  const packageDigest = computeTransferPackage(vectors.transfer_package);
  const receiptDigest = computeTransferReceipt(vectors.transfer_receipt);
  const finalizationDigest = computeTransferFinalization(vectors.transfer_finalization);
  expectDigest("continuity_intent", intentDigest, vectors.continuity_intent.expected_intent_digest);
  expectDigest("host_consent", consentDigest, vectors.host_consent.expected_consent_digest);
  expectDigest("body_registry", registryDigest, vectors.body_registry.expected_registry_digest);
  expectDigest("transfer_package", packageDigest, vectors.transfer_package.expected_package_digest);
  expectDigest("transfer_receipt", receiptDigest, vectors.transfer_receipt.expected_receipt_digest);
  expectDigest(
    "transfer_finalization",
    finalizationDigest,
    vectors.transfer_finalization.expected_finalization_digest
  );
  if (vectors.transfer_receipt.input.accepted_package_digest !== packageDigest) {
    throw new VectorError("receipt_not_linked_to_computed_package");
  }
  if (vectors.transfer_finalization.input.receipt_digest !== receiptDigest) {
    throw new VectorError("finalization_not_linked_to_computed_receipt");
  }
  for (const artifact of [
    vectors.transfer_package.input,
    vectors.transfer_receipt.input,
    vectors.transfer_finalization.input
  ]) {
    if (artifact.continuity_intent_ref !== vectors.continuity_intent.input.intent_id) {
      throw new VectorError("continuity_intent_ref_mismatch");
    }
    if (artifact.host_consent_ref !== vectors.host_consent.input.consent_id) {
      throw new VectorError("host_consent_ref_mismatch");
    }
  }

  const duplicateBody = clone(vectors.body_registry);
  duplicateBody.input.bodies[1].body_id = duplicateBody.input.bodies[0].body_id;
  expectError("continuity_duplicate_body", "duplicate_body_id", () => computeBodyRegistry(duplicateBody));

  const multipleWriters = clone(vectors.body_registry);
  multipleWriters.input.bodies[1].status = "active_writer";
  expectError("continuity_multiple_writers", "multiple_active_writers", () =>
    computeBodyRegistry(multipleWriters)
  );

  const unsafePackage = clone(vectors.transfer_package);
  unsafePackage.input.contents[0].path = "../memory/events.ndjson";
  expectError("continuity_unsafe_path", "invalid_relative_path", () =>
    computeTransferPackage(unsafePackage)
  );

  const duplicatePackagePath = clone(vectors.transfer_package);
  duplicatePackagePath.input.contents[1].path = duplicatePackagePath.input.contents[0].path;
  expectError("continuity_duplicate_path", "duplicate_package_path", () =>
    computeTransferPackage(duplicatePackagePath)
  );

  const missingGap = clone(vectors.transfer_receipt);
  missingGap.input.continuity_status = "known_gap";
  missingGap.input.continuity_gap_ref = null;
  expectError("continuity_missing_gap", "missing_continuity_gap_ref", () =>
    computeTransferReceipt(missingGap)
  );

  const invalidDestination = clone(vectors.transfer_finalization);
  invalidDestination.input.destination_final_status = "read_only";
  expectError("continuity_destination_writer", "destination_not_active_writer", () =>
    computeTransferFinalization(invalidDestination)
  );

  const invalidSource = clone(vectors.transfer_finalization);
  invalidSource.input.source_final_status = "active_writer";
  expectError("continuity_source_status", "invalid_source_final_status", () =>
    computeTransferFinalization(invalidSource)
  );

  const sameBody = clone(vectors.transfer_finalization);
  sameBody.input.destination_body_id = sameBody.input.source_body_id;
  expectError("continuity_same_body", "source_destination_same_body", () =>
    computeTransferFinalization(sameBody)
  );

  console.log("OK Node continuity digests and links");
  console.log("OK Node continuity corruption cases rejected (8)");
}

function rotateLeft(value, shift) {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 7);
}

function hChaCha20(key, noncePrefix) {
  if (key.length !== 32) throw new VectorError("xchacha_key_length_invalid");
  if (noncePrefix.length !== 16) throw new VectorError("xchacha_nonce_prefix_length_invalid");
  const constants = Buffer.from("expand 32-byte k", "ascii");
  const state = new Uint32Array(16);
  for (let index = 0; index < 4; index += 1) state[index] = constants.readUInt32LE(index * 4);
  for (let index = 0; index < 8; index += 1) state[index + 4] = key.readUInt32LE(index * 4);
  for (let index = 0; index < 4; index += 1) state[index + 12] = noncePrefix.readUInt32LE(index * 4);

  for (let round = 0; round < 10; round += 1) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }

  const output = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((word, index) => {
    output.writeUInt32LE(state[word], index * 4);
  });
  return output;
}

function xChaChaParameters(key, nonce) {
  if (nonce.length !== 24) throw new VectorError("xchacha_nonce_length_invalid");
  return {
    subkey: hChaCha20(key, nonce.subarray(0, 16)),
    nonce: Buffer.concat([Buffer.alloc(4), nonce.subarray(16, 24)])
  };
}

function xChaChaEncrypt(plaintext, aad, nonce, key) {
  const parameters = xChaChaParameters(key, nonce);
  const cipher = crypto.createCipheriv("chacha20-poly1305", parameters.subkey, parameters.nonce, {
    authTagLength: 16
  });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

function xChaChaDecrypt(ciphertextWithTag, aad, nonce, key) {
  if (ciphertextWithTag.length < 16) throw new VectorError("xchacha_ciphertext_too_short");
  const parameters = xChaChaParameters(key, nonce);
  const ciphertext = ciphertextWithTag.subarray(0, -16);
  const tag = ciphertextWithTag.subarray(-16);
  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305",
    parameters.subkey,
    parameters.nonce,
    { authTagLength: 16 }
  );
  decipher.setAuthTag(tag);
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function ed25519PrivateKeyFromSeed(seed) {
  if (seed.length !== 32) throw new VectorError("ed25519_seed_length_invalid");
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8"
  });
}

function rawEd25519PublicKey(key) {
  const exported = crypto.createPublicKey(key).export({ format: "der", type: "spki" });
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  if (!exported.subarray(0, spkiPrefix.length).equals(spkiPrefix)) {
    throw new VectorError("ed25519_public_key_encoding_invalid");
  }
  return exported.subarray(spkiPrefix.length);
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

async function verifyCryptoVectors() {
  const vectors = readJson("conformance/crypto_vectors.json");
  if (vectors.profile !== "genesis.crypto.digests.v0.1") {
    throw new VectorError(`crypto_profile_invalid:${vectors.profile}`);
  }

  for (const vector of vectors.vectors) {
    if (
      vector.case_id.startsWith("key-epoch")
      && (vector.domain !== "genesis.key.epoch.v0.1" || vector.fields.length !== 10)
    ) {
      throw new VectorError(`${vector.case_id}:key_epoch_preimage_must_bind_all_10_fields`);
    }
    expectDigest(vector.case_id, hashFields(vector.domain, vector.fields), vector.expected_digest);
  }
  console.log(`OK Node protocol and possession digests (${vectors.vectors.length})`);

  const ed = vectors.algorithms.ed25519;
  const edMessage = signatureEnvelopeBytes(ed.envelope);
  const privateKey = ed25519PrivateKeyFromSeed(Buffer.from(ed.seed_hex, "hex"));
  const publicKey = crypto.createPublicKey(privateKey);
  const expectedPublicKey = Buffer.from(ed.public_key_hex, "hex");
  if (!rawEd25519PublicKey(privateKey).equals(expectedPublicKey)) {
    throw new VectorError("ed25519_public_key_mismatch");
  }
  const expectedKeyRef = `sha256:${crypto
    .createHash("sha256")
    .update(expectedPublicKey)
    .digest("hex")}`;
  if (ed.envelope.public_key_ref !== expectedKeyRef) {
    throw new VectorError("ed25519_public_key_ref_mismatch");
  }
  const expectedSignature = Buffer.from(ed.envelope.signature_value, "hex");
  const generatedSignature = crypto.sign(null, edMessage, privateKey);
  if (!generatedSignature.equals(expectedSignature)) throw new VectorError("ed25519_signature_mismatch");
  if (!crypto.verify(null, edMessage, publicKey, expectedSignature)) {
    throw new VectorError("ed25519_signature_rejected");
  }
  if (ed.corruption.flip_first_signature_byte_must_fail !== true) {
    throw new VectorError("ed25519_corruption_requirement_missing");
  }
  const changedSignature = Buffer.from(expectedSignature);
  changedSignature[0] ^= 1;
  if (crypto.verify(null, edMessage, publicKey, changedSignature)) {
    throw new VectorError("ed25519_corrupted_signature_accepted");
  }
  const changedMessage = Buffer.from(edMessage);
  changedMessage[changedMessage.length - 1] ^= 1;
  if (crypto.verify(null, changedMessage, publicKey, expectedSignature)) {
    throw new VectorError("ed25519_corrupted_message_accepted");
  }
  if (ed.corruption.mutate_created_at_must_fail !== true) {
    throw new VectorError("ed25519_metadata_corruption_requirement_missing");
  }
  const changedEnvelope = structuredClone(ed.envelope);
  changedEnvelope.created_at = "2026-07-15T02:30:01Z";
  if (crypto.verify(null, signatureEnvelopeBytes(changedEnvelope), publicKey, expectedSignature)) {
    throw new VectorError("ed25519_mutated_envelope_metadata_accepted");
  }
  console.log("OK Node Ed25519 generation, verification, and corruption rejection");

  const xc = vectors.algorithms.xchacha20poly1305_ietf;
  const key = Buffer.from(xc.key_hex, "hex");
  const nonce = Buffer.from(xc.nonce_hex, "hex");
  const aad = Buffer.from(xc.aad_utf8, "utf8");
  const plaintext = Buffer.from(xc.plaintext_utf8, "utf8");
  const expectedCiphertext = Buffer.from(xc.ciphertext_with_tag_hex, "hex");
  const actualCiphertext = xChaChaEncrypt(plaintext, aad, nonce, key);
  if (!actualCiphertext.equals(expectedCiphertext)) throw new VectorError("xchacha_ciphertext_mismatch");
  if (!xChaChaDecrypt(expectedCiphertext, aad, nonce, key).equals(plaintext)) {
    throw new VectorError("xchacha_plaintext_mismatch");
  }
  if (xc.corruption.flip_first_ciphertext_byte_must_fail !== true) {
    throw new VectorError("xchacha_corruption_requirement_missing");
  }
  const changedCiphertext = Buffer.from(expectedCiphertext);
  changedCiphertext[0] ^= 1;
  let ciphertextRejected = false;
  try {
    xChaChaDecrypt(changedCiphertext, aad, nonce, key);
  } catch {
    ciphertextRejected = true;
  }
  if (!ciphertextRejected) throw new VectorError("xchacha_corrupted_ciphertext_accepted");
  const changedAad = Buffer.concat([aad, Buffer.from("!", "ascii")]);
  let aadRejected = false;
  try {
    xChaChaDecrypt(expectedCiphertext, changedAad, nonce, key);
  } catch {
    aadRejected = true;
  }
  if (!aadRejected) throw new VectorError("xchacha_corrupted_aad_accepted");
  console.log("OK Node XChaCha20-Poly1305 encryption and corruption rejection");

  const kd = vectors.algorithms.argon2id;
  if (kd.memlimit % 1024 !== 0) throw new VectorError("argon2id_memlimit_not_whole_kibibytes");
  const parameters = {
    password: Buffer.from(kd.password_utf8, "utf8"),
    salt: Buffer.from(kd.salt_hex, "hex"),
    parallelism: 1,
    iterations: kd.opslimit,
    memorySize: kd.memlimit / 1024,
    hashLength: kd.derived_key_len,
    outputType: "hex"
  };
  const derivedKey = await argon2id(parameters);
  if (derivedKey !== kd.derived_key_hex) throw new VectorError("argon2id_derived_key_mismatch");
  const changedPasswordKey = await argon2id({
    ...parameters,
    password: Buffer.from(`${kd.password_utf8}!`, "utf8")
  });
  if (changedPasswordKey === derivedKey) throw new VectorError("argon2id_password_change_not_detected");
  console.log("OK Node Argon2id derivation and changed-password divergence");
}

async function main() {
  verifyContinuityVectors();
  await verifyCryptoVectors();
  console.log("OK Node independently reproduces all shared protocol vectors");
  console.log("NOTE Reference conformance check; not a production security certification.");
}

main().catch((error) => {
  console.error(`FAIL Node protocol vectors: ${error.message}`);
  process.exitCode = 1;
});

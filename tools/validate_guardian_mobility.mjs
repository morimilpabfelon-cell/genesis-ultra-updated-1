#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = path.join(ROOT, "conformance", "guardian_mobility_vectors.json");
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const SHA_RE = /^sha256:[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

export const AUTHORIZATION_DOMAIN = "genesis.guardian.mobility.authorization.v0.2";
export const AUTHORIZATION_SIGNATURE_DOMAIN = "genesis.guardian.mobility.authorization.signature.v0.2";
export const EVENT_DOMAIN = "genesis.guardian.mobility.authority.event.v0.2";
export const EVENT_SIGNATURE_DOMAIN = "genesis.guardian.mobility.authority.event.signature.v0.2";
const ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1";

const SIGNATURE_FIELDS = new Set([
  "schema_version", "signature_profile", "signer_type", "signer_id",
  "key_epoch_id", "signed_domain", "signed_digest", "signature_value",
  "created_at", "public_key_ref",
]);
const AUTHORIZATION_FIELDS = new Set([
  "schema_version", "hash_profile", "authorization_id", "instance_id",
  "guardian_id", "guardian_key_epoch_id", "authority_epoch", "mode", "scope",
  "transfer_id", "source_body_id", "destination_body_id", "valid_from", "expires_at",
  "issued_at", "reservation_ttl_seconds", "ownership_conferred",
  "identity_mutation_allowed", "memory_mutation_allowed", "authorization_digest", "signature",
]);
const EVENT_FIELDS = new Set([
  "schema_version", "event_id", "authorization_id", "authorization_digest",
  "instance_id", "authority_epoch", "sequence", "previous_event_digest", "event_type",
  "transfer_id", "source_body_id", "destination_body_id", "reservation_expires_at",
  "occurred_at", "event_digest", "signature",
]);
const REQUEST_FIELDS = new Set([
  "authorization_id", "reservation_event_id", "transfer_id", "instance_id",
  "source_body_id", "destination_body_id", "authority_epoch", "prepared_at",
  "finalized_at", "host_consent_verified",
]);

export class MobilityError extends Error {}
function fail(code) { throw new MobilityError(code); }
function exactFields(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const keys = Object.keys(value);
  if (keys.length !== expected.size || !keys.every((key) => expected.has(key))) fail(code);
  return value;
}
function frame(value) {
  if (typeof value !== "string") fail("field_must_be_string");
  if (value.normalize("NFC") !== value) fail("text_not_nfc");
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes, Buffer.from("\n", "ascii")]);
}
function hashFields(domain, fields) {
  return `sha256:${crypto.createHash("sha256").update(Buffer.concat([frame(domain), ...fields.map(frame)])).digest("hex")}`;
}
function optionalText(value) { return value === null ? "" : String(value); }
function boolText(value) { return value ? "true" : "false"; }
function parseTime(value, code) {
  if (typeof value !== "string" || !TS_RE.test(value)) fail(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(code);
  return parsed;
}
function signatureBytes(envelope) {
  return Buffer.concat([
    frame(ENVELOPE_DOMAIN),
    ...[
      "schema_version", "signature_profile", "signer_type", "signer_id",
      "key_epoch_id", "signed_domain", "signed_digest", "created_at", "public_key_ref",
    ].map((field) => frame(envelope[field])),
  ]);
}
function publicKeyFromRaw(rawHex) {
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawHex, "hex")]),
    format: "der",
    type: "spki",
  });
}
function rawPublicKey(key) {
  const der = key.export({ format: "der", type: "spki" });
  return der.subarray(-32);
}
function resolvePublicKey(value) {
  if (typeof value === "string") return publicKeyFromRaw(value);
  if (Buffer.isBuffer(value)) return publicKeyFromRaw(value.toString("hex"));
  return value;
}
function verifySignature(envelope, publicKeys, expected, error) {
  exactFields(envelope, SIGNATURE_FIELDS, error);
  const fields = {
    schema_version: "genesis.signature.envelope.v0.1",
    signature_profile: "genesis.signature.ed25519.v0.1",
    signer_type: expected.signerType,
    signer_id: expected.signerId,
    key_epoch_id: expected.keyEpochId,
    signed_domain: expected.domain,
    signed_digest: expected.digest,
    created_at: expected.createdAt,
  };
  if (Object.entries(fields).some(([field, value]) => envelope[field] !== value)) fail(error);
  const stored = publicKeys.get(envelope.public_key_ref);
  if (!stored || !HEX128_RE.test(envelope.signature_value)) fail(error);
  const key = resolvePublicKey(stored);
  const fingerprint = `sha256:${crypto.createHash("sha256").update(rawPublicKey(key)).digest("hex")}`;
  if (fingerprint !== envelope.public_key_ref) fail(error);
  if (!crypto.verify(null, signatureBytes(envelope), key, Buffer.from(envelope.signature_value, "hex"))) fail(error);
}

export function computeAuthorizationDigest(item) {
  return hashFields(AUTHORIZATION_DOMAIN, [
    item.schema_version, item.hash_profile, item.authorization_id, item.instance_id,
    item.guardian_id, item.guardian_key_epoch_id, String(item.authority_epoch), item.mode,
    item.scope, optionalText(item.transfer_id), optionalText(item.source_body_id),
    optionalText(item.destination_body_id), item.valid_from, item.expires_at, item.issued_at,
    String(item.reservation_ttl_seconds), boolText(item.ownership_conferred),
    boolText(item.identity_mutation_allowed), boolText(item.memory_mutation_allowed),
  ]);
}

export function computeAuthorityEventDigest(item) {
  return hashFields(EVENT_DOMAIN, [
    item.schema_version, item.event_id, item.authorization_id, item.authorization_digest,
    item.instance_id, String(item.authority_epoch), String(item.sequence),
    item.previous_event_digest, item.event_type, optionalText(item.transfer_id),
    optionalText(item.source_body_id), optionalText(item.destination_body_id),
    optionalText(item.reservation_expires_at), item.occurred_at,
  ]);
}

export function validateAuthorization(item, publicKeys) {
  if (item === null || item === undefined) fail("guardian_authorization_missing");
  const authorization = exactFields(item, AUTHORIZATION_FIELDS, "guardian_authorization_fields_invalid");
  if (authorization.schema_version !== "genesis.guardian.mobility.authorization.v0.2" || authorization.hash_profile !== "genesis.hash.fields.v0.1") {
    fail("guardian_authorization_profile_invalid");
  }
  if (!Number.isSafeInteger(authorization.authority_epoch) || authorization.authority_epoch < 0) fail("guardian_authority_epoch_invalid");
  if (!Number.isSafeInteger(authorization.reservation_ttl_seconds) || authorization.reservation_ttl_seconds < 60 || authorization.reservation_ttl_seconds > 86400) {
    fail("guardian_reservation_ttl_invalid");
  }
  const issued = parseTime(authorization.issued_at, "guardian_authorization_time_invalid");
  const validFrom = parseTime(authorization.valid_from, "guardian_authorization_time_invalid");
  const expires = parseTime(authorization.expires_at, "guardian_authorization_time_invalid");
  if (issued > validFrom || validFrom >= expires) fail("guardian_authorization_window_invalid");
  if (authorization.ownership_conferred !== false || authorization.identity_mutation_allowed !== false || authorization.memory_mutation_allowed !== false) {
    fail("guardian_authorization_rights_boundary_invalid");
  }
  if (authorization.mode === "one_time") {
    if (authorization.scope !== "exact_transfer" || ["transfer_id", "source_body_id", "destination_body_id"].some((field) => typeof authorization[field] !== "string")) {
      fail("guardian_authorization_mode_scope_invalid");
    }
  } else if (authorization.mode === "standing") {
    if (authorization.scope !== "any_registered_body_with_host_consent" || ["transfer_id", "source_body_id", "destination_body_id"].some((field) => authorization[field] !== null)) {
      fail("guardian_authorization_mode_scope_invalid");
    }
  } else {
    fail("guardian_authorization_mode_scope_invalid");
  }
  if (!SHA_RE.test(authorization.authorization_digest)) fail("guardian_authorization_digest_invalid");
  if (computeAuthorizationDigest(authorization) !== authorization.authorization_digest) fail("guardian_authorization_digest_mismatch");
  verifySignature(authorization.signature, publicKeys, {
    digest: authorization.authorization_digest,
    signerType: "guardian",
    signerId: authorization.guardian_id,
    keyEpochId: authorization.guardian_key_epoch_id,
    domain: AUTHORIZATION_SIGNATURE_DOMAIN,
    createdAt: authorization.issued_at,
  }, "guardian_authorization_signature_invalid");
  return authorization;
}

export function validateEventChain(events, authorization, publicKeys) {
  if (!Array.isArray(events)) fail("guardian_authority_events_invalid");
  let previous = "GENESIS";
  const eventIds = new Set();
  const reservationTransfers = new Set();
  return events.map((rawEvent, sequence) => {
    const event = exactFields(rawEvent, EVENT_FIELDS, "guardian_authority_event_fields_invalid");
    if (event.schema_version !== "genesis.guardian.mobility.authority.event.v0.2") fail("guardian_authority_event_profile_invalid");
    if (eventIds.has(event.event_id)) fail("guardian_authority_event_duplicate");
    eventIds.add(event.event_id);
    if (event.sequence !== sequence || event.previous_event_digest !== previous) fail("guardian_authority_event_chain_invalid");
    if (
      event.authorization_id !== authorization.authorization_id
      || event.authorization_digest !== authorization.authorization_digest
      || event.instance_id !== authorization.instance_id
      || event.authority_epoch !== authorization.authority_epoch
    ) fail("guardian_authority_event_binding_invalid");
    parseTime(event.occurred_at, "guardian_authority_event_time_invalid");
    let signerType;
    let signerId;
    if (["reserved", "consumed"].includes(event.event_type)) {
      if (["transfer_id", "source_body_id", "destination_body_id"].some((field) => typeof event[field] !== "string")) fail("guardian_authority_event_scope_invalid");
      if (event.event_type === "reserved") {
        if (typeof event.reservation_expires_at !== "string") fail("guardian_authority_event_scope_invalid");
        parseTime(event.reservation_expires_at, "guardian_authority_event_time_invalid");
        if (reservationTransfers.has(event.transfer_id)) fail("guardian_authorization_replay");
        reservationTransfers.add(event.transfer_id);
        signerType = "body";
        signerId = event.source_body_id;
      } else {
        if (event.reservation_expires_at !== null) fail("guardian_authority_event_scope_invalid");
        signerType = "body";
        signerId = event.destination_body_id;
      }
    } else if (event.event_type === "revoked") {
      if (["transfer_id", "source_body_id", "destination_body_id", "reservation_expires_at"].some((field) => event[field] !== null)) fail("guardian_authority_event_scope_invalid");
      signerType = "guardian";
      signerId = authorization.guardian_id;
    } else {
      fail("guardian_authority_event_type_invalid");
    }
    if (!SHA_RE.test(event.event_digest) || computeAuthorityEventDigest(event) !== event.event_digest) fail("guardian_authority_event_digest_mismatch");
    const expectedEpoch = signerType === "guardian" ? authorization.guardian_key_epoch_id : event.signature?.key_epoch_id;
    verifySignature(event.signature, publicKeys, {
      digest: event.event_digest,
      signerType,
      signerId,
      keyEpochId: expectedEpoch,
      domain: EVENT_SIGNATURE_DOMAIN,
      createdAt: event.occurred_at,
    }, "guardian_authority_event_signature_invalid");
    previous = event.event_digest;
    return event;
  });
}

export function validateTransferAuthorization(authorization, events, request, publicKeys) {
  const grant = validateAuthorization(authorization, publicKeys);
  exactFields(request, REQUEST_FIELDS, "guardian_mobility_request_fields_invalid");
  if (request.authorization_id !== grant.authorization_id || request.instance_id !== grant.instance_id) fail("guardian_authorization_instance_mismatch");
  if (request.authority_epoch !== grant.authority_epoch) fail("guardian_authority_epoch_mismatch");
  const prepared = parseTime(request.prepared_at, "guardian_mobility_request_time_invalid");
  const finalized = parseTime(request.finalized_at, "guardian_mobility_request_time_invalid");
  if (finalized < prepared) fail("guardian_mobility_request_time_invalid");
  if (!(parseTime(grant.valid_from, "guardian_authorization_time_invalid") <= prepared && prepared < parseTime(grant.expires_at, "guardian_authorization_time_invalid"))) {
    fail("guardian_authorization_expired");
  }
  if (request.host_consent_verified !== true) fail("guardian_host_consent_required");
  if (grant.mode === "one_time" && ["transfer_id", "source_body_id", "destination_body_id"].some((field) => request[field] !== grant[field])) {
    fail("guardian_authorization_scope_mismatch");
  }
  const ledger = validateEventChain(events, grant, publicKeys);
  const revocations = ledger.filter((event) => event.event_type === "revoked");
  if (revocations.some((event) => parseTime(event.occurred_at, "guardian_authority_event_time_invalid") <= prepared)) fail("guardian_authorization_revoked");
  const reservations = ledger.filter((event) =>
    event.event_type === "reserved"
    && event.event_id === request.reservation_event_id
    && ["transfer_id", "source_body_id", "destination_body_id"].every((field) => event[field] === request[field])
  );
  if (reservations.length !== 1) fail("guardian_authorization_reservation_missing");
  const reservation = reservations[0];
  const reservedAt = parseTime(reservation.occurred_at, "guardian_authority_event_time_invalid");
  const reservationExpires = parseTime(reservation.reservation_expires_at, "guardian_authority_event_time_invalid");
  if (reservedAt > prepared || reservationExpires <= reservedAt) fail("guardian_authorization_reservation_window_invalid");
  if ((reservationExpires - reservedAt) / 1000 > grant.reservation_ttl_seconds) fail("guardian_authorization_reservation_window_invalid");
  if (reservationExpires > parseTime(grant.expires_at, "guardian_authorization_time_invalid")) fail("guardian_authorization_reservation_window_invalid");
  if (revocations.some((event) => parseTime(event.occurred_at, "guardian_authority_event_time_invalid") <= reservedAt)) fail("guardian_authorization_revoked");
  if (finalized > reservationExpires) fail("guardian_authorization_reservation_expired");
  const consumptions = ledger.filter((event) =>
    event.event_type === "consumed"
    && ["transfer_id", "source_body_id", "destination_body_id"].every((field) => event[field] === request[field])
  );
  if (consumptions.length !== 1) fail("guardian_authorization_consumption_missing");
  const consumedAt = parseTime(consumptions[0].occurred_at, "guardian_authority_event_time_invalid");
  if (!(finalized <= consumedAt && consumedAt <= reservationExpires)) fail("guardian_authorization_consumption_time_invalid");
  if (grant.mode === "one_time" && (
    ledger.filter((event) => event.event_type === "reserved").length !== 1
    || ledger.filter((event) => event.event_type === "consumed").length !== 1
  )) fail("guardian_authorization_one_time_already_used");
  return {
    authorization_id: grant.authorization_id,
    authorization_digest: grant.authorization_digest,
    reservation_event_id: reservation.event_id,
    reservation_event_digest: reservation.event_digest,
    mode: grant.mode,
    transfer_id: request.transfer_id,
  };
}

export function validateVector(vector) {
  if (vector.profile !== "genesis.guardian.mobility.conformance.v0.2") fail("guardian_mobility_vector_profile_invalid");
  const publicKeys = new Map(Object.entries(vector.test_public_keys).map(([ref, raw]) => [ref, publicKeyFromRaw(raw)]));
  for (const testCase of vector.positive_cases) {
    validateTransferAuthorization(testCase.authorization, testCase.events, testCase.request, publicKeys);
  }
  for (const testCase of vector.negative_cases) {
    let actual = null;
    try {
      validateTransferAuthorization(testCase.authorization, testCase.events, testCase.request, publicKeys);
    } catch (error) {
      if (!(error instanceof MobilityError)) throw error;
      actual = error.message;
    }
    if (actual !== testCase.expected_error) {
      fail(`guardian_mobility_negative_mismatch:${testCase.case_id}:expected=${testCase.expected_error}:actual=${actual}`);
    }
  }
  const expected = vector.expected;
  if (
    expected.positive_case_count !== vector.positive_cases.length
    || expected.negative_case_count !== vector.negative_cases.length
    || expected.one_time_authorization_digest !== vector.positive_cases[0].authorization.authorization_digest
    || expected.standing_authorization_digest !== vector.positive_cases[1].authorization.authorization_digest
  ) fail("guardian_mobility_expected_summary_invalid");
}

function main() {
  const vector = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
  validateVector(vector);
  console.log(`OK Guardian mobility authorizations independently (${vector.expected.positive_case_count} modes)`);
  console.log(`OK Guardian mobility negative cases independently (${vector.expected.negative_case_count})`);
  console.log("NOTE mobility authorization never grants ownership or identity/memory mutation.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(`FAIL Guardian mobility: ${error.message}`);
    process.exit(1);
  }
}

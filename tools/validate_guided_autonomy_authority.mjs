import crypto from "node:crypto";
import { validateDocument } from "./guided_autonomy.mjs";

const MARK = Symbol("validated-guided-autonomy-authority");
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const USE_FIELDS = new Set(["schema_version", "hash_profile", "use_id", "grant_ref", "instance_id", "body_id", "capability", "target_ref", "action_class", "data_class", "requested_actions", "requested_duration_seconds", "requested_bytes", "sandboxed", "human_confirmation_ref", "observer_ref", "reversible_plan_ref", "requested_at", "use_digest", "signature"]);
const SIGNATURE_FIELDS = new Set(["schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"]);

export class AuthorityError extends Error {}
const fail = (code) => { throw new AuthorityError(code); };
const optional = (value) => value === null || value === undefined ? "" : String(value);
const boolText = (value) => value ? "true" : "false";

function encode(value) {
  if (typeof value !== "string" || value.normalize("NFC") !== value) fail("authority_text_invalid");
  const raw = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${raw.length}:`, "ascii"), raw, Buffer.from("\n")]);
}
export function hashAuthorityFields(domain, fields) {
  return `sha256:${crypto.createHash("sha256").update(Buffer.concat([encode(domain), ...fields.map(encode)])).digest("hex")}`;
}
function exact(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const keys = Object.keys(value);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) fail(code);
}
function parseUtc(value) {
  if (typeof value !== "string" || !TS_RE.test(value)) fail("authority_timestamp_invalid");
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) fail("authority_timestamp_invalid");
  return parsed;
}
function signatureBytes(envelope) {
  exact(envelope, SIGNATURE_FIELDS, "signature_fields_invalid");
  const values = [envelope.schema_version, envelope.signature_profile, envelope.signer_type, envelope.signer_id, envelope.key_epoch_id, envelope.signed_domain, envelope.signed_digest, envelope.created_at, envelope.public_key_ref];
  return Buffer.concat([encode("genesis.signature.envelope.bytes.v0.1"), ...values.map(encode)]);
}
function publicKeyFromRaw(hex) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({ key: Buffer.concat([prefix, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}
function privateKeyFromSeed(hex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(hex, "hex")]), format: "der", type: "pkcs8" });
}
export function signFixtureEnvelope(key, signerType, signerId, digest, domain, createdAt) {
  const envelope = { schema_version: "genesis.signature.envelope.v0.1", signature_profile: "genesis.signature.ed25519.v0.1", signer_type: signerType, signer_id: signerId, key_epoch_id: key.key_epoch_id, signed_domain: domain, signed_digest: digest, signature_value: "", created_at: createdAt, public_key_ref: key.public_key_fingerprint };
  envelope.signature_value = crypto.sign(null, signatureBytes(envelope), privateKeyFromSeed(key.seed_hex)).toString("hex");
  return envelope;
}
export function verifyEnvelope(envelope, key, { digest, domain, signerType, signerId, createdAt, prefix }) {
  exact(envelope, SIGNATURE_FIELDS, `${prefix}_signature_fields_invalid`);
  if (envelope.schema_version !== "genesis.signature.envelope.v0.1" || envelope.signature_profile !== "genesis.signature.ed25519.v0.1") fail(`${prefix}_signature_profile_invalid`);
  if (envelope.signer_type !== signerType || envelope.signer_id !== signerId || envelope.key_epoch_id !== key.key_epoch_id) fail(`${prefix}_signer_invalid`);
  if (envelope.signed_domain !== domain || envelope.signed_digest !== digest || envelope.created_at !== createdAt || envelope.public_key_ref !== key.public_key_fingerprint) fail(`${prefix}_binding_invalid`);
  const signature = Buffer.from(envelope.signature_value, "hex");
  if (signature.length !== 64 || !crypto.verify(null, signatureBytes(envelope), publicKeyFromRaw(key.public_key_hex), signature)) fail(`${prefix}_signature_invalid`);
}

export function authorityFromValidatedFixture(document) {
  validateDocument(structuredClone(document));
  const grants = new Map(document.grants.map((grant) => [grant.grant_id, grant]));
  if (grants.size !== document.grants.length) fail("grant_id_duplicate");
  return Object.freeze({ [MARK]: true, document, grants, registered: new Set(document.registered_body_ids) });
}
function requireAuthority(authority) { if (!authority || authority[MARK] !== true) fail("authority_not_validated"); }
function stateAt(grant, events, at) {
  let status = "not_issued";
  const consumed = new Set();
  let headRef = null;
  let headHash = "GENESIS";
  for (const event of events) {
    if (parseUtc(event.recorded_at) > at) break;
    headRef = event.event_id; headHash = event.event_hash;
    if (event.grant_ref !== grant.grant_id) continue;
    if (event.event_type === "grant.issued") status = "active";
    else if (event.event_type === "grant.suspended") status = "suspended";
    else if (event.event_type === "grant.resumed") status = "active";
    else if (event.event_type === "grant.revoked") status = "revoked";
    else if (event.event_type === "grant.consumed") consumed.add(event.use_id);
  }
  if (grant.use_limit !== null && consumed.size >= grant.use_limit && status === "active") status = "exhausted";
  return { status, consumed, head_ref: headRef, head_hash: headHash };
}
export function resolveExactGrant(grantRef, capability, instanceId, atValue, authority) {
  requireAuthority(authority);
  const grant = authority.grants.get(grantRef);
  if (!grant) return { grant: null, state: null, reason: "grant_missing" };
  if (grant.instance_id !== instanceId) return { grant, state: null, reason: "grant_instance_mismatch" };
  if (grant.capability !== capability) return { grant, state: null, reason: "grant_capability_mismatch" };
  const at = parseUtc(atValue);
  const state = stateAt(grant, authority.document.ledger_events, at);
  let reason = "allowed";
  if (at < parseUtc(grant.not_before)) reason = "grant_not_yet_valid";
  else if (grant.expires_at !== null && at >= parseUtc(grant.expires_at)) reason = "grant_expired";
  else if (state.status !== "active") reason = `grant_${state.status}`;
  return { grant, state, reason };
}
function envelopeReason(request, grant, authority) {
  if (grant.body_scope === "specific_bodies" && !grant.body_ids.includes(request.body_id)) return "body_not_authorized";
  if (grant.body_scope === "registered_guardian_devices" && !authority.registered.has(request.body_id)) return "body_not_authorized";
  if (!grant.scope.allowed_target_refs.includes(request.target_ref)) return "target_not_authorized";
  if (!grant.scope.allowed_action_classes.includes(request.action_class)) return "action_not_authorized";
  if (!grant.scope.allowed_data_classes.includes(request.data_class)) return "data_class_not_authorized";
  if (request.requested_actions > grant.budget.max_actions_per_run) return "action_budget_exceeded";
  if (request.requested_duration_seconds > grant.budget.max_duration_seconds) return "duration_budget_exceeded";
  if (request.requested_bytes > grant.budget.max_bytes_per_run) return "byte_budget_exceeded";
  if (grant.controls.sandbox_required && !request.sandboxed) return "sandbox_required";
  if (grant.controls.human_confirmation_required && request.human_confirmation_ref === null) return "human_confirmation_required";
  if (grant.controls.observer_required && request.observer_ref === null) return "observer_required";
  if (grant.controls.reversible_required && request.reversible_plan_ref === null) return "reversibility_required";
  return "allowed";
}
export function computeAuthorizedUseDigest(item) {
  return hashAuthorityFields("genesis.autonomy.capability.use.v0.2", [item.schema_version, item.hash_profile, item.use_id, item.grant_ref, item.instance_id, item.body_id, item.capability, item.target_ref, item.action_class, item.data_class, String(item.requested_actions), String(item.requested_duration_seconds), String(item.requested_bytes), boolText(item.sandboxed), optional(item.human_confirmation_ref), optional(item.observer_ref), optional(item.reversible_plan_ref), item.requested_at]);
}
export function evaluateAuthorizedUse(item, authority) {
  requireAuthority(authority); exact(item, USE_FIELDS, "authorized_use_fields_invalid");
  if (item.schema_version !== "genesis.autonomy.capability.use.v0.2" || item.hash_profile !== "genesis.hash.fields.v0.1") fail("authorized_use_profile_invalid");
  const digest = computeAuthorizedUseDigest(item);
  if (item.use_digest !== digest) fail("authorized_use_digest_mismatch");
  verifyEnvelope(item.signature, authority.document.keys.body, { digest, domain: "genesis.autonomy.capability.use.signature.v0.2", signerType: "body", signerId: item.body_id, createdAt: item.requested_at, prefix: "authorized_use" });
  const resolved = resolveExactGrant(item.grant_ref, item.capability, item.instance_id, item.requested_at, authority);
  let reason = resolved.reason;
  if (reason === "allowed") reason = resolved.state.consumed.has(item.use_id) ? "use_already_consumed" : envelopeReason(item, resolved.grant, authority);
  const remaining = resolved.grant?.use_limit === null || !resolved.grant ? null : Math.max(0, resolved.grant.use_limit - (resolved.state?.consumed.size ?? 0) - (reason === "allowed" ? 1 : 0));
  const status = reason === "allowed" ? "allowed" : "denied";
  return { use_id: item.use_id, status, reason, grant_ref: item.grant_ref, remaining_uses: remaining, decision_digest: hashAuthorityFields("genesis.autonomy.capability.use.decision.v0.2", [item.use_id, item.use_digest, item.grant_ref, status, reason, optional(remaining)]) };
}
export function authorizeCampaignOpening(request, authority) {
  requireAuthority(authority);
  const resolved = resolveExactGrant(request.grant_ref, request.capability, request.instance_id, request.authorized_at, authority);
  let reason = resolved.reason;
  if (reason === "allowed") reason = envelopeReason(request, resolved.grant, authority);
  const status = reason === "allowed" ? "allowed" : "denied";
  const requestDigest = hashAuthorityFields("genesis.improvement.campaign.authority.request.v0.1", [request.campaign_digest, request.grant_ref, request.instance_id, request.body_id, request.capability, request.target_ref, request.action_class, request.data_class, String(request.requested_actions), String(request.requested_duration_seconds), String(request.requested_bytes), boolText(request.sandboxed), optional(request.human_confirmation_ref), optional(request.observer_ref), optional(request.reversible_plan_ref), request.authorized_at]);
  const grantDigest = resolved.grant?.grant_digest ?? "";
  const state = resolved.state;
  const digest = hashAuthorityFields("genesis.improvement.campaign.authorization.v0.1", [request.campaign_digest, request.grant_ref, grantDigest, String(authority.document.authority_epoch), authority.document.ledger_events[0].ledger_id, optional(state?.head_ref), state?.head_hash ?? "GENESIS", request.authorized_at, status, reason, requestDigest, authority.document.keys.guardian.key_epoch_id, request.body_id]);
  return { decision_status: status, decision_reason: reason, grant_ref: request.grant_ref, grant_digest: grantDigest || null, authority_request_digest: requestDigest, campaign_authorization_digest: digest, ledger_head_event_ref: state?.head_ref ?? null, ledger_head_hash: state?.head_hash ?? "GENESIS" };
}

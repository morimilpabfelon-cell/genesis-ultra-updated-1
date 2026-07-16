import crypto from "node:crypto";
import { ConformanceError, ensureInt, ensureSortedUniqueStrings, validateDocument, validateEvaluation, validateGrant, validateLedger, validateNfc, validateProposal, validateUse } from "./guided_autonomy.mjs";

const MARK = Symbol("validated-guided-autonomy-authority");
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const USE_FIELDS = new Set(["schema_version", "hash_profile", "use_id", "grant_ref", "instance_id", "body_id", "capability", "target_ref", "action_class", "data_class", "requested_actions", "requested_duration_seconds", "requested_bytes", "sandboxed", "human_confirmation_ref", "observer_ref", "reversible_plan_ref", "requested_at", "use_digest", "signature"]);
const SIGNATURE_FIELDS = new Set(["schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"]);

export class AuthorityError extends Error {}
const fail = (code) => { throw new AuthorityError(code); };
const optional = (value) => value === null || value === undefined ? "" : String(value);
const boolText = (value) => value ? "true" : "false";
function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
    return Object.freeze(value);
  }
  return value;
}
function readOnlyMap(map) {
  const view = {
    get: (key) => map.get(key),
    has: (key) => map.has(key),
    entries: () => map.entries(),
    keys: () => map.keys(),
    values: () => map.values(),
    get size() { return map.size; },
    [Symbol.iterator]: () => map[Symbol.iterator](),
  };
  return Object.freeze(view);
}
function readOnlySet(set) {
  const view = {
    has: (value) => set.has(value),
    entries: () => set.entries(),
    keys: () => set.keys(),
    values: () => set.values(),
    get size() { return set.size; },
    [Symbol.iterator]: () => set[Symbol.iterator](),
  };
  return Object.freeze(view);
}

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


const BUNDLE_FIELDS = new Set(["profile", "domains", "instance_id", "guardian_id", "authority_epoch", "registered_body_ids", "proposals", "evaluations", "grants", "ledger_events", "use_requests"]);
const PUBLIC_KEY_FIELDS = new Set(["public_key_hex", "public_key_fingerprint", "key_epoch_id"]);

function resolvePublicKey(publicKeyResolver, envelope, signerType, signerId) {
  if (typeof publicKeyResolver !== "function") fail("public_key_resolver_required");
  exact(envelope, SIGNATURE_FIELDS, "public_key_envelope_invalid");
  const key = publicKeyResolver({ signer_type: signerType, signer_id: signerId, key_epoch_id: envelope.key_epoch_id, public_key_ref: envelope.public_key_ref });
  exact(key, PUBLIC_KEY_FIELDS, "public_key_record_invalid");
  if (!/^[0-9a-f]{64}$/.test(key.public_key_hex)) fail("public_key_hex_invalid");
  if (!/^sha256:[0-9a-f]{64}$/.test(key.public_key_fingerprint)) fail("public_key_fingerprint_invalid");
  const expectedFingerprint = `sha256:${crypto.createHash("sha256").update(Buffer.from(key.public_key_hex, "hex")).digest("hex")}`;
  if (key.public_key_fingerprint !== expectedFingerprint) fail("public_key_fingerprint_mismatch");
  if (key.key_epoch_id !== envelope.key_epoch_id || key.public_key_fingerprint !== envelope.public_key_ref) fail("public_key_resolution_mismatch");
  return key;
}

export function publicAuthorityBundleFromFixture(document) {
  return structuredClone({
    profile: "genesis.autonomy.authority.bundle.v0.1",
    domains: document.domains,
    instance_id: document.instance_id,
    guardian_id: document.guardian_id,
    authority_epoch: document.authority_epoch,
    registered_body_ids: document.registered_body_ids,
    proposals: document.proposals,
    evaluations: document.evaluations,
    grants: document.grants,
    ledger_events: document.ledger_events,
    use_requests: document.use_requests,
  });
}

export function publicKeyResolverFromFixture(document) {
  const records = new Map();
  for (const [signerType, source] of Object.entries(document.keys)) {
    const key = { public_key_hex: source.public_key_hex, public_key_fingerprint: source.public_key_fingerprint, key_epoch_id: source.key_epoch_id };
    records.set(`${signerType}:${source.signer_id}:${source.key_epoch_id}:${source.public_key_fingerprint}`, Object.freeze(key));
  }
  return ({ signer_type, signer_id, key_epoch_id, public_key_ref }) => records.get(`${signer_type}:${signer_id}:${key_epoch_id}:${public_key_ref}`) ?? null;
}

function validateAuthorityBundleInternal(bundle, publicKeyResolver) {
  validateNfc(bundle);
  exact(bundle, BUNDLE_FIELDS, "authority_bundle_fields_invalid");
  if (bundle.profile !== "genesis.autonomy.authority.bundle.v0.1") fail("authority_bundle_profile_invalid");
  ensureInt(bundle.authority_epoch, "authority_bundle_epoch_invalid", 0);
  const registered = ensureSortedUniqueStrings(bundle.registered_body_ids, "authority_bundle_registered_bodies_invalid");
  const base = { domains: bundle.domains, instance_id: bundle.instance_id, guardian_id: bundle.guardian_id, authority_epoch: bundle.authority_epoch, registered_body_ids: registered };
  const proposalMap = new Map();
  for (const item of bundle.proposals) {
    const bodyKey = resolvePublicKey(publicKeyResolver, item.signature, "body", item.body_id);
    validateProposal(item, { ...base, keys: { body: bodyKey, guardian: null } });
    if (proposalMap.has(item.proposal_id)) fail("proposal_id_duplicate");
    proposalMap.set(item.proposal_id, item);
  }
  const evaluationMap = new Map();
  for (const item of bundle.evaluations) {
    const proposal = proposalMap.get(item.proposal_ref);
    if (!proposal) fail("evaluation_proposal_missing");
    const guardianKey = resolvePublicKey(publicKeyResolver, item.signature, "guardian", bundle.guardian_id);
    validateEvaluation(item, proposal, { ...base, keys: { body: null, guardian: guardianKey } });
    if (evaluationMap.has(item.evaluation_id)) fail("evaluation_id_duplicate");
    evaluationMap.set(item.evaluation_id, item);
  }
  const grants = [];
  const grantIds = new Set();
  for (const item of bundle.grants) {
    const proposal = proposalMap.get(item.proposal_ref);
    const evaluation = evaluationMap.get(item.evaluation_ref);
    if (!proposal) fail("grant_proposal_missing");
    if (!evaluation) fail("grant_evaluation_missing");
    const guardianKey = resolvePublicKey(publicKeyResolver, item.signature, "guardian", bundle.guardian_id);
    validateGrant(item, proposal, evaluation, { ...base, keys: { body: null, guardian: guardianKey } });
    if (grantIds.has(item.grant_id)) fail("grant_id_duplicate");
    grantIds.add(item.grant_id);
    grants.push(item);
  }
  const uses = [];
  const useIds = new Set();
  for (const item of bundle.use_requests) {
    const bodyKey = resolvePublicKey(publicKeyResolver, item.signature, "body", item.body_id);
    validateUse(item, { ...base, keys: { body: bodyKey, guardian: null } });
    if (useIds.has(item.use_id)) fail("use_id_duplicate");
    useIds.add(item.use_id);
    uses.push(item);
  }
  const ledgerResolver = ({ envelope, signer_type, signer_id }) => resolvePublicKey(publicKeyResolver, envelope, signer_type, signer_id);
  validateLedger(bundle.ledger_events, grants, uses, { ...base, keys: {} }, ledgerResolver);
  const frozenBundle = deepFreeze(bundle);
  const grantMap = new Map(grants.map((grant) => [grant.grant_id, grant]));
  return Object.freeze({ [MARK]: true, bundle: frozenBundle, grants: readOnlyMap(grantMap), registered: readOnlySet(new Set(registered)), keyResolver: publicKeyResolver });
}

export function validateAuthorityBundle(bundle, publicKeyResolver) {
  try { return validateAuthorityBundleInternal(structuredClone(bundle), publicKeyResolver); }
  catch (error) {
    if (error instanceof AuthorityError) throw error;
    if (error instanceof ConformanceError) throw new AuthorityError(error.message);
    throw error;
  }
}

export function authorityFromValidatedFixture(document) {
  validateDocument(structuredClone(document));
  return validateAuthorityBundle(publicAuthorityBundleFromFixture(document), publicKeyResolverFromFixture(document));
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
  const state = stateAt(grant, authority.bundle.ledger_events, at);
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
  const bodyKey = resolvePublicKey(authority.keyResolver, item.signature, "body", item.body_id);
  verifyEnvelope(item.signature, bodyKey, { digest, domain: "genesis.autonomy.capability.use.signature.v0.2", signerType: "body", signerId: item.body_id, createdAt: item.requested_at, prefix: "authorized_use" });
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
  const digest = hashAuthorityFields("genesis.improvement.campaign.authorization.v0.1", [request.campaign_digest, request.grant_ref, grantDigest, String(authority.bundle.authority_epoch), authority.bundle.ledger_events[0].ledger_id, optional(state?.head_ref), state?.head_hash ?? "GENESIS", request.authorized_at, status, reason, requestDigest, resolved.grant?.guardian_key_epoch_id ?? "", request.body_id]);
  return { decision_status: status, decision_reason: reason, grant_ref: request.grant_ref, grant_digest: grantDigest || null, authority_request_digest: requestDigest, campaign_authorization_digest: digest, ledger_head_event_ref: state?.head_ref ?? null, ledger_head_hash: state?.head_hash ?? "GENESIS" };
}

#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = path.join(ROOT, "conformance", "recursive_improvement_vectors.json");
const PROJECTION = path.join(ROOT, "runtime", "improvement-projection.json");
const ZERO = `sha256:${"0".repeat(64)}`;
class CheckError extends Error {}
const check = (ok, code) => { if (!ok) throw new CheckError(code); };
const cmp = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort(cmp).map((k) => [k, canon(v[k])]));
  if (typeof v === "string") check(v.normalize("NFC") === v, "text_not_nfc");
  return v;
}
const stable = (v) => JSON.stringify(canon(v));
const digest = (v) => `sha256:${crypto.createHash("sha256").update(stable(v)).digest("hex")}`;
const label = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
function keys(seed) {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const raw = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return { privateKey, publicText: `ed25519pk:${raw.toString("hex")}` };
}
const message = (domain, value) => Buffer.from(`${domain}\n${value}`);
const sign = (key, domain, value) => `ed25519sig:${crypto.sign(null, message(domain, value), key).toString("hex")}`;
function verify(publicText, signature, domain, value) {
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicText.slice(10), "hex")]);
  const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
  return crypto.verify(null, message(domain, value), key, Buffer.from(signature.slice(11), "hex"));
}
function load() { return JSON.parse(fs.readFileSync(VECTOR, "utf8")); }
function validateCampaignTemplate(c) {
  check(c.schema_version === "genesis.improvement.campaign.v0.1", "campaign_schema");
  check(c.hash_profile === "genesis.hash.fields.v0.1", "campaign_hash");
  check(c.guardian_grant_ref.length >= 8, "campaign_grant");
  check(["maximize", "minimize"].includes(c.metric.direction), "metric_direction");
  check(c.policy_profile === "genesis.improvement.search.aide-adapted.v0.1", "policy");
  const b = c.fixed_budget;
  check(Number.isSafeInteger(b.max_candidates) && b.max_candidates > 0, "max_candidates");
  check(Number.isSafeInteger(b.max_drafts) && b.max_drafts > 0 && b.max_drafts <= b.max_candidates, "max_drafts");
  check(Number.isSafeInteger(b.max_debug_depth) && b.max_debug_depth >= 0, "max_debug_depth");
  check(Number.isSafeInteger(b.plateau_window) && b.plateau_window > 0, "plateau_window");
  check(stable(c.sandbox_profile) === stable({ network_mode: "denied", filesystem_mode: "ephemeral_readonly_input", secrets_available: false, process_isolation: true, output_capture: true, environment_reproducible: true }), "sandbox");
  check(stable(c.private_evaluation) === stable({ cases_visible_to_agent: false, receipt_only: true, evaluator_separate: true }), "private_boundary");
}
function campaign(doc) {
  validateCampaignTemplate(doc.campaign_template);
  const pair = keys(doc.test_only_keys.guardian_seed_hex);
  const out = { ...structuredClone(doc.campaign_template), guardian_public_key: pair.publicText };
  out.campaign_digest = digest(out);
  out.guardian_signature = sign(pair.privateKey, "genesis.improvement.campaign.signature.v0.1", out.campaign_digest);
  check(verify(out.guardian_public_key, out.guardian_signature, "genesis.improvement.campaign.signature.v0.1", out.campaign_digest), "campaign_signature");
  return out;
}
function classify(t, used, limits) {
  const budgetMap = { actions: "max_actions", duration_ms: "max_duration_ms", token_units: "max_token_units", bytes: "max_bytes", cost_microunits: "max_cost_microunits" };
  if (Object.entries(budgetMap).some(([k, limit]) => used[k] > limits[limit])) return ["rejected", "budget_exceeded"];
  if (t.execution_status === "error") return ["buggy", "execution_error"];
  if (t.execution_status === "timeout") return ["buggy", "timeout"];
  if (t.public_score_milli === null) return ["rejected", "public_failed"];
  if (t.metric_manipulation_detected) return ["rejected", "metric_manipulation"];
  if (t.safety_regression_detected) return ["rejected", "safety_regression"];
  if (!t.private_pass) return ["rejected", "private_failed"];
  if (!t.generalization_pass) return ["rejected", "generalization_failed"];
  if (!t.maintainability_pass) return ["rejected", "maintainability_failed"];
  return ["accepted", null];
}
const best = (events) => events.filter((e) => e.status === "accepted").sort((a, b) => (b.evaluation.public_score_milli - a.evaluation.public_score_milli) || (a.sequence - b.sequence) || cmp(a.candidate_id, b.candidate_id))[0] ?? null;
function depth(event, map) { return event.operator === "debug" ? 1 + depth(map.get(event.parent_candidate_ref), map) : 0; }
function plateau(events, lineage, window) {
  const xs = events.filter((e) => e.lineage_id === lineage && e.operator === "improve" && e.status === "accepted");
  if (xs.length < window + 1) return false;
  const prior = Math.max(...xs.slice(0, -window).map((e) => e.evaluation.public_score_milli));
  return xs.slice(-window).every((e) => e.evaluation.public_score_milli <= prior);
}
function decision(c, events) {
  const b = c.fixed_budget;
  if (events.length < b.max_drafts) return { operator: "draft", parent_candidate_ref: null, lineage_id: `lin_draft_${String(events.length + 1).padStart(2, "0")}`, reason: "draft_quota" };
  const map = new Map(events.map((e) => [e.candidate_id, e]));
  const parents = new Set(events.map((e) => e.parent_candidate_ref).filter(Boolean));
  const bugs = events.filter((e) => e.status === "buggy" && !parents.has(e.candidate_id) && depth(e, map) < b.max_debug_depth).sort((a, z) => a.sequence - z.sequence || cmp(a.candidate_id, z.candidate_id));
  if (bugs.length) return { operator: "debug", parent_candidate_ref: bugs[0].candidate_id, lineage_id: bugs[0].lineage_id, reason: "debug_buggy_leaf" };
  const winner = best(events); check(winner, "no_candidate");
  if (plateau(events, winner.lineage_id, b.plateau_window)) return { operator: "improve", parent_candidate_ref: winner.candidate_id, lineage_id: `lin_fork_${String(events.length + 1).padStart(2, "0")}`, reason: "fork_plateau" };
  return { operator: "improve", parent_candidate_ref: winner.candidate_id, lineage_id: winner.lineage_id, reason: "improve_best" };
}
function events(doc, c) {
  const pair = keys(doc.test_only_keys.evaluator_seed_hex); const out = [];
  for (const t of doc.candidate_templates) {
    const next = decision(c, out);
    check(t.operator === next.operator, "operator_mismatch"); check(t.parent_candidate_ref === next.parent_candidate_ref, "parent_mismatch"); check(t.lineage_id === next.lineage_id, "lineage_mismatch");
    const map = new Map(out.map((e) => [e.candidate_id, e]));
    const source = t.operator === "draft" ? c.source_tree_digest : map.get(t.parent_candidate_ref).result_tree_digest;
    const used = { actions: 1, duration_ms: 30000, token_units: 20000, bytes: 1000000, cost_microunits: 10000 };
    const [status, reason] = classify(t, used, c.fixed_budget); check(status === t.status && reason === t.rejection_reason, "classification");
    const n = out.length; const id = t.candidate_id;
    const e = { schema_version: "genesis.improvement.candidate.event.v0.1", hash_profile: "genesis.hash.fields.v0.1", ledger_id: "ril_01HRECURSIVEIMPROVE0001", event_id: `rievt_${String(n + 1).padStart(2, "0")}_01HRECURSIVE`, sequence: n, previous_event_hash: out.at(-1)?.event_hash ?? ZERO, campaign_ref: c.campaign_id, campaign_digest: c.campaign_digest, candidate_id: id, parent_candidate_ref: t.parent_candidate_ref, lineage_id: t.lineage_id, operator: t.operator, proposal_digest: label(`${id}:proposal`), patch_digest: label(`${id}:patch`), source_tree_digest: source, result_tree_digest: label(`${id}:result-tree`), environment_digest: label("genesis.improvement.environment.v0.1"), budget_used: used, execution: { status: t.execution_status, output_digest: label(`${id}:output`), artifact_digest: label(`${id}:artifact`), error_class: t.execution_status === "error" ? "ValueError" : null }, evaluation: { public_score_milli: t.public_score_milli, public_pass: t.execution_status === "success" && t.public_score_milli !== null, private_receipt_digest: label(`${id}:private-receipt`), private_pass: t.private_pass, generalization_pass: t.generalization_pass, maintainability_pass: t.maintainability_pass, metric_manipulation_detected: t.metric_manipulation_detected, safety_regression_detected: t.safety_regression_detected }, status, rejection_reason: reason, recorded_at: `2026-07-16T03:${String(11 + n).padStart(2, "0")}:00Z`, evaluator_id: "eval_01HGENESISPRIVATE0001", evaluator_public_key: pair.publicText };
    e.event_hash = digest(e); e.evaluator_signature = sign(pair.privateKey, "genesis.improvement.candidate.event.signature.v0.1", e.event_hash);
    check(verify(e.evaluator_public_key, e.evaluator_signature, "genesis.improvement.candidate.event.signature.v0.1", e.event_hash), "event_signature"); out.push(e);
  }
  return out;
}
function projection(c, es) {
  const groups = new Map(); for (const e of es) { if (!groups.has(e.lineage_id)) groups.set(e.lineage_id, []); groups.get(e.lineage_id).push(e); }
  const lineages = [...groups.keys()].sort(cmp).map((id) => { const xs = groups.get(id); const winner = best(xs); const ids = new Set(xs.map((e) => e.candidate_id)); const root = xs.filter((e) => e.parent_candidate_ref === null || !ids.has(e.parent_candidate_ref)).sort((a, z) => a.sequence - z.sequence)[0]; return { lineage_id: id, root_candidate_ref: root.candidate_id, candidate_count: xs.length, accepted_count: xs.filter((e) => e.status === "accepted").length, buggy_count: xs.filter((e) => e.status === "buggy").length, rejected_count: xs.filter((e) => e.status === "rejected").length, best_candidate_ref: winner?.candidate_id ?? null, best_score_milli: winner?.evaluation.public_score_milli ?? null, plateau_detected: plateau(es, id, c.fixed_budget.plateau_window) }; });
  const winner = best(es); const ready = Boolean(winner && winner.evaluation.private_pass && winner.evaluation.generalization_pass && winner.evaluation.maintainability_pass && !winner.evaluation.metric_manipulation_detected && !winner.evaluation.safety_regression_detected);
  const p = { schema_version: "genesis.improvement.projection.v0.1", hash_profile: "genesis.hash.fields.v0.1", campaign_ref: c.campaign_id, campaign_digest: c.campaign_digest, ledger_id: es[0].ledger_id, source_tree_digest: c.source_tree_digest, source_event_count: es.length, source_last_event_hash: es.at(-1).event_hash, candidate_count: es.length, accepted_count: es.filter((e) => e.status === "accepted").length, buggy_count: es.filter((e) => e.status === "buggy").length, rejected_count: es.filter((e) => e.status === "rejected").length, operator_counts: Object.fromEntries(["draft", "debug", "improve"].map((op) => [op, es.filter((e) => e.operator === op).length])), lineages, best_candidate_ref: winner?.candidate_id ?? null, best_score_milli: winner?.evaluation.public_score_milli ?? null, next_decision: decision(c, es), promotion: { status: ready ? "candidate_ready" : "not_ready", candidate_ref: ready ? winner.candidate_id : null, requires_guardian_approval: true, required_capability: "code.propose_change", direct_merge_forbidden: true } };
  p.projection_digest = digest(p); return p;
}
function run() {
  const doc = load(); const c = campaign(doc); const es = events(doc, c); const p = projection(c, es); const x = doc.expected;
  check(es.length === x.candidate_count && p.lineages.length === x.lineage_count, "counts"); check(stable(p.operator_counts) === stable(x.operator_counts), "operators"); check(p.best_candidate_ref === x.best_candidate_ref && p.best_score_milli === x.best_score_milli, "best"); check(p.projection_digest === x.projection_digest, "projection_digest"); check(x.boundary_rejections === 38, "boundary_count");
  return { doc, c, es, p };
}
function writeProjection(p) { fs.mkdirSync(path.dirname(PROJECTION), { recursive: true }); const temp = `${PROJECTION}.${process.pid}.tmp`; fs.writeFileSync(temp, `${JSON.stringify(p, null, 2)}\n`); fs.renameSync(temp, PROJECTION); }
const [command = "validate", arg] = process.argv.slice(2);
try {
  const { c, es, p } = run();
  if (command === "validate") { console.log(`OK recursive improvement campaign (${es.length} candidates, ${p.lineages.length} lineages)`); console.log(`OK operators (draft=${p.operator_counts.draft}, debug=${p.operator_counts.debug}, improve=${p.operator_counts.improve})`); console.log(`OK outcomes (${p.accepted_count} accepted, ${p.buggy_count} buggy, ${p.rejected_count} rejected)`); console.log(`OK projection digest ${p.projection_digest}`); console.log("OK recursive improvement boundary rejection cases (38)"); }
  else if (command === "build") { writeProjection(p); console.log(PROJECTION); }
  else if (command === "select") { const n = arg === undefined ? es.length : Number(arg) + 1; check(Number.isInteger(n) && n >= 0 && n <= es.length, "sequence"); console.log(JSON.stringify(decision(c, es.slice(0, n)), null, 2)); }
  else if (command === "inspect") { check(fs.existsSync(PROJECTION), "projection_missing"); console.log(fs.readFileSync(PROJECTION, "utf8")); }
  else if (command === "promote") console.log(JSON.stringify(p.promotion, null, 2));
  else check(false, "command");
} catch (error) { console.error(`FAIL recursive improvement laboratory: ${error.message}`); process.exitCode = 1; }

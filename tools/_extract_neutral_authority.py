#!/usr/bin/env python3
"""Temporary deterministic refactor that extracts the public authority bundle API."""
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replace_anchor_invalid:{label}:{count}")
    return text.replace(old, new, 1)


def insert_once(text: str, anchor: str, inserted: str, label: str) -> str:
    if text.count(anchor) != 1:
        raise SystemExit(f"insert_anchor_invalid:{label}:{text.count(anchor)}")
    return text.replace(anchor, inserted + anchor, 1)


def patch_core_node() -> None:
    path = ROOT / "tools" / "guided_autonomy.mjs"
    text = path.read_text(encoding="utf-8")
    for old, new, label in [
        ("function validateNfc(value) {", "export function validateNfc(value) {", "node-export-nfc"),
        ("function ensureInt(value, code, minimum = 0) {", "export function ensureInt(value, code, minimum = 0) {", "node-export-int"),
        ("function ensureSortedUniqueStrings(values, code, { allowEmpty = false } = {}) {", "export function ensureSortedUniqueStrings(values, code, { allowEmpty = false } = {}) {", "node-export-strings"),
        ("function validateProposal(item, document) {", "export function validateProposal(item, document) {", "node-export-proposal"),
        ("function validateEvaluation(item, proposal, document) {", "export function validateEvaluation(item, proposal, document) {", "node-export-evaluation"),
        ("function validateGrant(item, proposal, evaluation, document) {", "export function validateGrant(item, proposal, evaluation, document) {", "node-export-grant"),
        ("function validateUse(item, document) {", "export function validateUse(item, document) {", "node-export-use"),
        ("function validateLedger(events, grants, uses, document) {", "export function validateLedger(events, grants, uses, document, keyResolver = null) {", "node-export-ledger"),
    ]:
        text = replace_once(text, old, new, label)
    text = replace_once(
        text,
        '      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: document.keys.body, signerType: "body", signerId: use.body_id, createdAt: event.recorded_at, prefix: "ledger" });',
        '      const bodyKey = keyResolver ? keyResolver({ envelope: event.signature, signer_type: "body", signer_id: use.body_id }) : document.keys.body;\n      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: bodyKey, signerType: "body", signerId: use.body_id, createdAt: event.recorded_at, prefix: "ledger" });',
        "node-ledger-body-key",
    )
    text = replace_once(
        text,
        '      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: document.keys.guardian, signerType: "guardian", signerId: document.guardian_id, createdAt: event.recorded_at, prefix: "ledger" });',
        '      const guardianKey = keyResolver ? keyResolver({ envelope: event.signature, signer_type: "guardian", signer_id: document.guardian_id }) : document.keys.guardian;\n      validateSignature(event.signature, { digest, domain: document.domains.event_signature, key: guardianKey, signerType: "guardian", signerId: document.guardian_id, createdAt: event.recorded_at, prefix: "ledger" });',
        "node-ledger-guardian-key",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_core_python() -> None:
    path = ROOT / "tools" / "validate_guided_autonomy.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "def validate_ledger(events: list[dict], grants: list[dict], uses: list[dict], document: dict) -> None:",
        "def validate_ledger(events: list[dict], grants: list[dict], uses: list[dict], document: dict, key_resolver=None) -> None:",
        "py-ledger-resolver-param",
    )
    text = replace_once(
        text,
        '''            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=document["keys"]["body"], signer_type="body", signer_id=use["body_id"], created_at=event["recorded_at"], prefix="ledger")''',
        '''            body_key = key_resolver({"envelope": event["signature"], "signer_type": "body", "signer_id": use["body_id"]}) if key_resolver else document["keys"]["body"]
            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=body_key, signer_type="body", signer_id=use["body_id"], created_at=event["recorded_at"], prefix="ledger")''',
        "py-ledger-body-key",
    )
    text = replace_once(
        text,
        '''            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=document["keys"]["guardian"], signer_type="guardian", signer_id=document["guardian_id"], created_at=event["recorded_at"], prefix="ledger")''',
        '''            guardian_key = key_resolver({"envelope": event["signature"], "signer_type": "guardian", "signer_id": document["guardian_id"]}) if key_resolver else document["keys"]["guardian"]
            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=guardian_key, signer_type="guardian", signer_id=document["guardian_id"], created_at=event["recorded_at"], prefix="ledger")''',
        "py-ledger-guardian-key",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


NODE_NEUTRAL = r'''
const BUNDLE_FIELDS = new Set(["profile", "domains", "instance_id", "guardian_id", "authority_epoch", "registered_body_ids", "proposals", "evaluations", "grants", "ledger_events", "use_requests"]);
const PUBLIC_KEY_FIELDS = new Set(["public_key_hex", "public_key_fingerprint", "key_epoch_id"]);

function resolvePublicKey(publicKeyResolver, envelope, signerType, signerId) {
  if (typeof publicKeyResolver !== "function") fail("public_key_resolver_required");
  const key = publicKeyResolver({ signer_type: signerType, signer_id: signerId, key_epoch_id: envelope.key_epoch_id, public_key_ref: envelope.public_key_ref });
  exact(key, PUBLIC_KEY_FIELDS, "public_key_record_invalid");
  if (!/^[0-9a-f]{64}$/.test(key.public_key_hex)) fail("public_key_hex_invalid");
  if (!/^sha256:[0-9a-f]{64}$/.test(key.public_key_fingerprint)) fail("public_key_fingerprint_invalid");
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

export function validateAuthorityBundle(bundle, publicKeyResolver) {
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
  const grantMap = new Map(grants.map((grant) => [grant.grant_id, grant]));
  return Object.freeze({ [MARK]: true, bundle, grants: grantMap, registered: new Set(registered), keyResolver: publicKeyResolver });
}

'''


def patch_adapter_node() -> None:
    path = ROOT / "tools" / "validate_guided_autonomy_authority.mjs"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        'import { validateDocument } from "./guided_autonomy.mjs";',
        'import { ensureInt, ensureSortedUniqueStrings, validateDocument, validateEvaluation, validateGrant, validateLedger, validateNfc, validateProposal, validateUse } from "./guided_autonomy.mjs";',
        "node-adapter-imports",
    )
    anchor = "export function authorityFromValidatedFixture(document) {"
    text = insert_once(text, anchor, NODE_NEUTRAL, "node-neutral-insert")
    text = re.sub(
        r'export function authorityFromValidatedFixture\(document\) \{.*?\n\}',
        '''export function authorityFromValidatedFixture(document) {
  validateDocument(structuredClone(document));
  return validateAuthorityBundle(publicAuthorityBundleFromFixture(document), publicKeyResolverFromFixture(document));
}''',
        text,
        count=1,
        flags=re.S,
    )
    text = text.replace("authority.document.ledger_events", "authority.bundle.ledger_events")
    text = text.replace("authority.document.authority_epoch", "authority.bundle.authority_epoch")
    text = text.replace("authority.document.ledger_events[0].ledger_id", "authority.bundle.ledger_events[0].ledger_id")
    text = replace_once(
        text,
        '  verifyEnvelope(item.signature, authority.document.keys.body, { digest, domain: "genesis.autonomy.capability.use.signature.v0.2", signerType: "body", signerId: item.body_id, createdAt: item.requested_at, prefix: "authorized_use" });',
        '  const bodyKey = resolvePublicKey(authority.keyResolver, item.signature, "body", item.body_id);\n  verifyEnvelope(item.signature, bodyKey, { digest, domain: "genesis.autonomy.capability.use.signature.v0.2", signerType: "body", signerId: item.body_id, createdAt: item.requested_at, prefix: "authorized_use" });',
        "node-authorized-use-key",
    )
    text = replace_once(
        text,
        'authority.document.keys.guardian.key_epoch_id',
        'resolved.grant?.guardian_key_epoch_id ?? ""',
        "node-guardian-epoch",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


PY_NEUTRAL = r'''
BUNDLE_FIELDS={"profile","domains","instance_id","guardian_id","authority_epoch","registered_body_ids","proposals","evaluations","grants","ledger_events","use_requests"}
PUBLIC_KEY_FIELDS={"public_key_hex","public_key_fingerprint","key_epoch_id"}

def resolve_public_key(public_key_resolver,envelope,signer_type,signer_id):
 if not callable(public_key_resolver): fail('public_key_resolver_required')
 key=public_key_resolver({'signer_type':signer_type,'signer_id':signer_id,'key_epoch_id':envelope['key_epoch_id'],'public_key_ref':envelope['public_key_ref']})
 exact(key,PUBLIC_KEY_FIELDS,'public_key_record_invalid')
 if not __import__('re').fullmatch(r'[0-9a-f]{64}',key['public_key_hex']): fail('public_key_hex_invalid')
 if not __import__('re').fullmatch(r'sha256:[0-9a-f]{64}',key['public_key_fingerprint']): fail('public_key_fingerprint_invalid')
 if key['key_epoch_id']!=envelope['key_epoch_id'] or key['public_key_fingerprint']!=envelope['public_key_ref']: fail('public_key_resolution_mismatch')
 return key

def public_authority_bundle_from_fixture(document):
 return __import__('copy').deepcopy({'profile':'genesis.autonomy.authority.bundle.v0.1','domains':document['domains'],'instance_id':document['instance_id'],'guardian_id':document['guardian_id'],'authority_epoch':document['authority_epoch'],'registered_body_ids':document['registered_body_ids'],'proposals':document['proposals'],'evaluations':document['evaluations'],'grants':document['grants'],'ledger_events':document['ledger_events'],'use_requests':document['use_requests']})

def public_key_resolver_from_fixture(document):
 records={}
 for signer_type,source in document['keys'].items():
  key={'public_key_hex':source['public_key_hex'],'public_key_fingerprint':source['public_key_fingerprint'],'key_epoch_id':source['key_epoch_id']}
  records[(signer_type,source['signer_id'],source['key_epoch_id'],source['public_key_fingerprint'])]=key
 return lambda query: records.get((query['signer_type'],query['signer_id'],query['key_epoch_id'],query['public_key_ref']))

def validate_authority_bundle(bundle,public_key_resolver):
 validate_nfc(bundle);exact(bundle,BUNDLE_FIELDS,'authority_bundle_fields_invalid')
 if bundle['profile']!='genesis.autonomy.authority.bundle.v0.1': fail('authority_bundle_profile_invalid')
 ensure_int(bundle['authority_epoch'],'authority_bundle_epoch_invalid',0);registered=ensure_sorted_unique_strings(bundle['registered_body_ids'],'authority_bundle_registered_bodies_invalid')
 base={'domains':bundle['domains'],'instance_id':bundle['instance_id'],'guardian_id':bundle['guardian_id'],'authority_epoch':bundle['authority_epoch'],'registered_body_ids':registered}
 proposals={}
 for item in bundle['proposals']:
  body_key=resolve_public_key(public_key_resolver,item['signature'],'body',item['body_id']);validate_proposal(item,{**base,'keys':{'body':body_key,'guardian':None}})
  if item['proposal_id'] in proposals: fail('proposal_id_duplicate')
  proposals[item['proposal_id']]=item
 evaluations={}
 for item in bundle['evaluations']:
  proposal=proposals.get(item['proposal_ref'])
  if proposal is None: fail('evaluation_proposal_missing')
  guardian_key=resolve_public_key(public_key_resolver,item['signature'],'guardian',bundle['guardian_id']);validate_evaluation(item,proposal,{**base,'keys':{'body':None,'guardian':guardian_key}})
  if item['evaluation_id'] in evaluations: fail('evaluation_id_duplicate')
  evaluations[item['evaluation_id']]=item
 grants=[];grant_ids=set()
 for item in bundle['grants']:
  proposal=proposals.get(item['proposal_ref']);evaluation=evaluations.get(item['evaluation_ref'])
  if proposal is None: fail('grant_proposal_missing')
  if evaluation is None: fail('grant_evaluation_missing')
  guardian_key=resolve_public_key(public_key_resolver,item['signature'],'guardian',bundle['guardian_id']);validate_grant(item,proposal,evaluation,{**base,'keys':{'body':None,'guardian':guardian_key}})
  if item['grant_id'] in grant_ids: fail('grant_id_duplicate')
  grant_ids.add(item['grant_id']);grants.append(item)
 uses=[];use_ids=set()
 for item in bundle['use_requests']:
  body_key=resolve_public_key(public_key_resolver,item['signature'],'body',item['body_id']);validate_use(item,{**base,'keys':{'body':body_key,'guardian':None}})
  if item['use_id'] in use_ids: fail('use_id_duplicate')
  use_ids.add(item['use_id']);uses.append(item)
 def ledger_resolver(query): return resolve_public_key(public_key_resolver,query['envelope'],query['signer_type'],query['signer_id'])
 validate_ledger(bundle['ledger_events'],grants,uses,{**base,'keys':{}},ledger_resolver)
 return Authority(bundle,{g['grant_id']:g for g in grants},frozenset(registered),public_key_resolver)

validateAuthorityBundle=validate_authority_bundle
'''


def patch_adapter_python() -> None:
    path = ROOT / "tools" / "validate_guided_autonomy_authority.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from validate_guided_autonomy import validate_document",
        "from validate_guided_autonomy import ensure_int, ensure_sorted_unique_strings, validate_document, validate_evaluation, validate_grant, validate_ledger, validate_nfc, validate_proposal, validate_use",
        "py-adapter-imports",
    )
    text = replace_once(
        text,
        "class Authority:\n document:dict; grants:dict; registered:frozenset",
        "class Authority:\n bundle:dict; grants:dict; registered:frozenset; key_resolver:object",
        "py-authority-fields",
    )
    anchor = "def authority_from_validated_fixture(document):"
    text = insert_once(text, anchor, PY_NEUTRAL, "py-neutral-insert")
    text = re.sub(
        r'def authority_from_validated_fixture\(document\):\n.*?\n(?=def state_at)',
        '''def authority_from_validated_fixture(document):
 validate_document(__import__('copy').deepcopy(document))
 return validate_authority_bundle(public_authority_bundle_from_fixture(document),public_key_resolver_from_fixture(document))
''',
        text,
        count=1,
        flags=re.S,
    )
    text = text.replace("authority.document['ledger_events']", "authority.bundle['ledger_events']")
    text = text.replace("a.document['authority_epoch']", "a.bundle['authority_epoch']")
    text = text.replace("a.document['ledger_events'][0]['ledger_id']", "a.bundle['ledger_events'][0]['ledger_id']")
    text = replace_once(
        text,
        " verify_envelope(i['signature'],a.document['keys']['body'],digest=digest,domain='genesis.autonomy.capability.use.signature.v0.2',signer_type='body',signer_id=i['body_id'],created_at=i['requested_at'],prefix='authorized_use')",
        " body_key=resolve_public_key(a.key_resolver,i['signature'],'body',i['body_id']);verify_envelope(i['signature'],body_key,digest=digest,domain='genesis.autonomy.capability.use.signature.v0.2',signer_type='body',signer_id=i['body_id'],created_at=i['requested_at'],prefix='authorized_use')",
        "py-authorized-use-key",
    )
    text = replace_once(
        text,
        "a.document['keys']['guardian']['key_epoch_id']",
        "'' if x['grant'] is None else x['grant']['guardian_key_epoch_id']",
        "py-guardian-epoch",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_laboratory() -> None:
    node_path = ROOT / "tools" / "validate_recursive_improvement_lab.mjs"
    node = node_path.read_text(encoding="utf-8")
    node = replace_once(
        node,
        "  authorityFromValidatedFixture,\n",
        "  authorityFromValidatedFixture,\n  validateAuthorityBundle,\n",
        "lab-node-import",
    )
    node = replace_once(
        node,
        ' const authority=authorityFromValidatedFixture(guided),grant=guided.grants.find(g=>g.grant_id===lab.campaign.guardian_grant_ref);',
        ' const authority=authorityFromValidatedFixture(guided);if(["keys","expected","must_reject"].some(field=>Object.hasOwn(authority.bundle,field)))throw Error("neutral_bundle_contains_test_fields");const grant=guided.grants.find(g=>g.grant_id===lab.campaign.guardian_grant_ref);',
        "lab-node-neutral-check",
    )
    node = replace_once(
        node,
        " return{receipt,decision,negatives};",
        ' const broken=structuredClone(authority.bundle);broken.ledger_events[1].previous_event_hash="sha256:"+"0".repeat(64);expectFailure("neutral_bundle_ledger",()=>validateAuthorityBundle(broken,authority.keyResolver));negatives++;return{receipt,decision,negatives};',
        "lab-node-neutral-negative",
    )
    node_path.write_text(node, encoding="utf-8", newline="\n")

    py_path = ROOT / "tools" / "validate_recursive_improvement_lab.py"
    py = py_path.read_text(encoding="utf-8")
    py = replace_once(
        py,
        "from validate_guided_autonomy_authority import AuthorityError,authority_from_validated_fixture,authorize_campaign_opening,compute_authorized_use_digest,evaluate_authorized_use,sign_fixture_envelope,verify_envelope",
        "from validate_guided_autonomy_authority import AuthorityError,authority_from_validated_fixture,authorize_campaign_opening,compute_authorized_use_digest,evaluate_authorized_use,sign_fixture_envelope,validate_authority_bundle,verify_envelope",
        "lab-py-import",
    )
    py = replace_once(
        py,
        " authority=authority_from_validated_fixture(guided);grant=next((g for g in guided['grants'] if g['grant_id']==lab['campaign']['guardian_grant_ref']),None)",
        " authority=authority_from_validated_fixture(guided)\n if any(field in authority.bundle for field in ['keys','expected','must_reject']): raise ValueError('neutral_bundle_contains_test_fields')\n grant=next((g for g in guided['grants'] if g['grant_id']==lab['campaign']['guardian_grant_ref']),None)",
        "lab-py-neutral-check",
    )
    py = replace_once(
        py,
        " return {'receipt':receipt,'decision':decision,'negatives':negatives}",
        " broken=deepcopy(authority.bundle);broken['ledger_events'][1]['previous_event_hash']='sha256:'+'0'*64;expect_failure('neutral_bundle_ledger',lambda:validate_authority_bundle(broken,authority.key_resolver));negatives+=1\n return {'receipt':receipt,'decision':decision,'negatives':negatives}",
        "lab-py-neutral-negative",
    )
    py_path.write_text(py, encoding="utf-8", newline="\n")


def update_docs() -> None:
    registry_path = ROOT / "conformance" / "tool_execution_registry.json"
    registry = registry_path.read_text(encoding="utf-8")
    registry = registry.replace("Adaptador de conformidad sobre el fixture validado de autonomía guiada: resolución exacta de grants y decisiones firmadas de uso consumida por el laboratorio.", "Validador neutral de bundles públicos de autoridad, resolución exacta de grants y decisiones firmadas de uso; el fixture TEST ONLY es una capa separada.")
    registry_path.write_text(registry, encoding="utf-8", newline="\n")

    spec_path = ROOT / "spec" / "RECURSIVE_IMPROVEMENT_LAB.md"
    spec = spec_path.read_text(encoding="utf-8")
    old = "Los adaptadores `validate_guided_autonomy_authority.{mjs,py}` consumen actualmente el fixture completo y validado de autonomía guiada. Son adaptadores de conformidad, no todavía una API productiva neutral."
    new = "`validate_guided_autonomy_authority.{mjs,py}` expone `validateAuthorityBundle`/`validate_authority_bundle` sobre objetos públicos, firmas, enlaces y ledger. El bundle neutral excluye semillas privadas, `expected` y `must_reject`; el fixture TEST ONLY se valida por separado y solo provee un resolvedor público para conformidad."
    spec = replace_once(spec, old, new, "lab-spec-neutral")
    spec = spec.replace("- separar `validateAuthorityBundle` de semillas y expectativas TEST ONLY;\n", "")
    spec_path.write_text(spec, encoding="utf-8", newline="\n")

    guided_path = ROOT / "spec" / "GUIDED_AUTONOMY_AND_CAPABILITY_GRANTS.md"
    guided = guided_path.read_text(encoding="utf-8")
    anchor = "## 10.1 Selección exacta y usos v0.2"
    insert = '''## 10.0 Bundle neutral de autoridad

`genesis.autonomy.authority.bundle.v0.1` contiene únicamente dominios, identidad, cuerpos registrados, propuestas, evaluaciones, grants, solicitudes firmadas y ledger. No contiene semillas privadas, expectativas doradas ni mutaciones negativas. `validateAuthorityBundle(bundle, publicKeyResolver)` resuelve cada clave mediante `signer_type`, `signer_id`, `key_epoch_id` y `public_key_ref`, y reutiliza las mismas reglas normativas del validador de conformidad.

'''
    guided = insert_once(guided, anchor, insert, "guided-spec-neutral")
    guided_path.write_text(guided, encoding="utf-8", newline="\n")

    checklist_path = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    checklist = checklist_path.read_text(encoding="utf-8")
    checklist = checklist.replace("y ocho rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión o revocación.", "y nueve rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión, revocación o ledger público inválido.")
    checklist = checklist.replace("          - [ ] Extraer una API neutral `validateAuthorityBundle` sin semillas ni expectativas TEST ONLY.\n", "")
    checklist_path.write_text(checklist, encoding="utf-8", newline="\n")


def main() -> None:
    patch_core_node()
    patch_core_python()
    patch_adapter_node()
    patch_adapter_python()
    patch_laboratory()
    update_docs()
    print("OK extracted neutral authority bundle API")


if __name__ == "__main__":
    main()

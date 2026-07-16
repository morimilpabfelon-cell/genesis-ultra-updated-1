#!/usr/bin/env python3
"""Temporary deterministic migration for evaluator attestations and portable lab inputs."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]


def plus(ts: str, seconds: int) -> str:
    return (datetime.fromisoformat(ts.replace("Z", "+00:00")) + timedelta(seconds=seconds)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replace_anchor_invalid:{label}:{count}")
    return text.replace(old, new, 1)


def sub_once(text: str, pattern: str, replacement: str, label: str, flags: int = 0) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"sub_anchor_invalid:{label}:{count}")
    return updated


NODE_HELPERS = r'''
const MAX_INT=Number.MAX_SAFE_INTEGER;
function validatePortable(value){
 if(typeof value==="string"){if(value.normalize("NFC")!==value)throw Error("text_not_nfc");return}
 if(typeof value==="number"){if(!Number.isSafeInteger(value)||Math.abs(value)>MAX_INT)throw Error("integer_not_portable");return}
 if(Array.isArray(value)){for(const item of value)validatePortable(item);return}
 if(value&&typeof value==="object"){for(const [key,item] of Object.entries(value)){validatePortable(key);validatePortable(item)}}
}
function optionalText(value){return value===null||value===undefined?"":String(value)}
function boolText(value){return value?"true":"false"}
function computeEvaluatorDigest(candidate,campaignDigest){
 const e=candidate.execution,v=candidate.evaluation;
 return hashAuthorityFields("genesis.improvement.candidate.evaluation.v0.2",[
  campaignDigest,candidate.candidate_id,optionalText(candidate.parent_candidate_ref),candidate.operator,
  candidate.patch_digest,candidate.code_digest,boolText(e.buggy),String(e.cpu_seconds),String(e.memory_mb),String(e.output_bytes),
  optionalText(v.public_metric_milli),optionalText(v.private_receipt_digest),boolText(v.reward_hacking_detected),
  boolText(v.safety_regression_detected),boolText(v.maintainability_passed),candidate.expected_status,candidate.evaluated_at,
 ]);
}
function evaluatorKey(evaluator){return{public_key_hex:evaluator.public_key_hex,public_key_fingerprint:evaluator.public_key_fingerprint,key_epoch_id:evaluator.key_epoch_id}}
'''

NODE_VALIDATE = r'''function validateLab(input){
 validatePortable(input);
 const doc=structuredClone(input),evaluator=doc.evaluator;
 if(!evaluator||evaluator.evaluator_id!=="eval_01HGENESISPRIVATE0001"||!/^[0-9a-f]{64}$/.test(evaluator.public_key_hex)||!/^sha256:[0-9a-f]{64}$/.test(evaluator.public_key_fingerprint)||!evaluator.key_epoch_id)throw Error("evaluator_profile_invalid");
 const c=doc.campaign,cd=c.campaign_digest;delete c.campaign_digest;if(h("campaign",c)!==cd)throw Error("campaign_digest_mismatch");c.campaign_digest=cd;if(c.schema_version!=="genesis.improvement.campaign.v0.2"||JSON.stringify(c.forbidden_capabilities)!==JSON.stringify(FORBIDDEN)||!c.guardian_grant_ref||!c.opened_at||!c.authority_binding)throw Error("authority_invalid");
 const by=new Map(),accepted=[],rejected=[],buggy=[];for(const n of doc.candidates){if(by.has(n.candidate_id))throw Error("duplicate_candidate");const evaluationDigest=computeEvaluatorDigest(n,c.campaign_digest);if(n.evaluation_digest!==evaluationDigest)throw Error("candidate_evaluation_digest_mismatch");verifyEnvelope(n.evaluator_signature,evaluatorKey(evaluator),{digest:evaluationDigest,domain:"genesis.improvement.candidate.evaluation.signature.v0.2",signerType:"evaluator",signerId:evaluator.evaluator_id,createdAt:n.evaluated_at,prefix:"candidate_evaluation"});const d=n.candidate_digest;delete n.candidate_digest;if(h("candidate",n)!==d)throw Error("candidate_digest_mismatch");n.candidate_digest=d;const p=n.parent_candidate_ref,op=n.operator;if(!["draft","debug","improve"].includes(op))throw Error("operator_invalid");if(op==="draft"&&(p!==null||n.source_candidate_ref!==null))throw Error("draft_parent");if(op!=="draft"&&(!by.has(p)||n.source_candidate_ref!==p))throw Error("parent_missing");if(op==="debug"&&!by.get(p).execution.buggy)throw Error("debug_parent");if(op==="improve"&&by.get(p).execution.buggy)throw Error("improve_parent");const e=n.execution,v=n.evaluation,b=c.budget;let s="accepted";if(e.buggy)s="buggy";else if(e.cpu_seconds>b.max_cpu_seconds||e.memory_mb>b.max_memory_mb||e.output_bytes>b.max_output_bytes)s="rejected_budget";else if(!v.private_receipt_digest)s="rejected_private_receipt";else if(v.reward_hacking_detected)s="rejected_reward_hacking";else if(v.safety_regression_detected)s="rejected_safety";else if(!v.maintainability_passed)s="rejected_maintainability";else if(!Number.isInteger(v.public_metric_milli))s="rejected_metric";if(s!==n.expected_status)throw Error("status_mismatch");by.set(n.candidate_id,n);(s==="buggy"?buggy:s==="accepted"?accepted:rejected).push(n.candidate_id)}
 const p=doc.expected_projection,pd=p.projection_digest;delete p.projection_digest;const best=accepted.reduce((a,b)=>by.get(a).evaluation.public_metric_milli>=by.get(b).evaluation.public_metric_milli?a:b);const calc={campaign_ref:c.campaign_id,candidate_count:by.size,accepted,rejected,buggy,best_candidate_ref:best,best_metric_milli:by.get(best).evaluation.public_metric_milli};if(JSON.stringify(calc)!==JSON.stringify(p)||h("projection",p)!==pd)throw Error("projection_mismatch");if(doc.negative_case_ids.length!==20||new Set(doc.negative_case_ids).size!==20)throw Error("negative_cases");return{campaign:c,candidates:[...by.values()],projection:{...p,projection_digest:pd},best,expectedAuthority:doc.expected_authority_execution};
}'''

NODE_BOUNDARIES = r'''
function expectLabFailure(label,fn){try{fn()}catch{return}throw Error(`${label}:accepted`)}
function runLabBoundaryNegatives(input){
 let negatives=0;
 const badSignature=structuredClone(input);badSignature.candidates[0].evaluator_signature.signature_value="0".repeat(128);expectLabFailure("evaluator_signature",()=>validateLab(badSignature));negatives++;
 const badNfc=structuredClone(input);badNfc.campaign.goal="Cafe\u0301";expectLabFailure("lab_nfc",()=>validateLab(badNfc));negatives++;
 const badInteger=structuredClone(input);badInteger.campaign.budget.max_steps=9007199254740992;expectLabFailure("lab_safe_integer",()=>validateLab(badInteger));negatives++;
 return negatives;
}
'''

PY_HELPERS = r'''
MAX_INT=9007199254740991

def validate_portable(value):
 if isinstance(value,str):
  if __import__('unicodedata').normalize('NFC',value)!=value: raise ValueError('text_not_nfc')
 elif type(value) is int:
  if abs(value)>MAX_INT: raise ValueError('integer_not_portable')
 elif isinstance(value,list):
  for item in value: validate_portable(item)
 elif isinstance(value,dict):
  for key,item in value.items(): validate_portable(key);validate_portable(item)
def optional_text(value): return '' if value is None else str(value)
def bool_text(value): return 'true' if value else 'false'
def compute_evaluator_digest(candidate,campaign_digest):
 e=candidate['execution'];v=candidate['evaluation']
 return hash_authority_fields('genesis.improvement.candidate.evaluation.v0.2',[campaign_digest,candidate['candidate_id'],optional_text(candidate['parent_candidate_ref']),candidate['operator'],candidate['patch_digest'],candidate['code_digest'],bool_text(e['buggy']),str(e['cpu_seconds']),str(e['memory_mb']),str(e['output_bytes']),optional_text(v['public_metric_milli']),optional_text(v['private_receipt_digest']),bool_text(v['reward_hacking_detected']),bool_text(v['safety_regression_detected']),bool_text(v['maintainability_passed']),candidate['expected_status'],candidate['evaluated_at']])
def evaluator_key(evaluator): return {'public_key_hex':evaluator['public_key_hex'],'public_key_fingerprint':evaluator['public_key_fingerprint'],'key_epoch_id':evaluator['key_epoch_id']}
'''

PY_VALIDATE = r'''def validate_lab(input):
 validate_portable(input);doc=deepcopy(input);evaluator=doc.get('evaluator')
 if not evaluator or evaluator.get('evaluator_id')!='eval_01HGENESISPRIVATE0001' or not __import__('re').fullmatch(r'[0-9a-f]{64}',evaluator.get('public_key_hex','')) or not __import__('re').fullmatch(r'sha256:[0-9a-f]{64}',evaluator.get('public_key_fingerprint','')) or not evaluator.get('key_epoch_id'): raise ValueError('evaluator_profile_invalid')
 c=doc['campaign'];cd=c.pop('campaign_digest')
 if h('campaign',c)!=cd: raise ValueError('campaign_digest_mismatch')
 c['campaign_digest']=cd
 if c.get('schema_version')!='genesis.improvement.campaign.v0.2' or c['forbidden_capabilities']!=FORBIDDEN or not c['guardian_grant_ref'] or not c.get('opened_at') or not c.get('authority_binding'): raise ValueError('authority_invalid')
 by={};accepted=[];rejected=[];buggy=[]
 for n in doc['candidates']:
  if n['candidate_id'] in by: raise ValueError('duplicate_candidate')
  evaluation_digest=compute_evaluator_digest(n,c['campaign_digest'])
  if n['evaluation_digest']!=evaluation_digest: raise ValueError('candidate_evaluation_digest_mismatch')
  verify_envelope(n['evaluator_signature'],evaluator_key(evaluator),digest=evaluation_digest,domain='genesis.improvement.candidate.evaluation.signature.v0.2',signer_type='evaluator',signer_id=evaluator['evaluator_id'],created_at=n['evaluated_at'],prefix='candidate_evaluation')
  d=n.pop('candidate_digest')
  if h('candidate',n)!=d: raise ValueError('candidate_digest_mismatch')
  n['candidate_digest']=d;p=n['parent_candidate_ref'];op=n['operator']
  if op not in {'draft','debug','improve'}: raise ValueError('operator_invalid')
  if op=='draft' and (p is not None or n['source_candidate_ref'] is not None): raise ValueError('draft_parent')
  if op!='draft' and (p not in by or n['source_candidate_ref']!=p): raise ValueError('parent_missing')
  if op=='debug' and not by[p]['execution']['buggy']: raise ValueError('debug_parent')
  if op=='improve' and by[p]['execution']['buggy']: raise ValueError('improve_parent')
  e=n['execution'];v=n['evaluation'];b=c['budget'];s='accepted'
  if e['buggy']: s='buggy'
  elif e['cpu_seconds']>b['max_cpu_seconds'] or e['memory_mb']>b['max_memory_mb'] or e['output_bytes']>b['max_output_bytes']: s='rejected_budget'
  elif not v['private_receipt_digest']: s='rejected_private_receipt'
  elif v['reward_hacking_detected']: s='rejected_reward_hacking'
  elif v['safety_regression_detected']: s='rejected_safety'
  elif not v['maintainability_passed']: s='rejected_maintainability'
  elif type(v['public_metric_milli']) is not int: s='rejected_metric'
  if s!=n['expected_status']: raise ValueError('status_mismatch')
  by[n['candidate_id']]=n;(buggy if s=='buggy' else accepted if s=='accepted' else rejected).append(n['candidate_id'])
 p=doc['expected_projection'];pd=p.pop('projection_digest');best=max(accepted,key=lambda x:by[x]['evaluation']['public_metric_milli']);calc={'campaign_ref':c['campaign_id'],'candidate_count':len(by),'accepted':accepted,'rejected':rejected,'buggy':buggy,'best_candidate_ref':best,'best_metric_milli':by[best]['evaluation']['public_metric_milli']}
 if calc!=p or h('projection',p)!=pd: raise ValueError('projection_mismatch')
 if len(doc['negative_case_ids'])!=20 or len(set(doc['negative_case_ids']))!=20: raise ValueError('negative_cases')
 return {'campaign':c,'candidates':list(by.values()),'projection':{**p,'projection_digest':pd},'best':best,'expected_authority':doc['expected_authority_execution']}
'''

PY_BOUNDARIES = r'''
def expect_lab_failure(label,fn):
 try: fn()
 except (AuthorityError,ValueError,KeyError,TypeError): return
 raise ValueError(f'{label}:accepted')
def run_lab_boundary_negatives(input):
 negatives=0;bad_signature=deepcopy(input);bad_signature['candidates'][0]['evaluator_signature']['signature_value']='0'*128;expect_lab_failure('evaluator_signature',lambda:validate_lab(bad_signature));negatives+=1;bad_nfc=deepcopy(input);bad_nfc['campaign']['goal']='Cafe\u0301';expect_lab_failure('lab_nfc',lambda:validate_lab(bad_nfc));negatives+=1;bad_integer=deepcopy(input);bad_integer['campaign']['budget']['max_steps']=9007199254740992;expect_lab_failure('lab_safe_integer',lambda:validate_lab(bad_integer));negatives+=1;return negatives
'''


def patch_validators() -> None:
    node_path = ROOT / "tools" / "validate_recursive_improvement_lab.mjs"
    node = node_path.read_text(encoding="utf-8")
    node = node.replace('const FORBIDDEN=["active_writer.assign","authority.self_grant","guardian.replace","identity.modify","main.protection.disable","memory.rewrite","private_eval.read"];\n', 'const FORBIDDEN=["active_writer.assign","authority.self_grant","guardian.replace","identity.modify","main.protection.disable","memory.rewrite","private_eval.read"];\n'+NODE_HELPERS, 1)
    node = sub_once(node, r'function validateLab\(input\)\{.*?\n\}', NODE_VALIDATE, "node-validate-lab", re.S)
    node = node.replace('function expectReason(label,expected,fn)', NODE_BOUNDARIES+'function expectReason(label,expected,fn)', 1)
    node = sub_once(node, r'function main\(\)\{.*?\ntry\{main\(\)', '''function main(){const raw=JSON.parse(fs.readFileSync(path.resolve(process.argv[2]??LAB),"utf8")),labNegatives=runLabBoundaryNegatives(raw),lab=validateLab(raw),integration=validateAuthority(lab,JSON.parse(fs.readFileSync(path.resolve(process.argv[3]??AUTH),"utf8")));console.log(`OK recursive improvement laboratory (${lab.projection.candidate_count} candidates; best=${lab.best})`);console.log(`OK projection digest ${lab.projection.projection_digest}`);console.log(`OK signed evaluator attestations (${lab.candidates.length})`);console.log(`OK signed exact-grant campaign authorization ${integration.receipt.campaign_authorization_digest}`);console.log(`OK candidate authority mapping (${integration.execution.summary.operation_count} signed uses; ${integration.execution.summary.final_grant_status})`);console.log(`OK candidate authority mapping digest ${integration.execution.summary.mapping_digest}`);console.log(`OK authority integration negative cases (${integration.negatives+labNegatives})`)}
try{main()''', "node-main", re.S)
    node_path.write_text(node, encoding="utf-8", newline="\n")

    py_path = ROOT / "tools" / "validate_recursive_improvement_lab.py"
    py = py_path.read_text(encoding="utf-8")
    py = py.replace("FORBIDDEN=['active_writer.assign','authority.self_grant','guardian.replace','identity.modify','main.protection.disable','memory.rewrite','private_eval.read']\n", "FORBIDDEN=['active_writer.assign','authority.self_grant','guardian.replace','identity.modify','main.protection.disable','memory.rewrite','private_eval.read']\n"+PY_HELPERS, 1)
    py = sub_once(py, r'def validate_lab\(input\):.*?\n(?=def expect_reason)', PY_VALIDATE+'\n', "py-validate-lab", re.S)
    py = py.replace('def expect_reason(label,expected,fn):', PY_BOUNDARIES+'def expect_reason(label,expected,fn):', 1)
    py = sub_once(py, r'def main\(\):\n.*?\nif __name__==', '''def main():
 raw=json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else LAB).read_text());lab_negatives=run_lab_boundary_negatives(raw);lab=validate_lab(raw);integration=validate_authority(lab,json.loads((Path(sys.argv[2]) if len(sys.argv)>2 else AUTH).read_text()));print(f"OK recursive improvement laboratory ({lab['projection']['candidate_count']} candidates; best={lab['best']})");print(f"OK projection digest {lab['projection']['projection_digest']}");print(f"OK signed evaluator attestations ({len(lab['candidates'])})");print(f"OK signed exact-grant campaign authorization {integration['receipt']['campaign_authorization_digest']}");print(f"OK candidate authority mapping ({integration['execution']['summary']['operation_count']} signed uses; {integration['execution']['summary']['final_grant_status']})");print(f"OK candidate authority mapping digest {integration['execution']['summary']['mapping_digest']}");print(f"OK authority integration negative cases ({integration['negatives']+lab_negatives})")
if __name__==''', "py-main", re.S)
    py_path.write_text(py, encoding="utf-8", newline="\n")


def migrate_vector() -> None:
    sys.path.insert(0, str((ROOT / "tools").resolve()))
    authority = importlib.import_module("validate_guided_autonomy_authority")
    path = ROOT / "conformance" / "recursive_improvement_lab_vectors.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    seed_hex = "22" * 32
    signing = SigningKey(bytes.fromhex(seed_hex))
    public_hex = signing.verify_key.encode().hex()
    evaluator = {
        "warning": "TEST ONLY - never use this seed outside conformance fixtures",
        "evaluator_id": "eval_01HGENESISPRIVATE0001",
        "seed_hex": seed_hex,
        "public_key_hex": public_hex,
        "public_key_fingerprint": "sha256:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest(),
        "key_epoch_id": "epoch_01HGENESIS_EVALUATOR01",
    }
    document["evaluator"] = evaluator
    key = {"seed_hex": seed_hex, "public_key_hex": public_hex, "public_key_fingerprint": evaluator["public_key_fingerprint"], "key_epoch_id": evaluator["key_epoch_id"]}
    for index, candidate in enumerate(document["candidates"]):
        candidate["evaluated_at"] = plus(document["campaign"]["opened_at"], 300 + index)
        candidate["evaluation_digest"] = authority.hash_authority_fields("genesis.improvement.candidate.evaluation.v0.2", [
            document["campaign"]["campaign_digest"], candidate["candidate_id"], "" if candidate["parent_candidate_ref"] is None else candidate["parent_candidate_ref"], candidate["operator"], candidate["patch_digest"], candidate["code_digest"],
            "true" if candidate["execution"]["buggy"] else "false", str(candidate["execution"]["cpu_seconds"]), str(candidate["execution"]["memory_mb"]), str(candidate["execution"]["output_bytes"]),
            "" if candidate["evaluation"]["public_metric_milli"] is None else str(candidate["evaluation"]["public_metric_milli"]), "" if candidate["evaluation"]["private_receipt_digest"] is None else candidate["evaluation"]["private_receipt_digest"],
            "true" if candidate["evaluation"]["reward_hacking_detected"] else "false", "true" if candidate["evaluation"]["safety_regression_detected"] else "false", "true" if candidate["evaluation"]["maintainability_passed"] else "false", candidate["expected_status"], candidate["evaluated_at"],
        ])
        candidate["evaluator_signature"] = authority.sign_fixture_envelope(key, "evaluator", evaluator["evaluator_id"], candidate["evaluation_digest"], "genesis.improvement.candidate.evaluation.signature.v0.2", candidate["evaluated_at"])
        unsigned = deepcopy(candidate)
        unsigned.pop("candidate_digest", None)
        candidate["candidate_digest"] = "sha256:" + hashlib.sha256(("candidate\n" + json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))).encode("utf-8")).hexdigest()
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def update_schema_and_negative() -> None:
    schema_path = ROOT / "schemas" / "recursive_improvement_lab.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if "evaluator" not in schema["required"]:
        schema["required"].insert(1, "evaluator")
    schema["$defs"]["signatureEnvelope"] = {
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"],
        "properties": {
            "schema_version": {"const": "genesis.signature.envelope.v0.1"}, "signature_profile": {"const": "genesis.signature.ed25519.v0.1"}, "signer_type": {"const": "evaluator"},
            "signer_id": {"type": "string", "minLength": 1}, "key_epoch_id": {"type": "string", "minLength": 1}, "signed_domain": {"const": "genesis.improvement.candidate.evaluation.signature.v0.2"},
            "signed_digest": {"$ref": "#/$defs/digest"}, "signature_value": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "created_at": {"type": "string", "format": "date-time", "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"},
            "public_key_ref": {"$ref": "#/$defs/digest"},
        },
    }
    schema["properties"]["evaluator"] = {
        "type": "object", "additionalProperties": False,
        "required": ["warning", "evaluator_id", "seed_hex", "public_key_hex", "public_key_fingerprint", "key_epoch_id"],
        "properties": {
            "warning": {"type": "string", "minLength": 1}, "evaluator_id": {"const": "eval_01HGENESISPRIVATE0001"}, "seed_hex": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "public_key_hex": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "public_key_fingerprint": {"$ref": "#/$defs/digest"}, "key_epoch_id": {"type": "string", "minLength": 1},
        },
    }
    candidate = schema["properties"]["candidates"]["items"]
    for field in ["evaluated_at", "evaluation_digest", "evaluator_signature"]:
        if field not in candidate["required"]:
            candidate["required"].append(field)
    candidate["properties"]["evaluated_at"] = {"type": "string", "format": "date-time", "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"}
    candidate["properties"]["evaluation_digest"] = {"$ref": "#/$defs/digest"}
    candidate["properties"]["evaluator_signature"] = {"$ref": "#/$defs/signatureEnvelope"}
    schema_path.write_text(json.dumps(schema, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    cases_path = ROOT / "conformance" / "schema_invalid_cases.json"
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    lab = json.loads((ROOT / "conformance" / "recursive_improvement_lab_vectors.json").read_text(encoding="utf-8"))
    case = next(item for item in cases["cases"] if item["case_id"] == "recursive-improvement-rejects-extra-field")
    case["artifact"] = deepcopy(lab);case["artifact"]["unexpected_core_field"] = True
    cases_path.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def update_docs() -> None:
    spec_path = ROOT / "spec" / "RECURSIVE_IMPROVEMENT_LAB.md"
    spec = spec_path.read_text(encoding="utf-8")
    marker = "- Ed25519 campaign attestations and signed use requests are verified;" if "- Ed25519 campaign attestations and signed use requests are verified;" in spec else None
    if marker:
        spec = spec.replace(marker, marker + "\n- each candidate evaluation carries an independent Ed25519 evaluator attestation;", 1)
    else:
        anchor = "## Conformidad implementada"
        if anchor not in spec: raise SystemExit("lab_spec_conformance_anchor_missing")
        spec = spec.replace(anchor, "## Atestación del evaluador\n\nCada candidato enlaza `evaluation_digest`, `evaluated_at` y una firma Ed25519 independiente del evaluador TEST ONLY. La firma cubre campaña, candidato, linaje, patch, código, ejecución, evaluación y estado esperado. Alterar la firma, el digest o cualquier campo enlazado produce rechazo.\n\n"+anchor, 1)
    spec = spec.replace("- digest determinista de campaña y candidatos;", "- UTF-8/NFC y enteros portables en campaña, candidatos y evaluaciones;\n- digest determinista de campaña y candidatos;", 1)
    spec = spec.replace("- firma Ed25519 de atestación de campaña;", "- firma Ed25519 de atestación de campaña y firmas independientes del evaluador por candidato;", 1)
    spec = spec.replace("- rechazo de grant sintético", "- rechazo de firma de evaluador alterada, texto no NFC, entero inseguro, grant sintético", 1)
    spec_path.write_text(spec, encoding="utf-8", newline="\n")

    checklist_path = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    checklist = checklist_path.read_text(encoding="utf-8")
    checklist = checklist.replace("y once rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión, revocación, ledger público o mapping de consumo inválido", "y catorce rechazos adicionales de autoridad, firma de campaña/evaluador, NFC, entero portable, tiempo, presupuesto, suspensión, revocación, ledger público o mapping de consumo inválido")
    checklist_path.write_text(checklist, encoding="utf-8", newline="\n")


def main() -> None:
    migrate_vector()
    patch_validators()
    update_schema_and_negative()
    update_docs()
    print("OK hardened laboratory evaluator attestations and portable inputs")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Temporary deterministic migration for candidate-to-authority-use mapping."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

NODE_SOURCE = r'''#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { computeEventHash } from "./guided_autonomy.mjs";
import {
  AuthorityError,
  authorityFromValidatedFixture,
  authorizeCampaignOpening,
  computeAuthorizedUseDigest,
  evaluateAuthorizedUse,
  hashAuthorityFields,
  resolveExactGrant,
  signFixtureEnvelope,
  validateAuthorityBundle,
  verifyEnvelope,
} from "./validate_guided_autonomy_authority.mjs";

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const LAB=path.join(ROOT,"conformance","recursive_improvement_lab_vectors.json");
const AUTH=path.join(ROOT,"conformance","guided_autonomy_vectors.json");
const FORBIDDEN=["active_writer.assign","authority.self_grant","guardian.replace","identity.modify","main.protection.disable","memory.rewrite","private_eval.read"];
function canonical(x){if(Array.isArray(x))return x.map(canonical);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])]));return x}
const h=(d,o)=>`sha256:${crypto.createHash("sha256").update(`${d}\n${JSON.stringify(canonical(o))}`).digest("hex")}`;
const plus=(ts,seconds)=>new Date(new Date(ts).getTime()+seconds*1000).toISOString().replace(".000Z","Z");
function validateLab(input){
 const doc=structuredClone(input),c=doc.campaign,cd=c.campaign_digest;delete c.campaign_digest;if(h("campaign",c)!==cd)throw Error("campaign_digest_mismatch");c.campaign_digest=cd;if(c.schema_version!=="genesis.improvement.campaign.v0.2"||JSON.stringify(c.forbidden_capabilities)!==JSON.stringify(FORBIDDEN)||!c.guardian_grant_ref||!c.opened_at||!c.authority_binding)throw Error("authority_invalid");
 const by=new Map(),accepted=[],rejected=[],buggy=[];for(const n of doc.candidates){if(by.has(n.candidate_id))throw Error("duplicate_candidate");const d=n.candidate_digest;delete n.candidate_digest;if(h("candidate",n)!==d)throw Error("candidate_digest_mismatch");n.candidate_digest=d;const p=n.parent_candidate_ref,op=n.operator;if(!["draft","debug","improve"].includes(op))throw Error("operator_invalid");if(op==="draft"&&(p!==null||n.source_candidate_ref!==null))throw Error("draft_parent");if(op!=="draft"&&(!by.has(p)||n.source_candidate_ref!==p))throw Error("parent_missing");if(op==="debug"&&!by.get(p).execution.buggy)throw Error("debug_parent");if(op==="improve"&&by.get(p).execution.buggy)throw Error("improve_parent");const e=n.execution,v=n.evaluation,b=c.budget;let s="accepted";if(e.buggy)s="buggy";else if(e.cpu_seconds>b.max_cpu_seconds||e.memory_mb>b.max_memory_mb||e.output_bytes>b.max_output_bytes)s="rejected_budget";else if(!v.private_receipt_digest)s="rejected_private_receipt";else if(v.reward_hacking_detected)s="rejected_reward_hacking";else if(v.safety_regression_detected)s="rejected_safety";else if(!v.maintainability_passed)s="rejected_maintainability";else if(!Number.isInteger(v.public_metric_milli))s="rejected_metric";if(s!==n.expected_status)throw Error("status_mismatch");by.set(n.candidate_id,n);(s==="buggy"?buggy:s==="accepted"?accepted:rejected).push(n.candidate_id)}
 const p=doc.expected_projection,pd=p.projection_digest;delete p.projection_digest;const best=accepted.reduce((a,b)=>by.get(a).evaluation.public_metric_milli>=by.get(b).evaluation.public_metric_milli?a:b);const calc={campaign_ref:c.campaign_id,candidate_count:by.size,accepted,rejected,buggy,best_candidate_ref:best,best_metric_milli:by.get(best).evaluation.public_metric_milli};if(JSON.stringify(calc)!==JSON.stringify(p)||h("projection",p)!==pd)throw Error("projection_mismatch");if(doc.negative_case_ids.length!==20||new Set(doc.negative_case_ids).size!==20)throw Error("negative_cases");return{campaign:c,candidates:[...by.values()],projection:{...p,projection_digest:pd},best,expectedAuthority:doc.expected_authority_execution};
}
function expectReason(label,expected,fn){const r=fn(),actual=r.decision_reason??r.reason;if(actual!==expected)throw Error(`${label}:expected:${expected}:got:${actual}`)}
function expectFailure(label,fn){try{fn()}catch(e){if(e instanceof AuthorityError)return;throw e}throw Error(`${label}:accepted`)}
export function buildCandidateAuthorityExecution(lab,guided,baseAuthority,checkExpected=true){
 const grant=baseAuthority.grants.get(lab.campaign.guardian_grant_ref);if(!grant)throw Error("candidate_mapping_grant_missing");const binding=lab.campaign.authority_binding,bundle=structuredClone(baseAuthority.bundle),mapping=[];let cursor=plus(lab.campaign.opened_at,60),index=0,currentAuthority=baseAuthority;
 for(const candidate of lab.candidates){const actions=["compile",...(candidate.execution.buggy?[]:["test"])];for(const actionClass of actions){index++;const n=String(index).padStart(2,"0"),use={schema_version:"genesis.autonomy.capability.use.v0.2",hash_profile:"genesis.hash.fields.v0.1",use_id:`use_01HRILAB_${n}`,grant_ref:grant.grant_id,instance_id:lab.campaign.instance_id,body_id:binding.body_id,capability:binding.capability,target_ref:binding.target_ref,action_class:actionClass,data_class:binding.data_class,requested_actions:1,requested_duration_seconds:Math.max(1,Math.min(candidate.execution.cpu_seconds,grant.budget.max_duration_seconds)),requested_bytes:Math.min(candidate.execution.output_bytes,grant.budget.max_bytes_per_run),sandboxed:binding.sandboxed,human_confirmation_ref:`confirm_01HRILAB_${n}`,observer_ref:`observer_01HRILAB_${n}`,reversible_plan_ref:`revert_01HRILAB_${n}`,requested_at:cursor,use_digest:"",signature:null};use.use_digest=computeAuthorizedUseDigest(use);use.signature=signFixtureEnvelope(guided.keys.body,"body",binding.body_id,use.use_digest,"genesis.autonomy.capability.use.signature.v0.2",use.requested_at);bundle.use_requests.push(use);currentAuthority=validateAuthorityBundle(bundle,baseAuthority.keyResolver);const decision=evaluateAuthorizedUse(use,currentAuthority);if(decision.status!=="allowed")throw Error(`candidate_use_denied:${candidate.candidate_id}:${actionClass}:${decision.reason}`);const recordedAt=plus(cursor,1),event={schema_version:guided.domains.event,hash_profile:"genesis.hash.fields.v0.1",ledger_id:bundle.ledger_events[0].ledger_id,event_id:`capevent_01HRILAB_${n}`,sequence:bundle.ledger_events.length,previous_event_hash:bundle.ledger_events.at(-1).event_hash,guardian_id:guided.guardian_id,instance_id:guided.instance_id,authority_epoch:guided.authority_epoch,event_type:"grant.consumed",grant_ref:grant.grant_id,body_id:binding.body_id,use_id:use.use_id,subject_digest:use.use_digest,recorded_at:recordedAt,event_hash:"",signature:null};event.event_hash=computeEventHash(event);event.signature=signFixtureEnvelope(guided.keys.body,"body",binding.body_id,event.event_hash,guided.domains.event_signature,recordedAt);bundle.ledger_events.push(event);currentAuthority=validateAuthorityBundle(bundle,baseAuthority.keyResolver);mapping.push({candidate_ref:candidate.candidate_id,action_class:actionClass,use_ref:use.use_id,event_ref:event.event_id,decision_digest:decision.decision_digest});cursor=plus(cursor,2)}}
 const finalResolved=resolveExactGrant(grant.grant_id,grant.capability,grant.instance_id,cursor,currentAuthority);if(finalResolved.reason!=="grant_exhausted")throw Error(`candidate_mapping_not_exhausted:${finalResolved.reason}`);const fields=[lab.campaign.campaign_id,grant.grant_id,String(mapping.length),...mapping.flatMap(item=>[item.candidate_ref,item.action_class,item.use_ref,item.event_ref,item.decision_digest])],summary={operation_count:mapping.length,compile_count:mapping.filter(item=>item.action_class==="compile").length,test_count:mapping.filter(item=>item.action_class==="test").length,consumed_use_count:finalResolved.state.consumed.size,final_grant_status:"exhausted",mapping_digest:hashAuthorityFields("genesis.improvement.candidate.authority.mapping.v0.1",fields),final_ledger_head_hash:bundle.ledger_events.at(-1).event_hash};if(checkExpected&&JSON.stringify(summary)!==JSON.stringify(lab.expectedAuthority))throw Error("candidate_authority_mapping_mismatch");return{summary,mapping,bundle,authority:currentAuthority,firstUse:bundle.use_requests.at(-mapping.length)};
}
function validateAuthority(lab,guided){
 const authority=authorityFromValidatedFixture(guided);if(["keys","expected","must_reject"].some(field=>Object.hasOwn(authority.bundle,field)))throw Error("neutral_bundle_contains_test_fields");const grant=guided.grants.find(g=>g.grant_id===lab.campaign.guardian_grant_ref);if(!grant)throw Error("declared_grant_missing");if(lab.campaign.instance_id!==guided.instance_id||grant.instance_id!==lab.campaign.instance_id)throw Error("campaign_instance_mismatch");const binding=lab.campaign.authority_binding,issued=guided.ledger_events.find(e=>e.grant_ref===grant.grant_id&&e.event_type==="grant.issued");if(!issued)throw Error("sandbox_grant_not_issued");const opened=lab.campaign.opened_at,campaignSig=signFixtureEnvelope(guided.keys.guardian,"guardian",guided.guardian_id,lab.campaign.campaign_digest,"genesis.improvement.campaign.signature.v0.2",opened);verifyEnvelope(campaignSig,guided.keys.guardian,{digest:lab.campaign.campaign_digest,domain:"genesis.improvement.campaign.signature.v0.2",signerType:"guardian",signerId:guided.guardian_id,createdAt:opened,prefix:"campaign"});const request={campaign_digest:lab.campaign.campaign_digest,grant_ref:grant.grant_id,instance_id:lab.campaign.instance_id,...binding,authorized_at:opened},receipt=authorizeCampaignOpening(request,authority);if(receipt.decision_status!=="allowed")throw Error(`campaign_authorization_failed:${receipt.decision_reason}`);const execution=buildCandidateAuthorityExecution(lab,guided,authority,true);
 let negatives=0;expectReason("synthetic","grant_missing",()=>authorizeCampaignOpening({...request,grant_ref:"grant_code_sandbox_001"},authority));negatives++;expectReason("instance","grant_instance_mismatch",()=>authorizeCampaignOpening({...request,instance_id:"inst_wrong"},authority));negatives++;expectReason("early","grant_not_yet_valid",()=>authorizeCampaignOpening({...request,authorized_at:plus(grant.not_before,-1)},authority));negatives++;expectReason("bytes","byte_budget_exceeded",()=>authorizeCampaignOpening({...request,requested_bytes:grant.budget.max_bytes_per_run+1},authority));negatives++;const badSig=structuredClone(campaignSig);badSig.signature_value="0".repeat(128);expectFailure("campaign_signature",()=>verifyEnvelope(badSig,guided.keys.guardian,{digest:lab.campaign.campaign_digest,domain:"genesis.improvement.campaign.signature.v0.2",signerType:"guardian",signerId:guided.guardian_id,createdAt:opened,prefix:"campaign"}));negatives++;const badUse=structuredClone(execution.firstUse);badUse.grant_ref="grant_other";expectFailure("signed_grant_ref",()=>evaluateAuthorizedUse(badUse,authority));negatives++;
 const controlGrant=guided.grants.find(item=>item.grant_id==="grant_01HAUTONOMY_CODE000001");for(const [eventType,reason] of [["grant.suspended","grant_suspended"],["grant.revoked","grant_revoked"]]){const event=guided.ledger_events.find(e=>e.grant_ref===controlGrant.grant_id&&e.event_type===eventType);expectReason(eventType,reason,()=>authorizeCampaignOpening({...request,grant_ref:controlGrant.grant_id,authorized_at:event.recorded_at},authority));negatives++}
 const broken=structuredClone(authority.bundle);broken.ledger_events[1].previous_event_hash="sha256:"+"0".repeat(64);expectFailure("neutral_bundle_ledger",()=>validateAuthorityBundle(broken,authority.keyResolver));negatives++;const wrongEvent=structuredClone(execution.bundle);wrongEvent.ledger_events.at(-1).grant_ref="grant_other";expectFailure("candidate_consumption_grant",()=>validateAuthorityBundle(wrongEvent,authority.keyResolver));negatives++;const shortened=structuredClone(execution.bundle);shortened.ledger_events.pop();const shortenedAuthority=validateAuthorityBundle(shortened,authority.keyResolver),shortenedState=resolveExactGrant(grant.grant_id,grant.capability,grant.instance_id,plus(shortened.ledger_events.at(-1).recorded_at,1),shortenedAuthority);if(shortenedState.reason==="grant_exhausted")throw Error("candidate_mapping_missing_event_accepted");negatives++;return{receipt,execution,negatives};
}
function main(){const lab=validateLab(JSON.parse(fs.readFileSync(path.resolve(process.argv[2]??LAB),"utf8"))),integration=validateAuthority(lab,JSON.parse(fs.readFileSync(path.resolve(process.argv[3]??AUTH),"utf8")));console.log(`OK recursive improvement laboratory (${lab.projection.candidate_count} candidates; best=${lab.best})`);console.log(`OK projection digest ${lab.projection.projection_digest}`);console.log(`OK signed exact-grant campaign authorization ${integration.receipt.campaign_authorization_digest}`);console.log(`OK candidate authority mapping (${integration.execution.summary.operation_count} signed uses; ${integration.execution.summary.final_grant_status})`);console.log(`OK candidate authority mapping digest ${integration.execution.summary.mapping_digest}`);console.log(`OK authority integration negative cases (${integration.negatives})`)}
try{main()}catch(error){console.error(`FAIL recursive improvement laboratory: ${error.message}`);process.exit(1)}
'''

PY_SOURCE = r'''#!/usr/bin/env python3
from __future__ import annotations
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib,json,sys
from pathlib import Path
from validate_guided_autonomy import compute_event_hash
from validate_guided_autonomy_authority import AuthorityError,authority_from_validated_fixture,authorize_campaign_opening,compute_authorized_use_digest,evaluate_authorized_use,hash_authority_fields,resolve_exact_grant,sign_fixture_envelope,validate_authority_bundle,verify_envelope
ROOT=Path(__file__).resolve().parents[1];LAB=ROOT/'conformance'/'recursive_improvement_lab_vectors.json';AUTH=ROOT/'conformance'/'guided_autonomy_vectors.json'
FORBIDDEN=['active_writer.assign','authority.self_grant','guardian.replace','identity.modify','main.protection.disable','memory.rewrite','private_eval.read']
def h(domain,obj): return 'sha256:'+hashlib.sha256((domain+'\n'+json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))).encode()).hexdigest()
def plus(ts,seconds): return (datetime.fromisoformat(ts.replace('Z','+00:00'))+timedelta(seconds=seconds)).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def validate_lab(input):
 doc=deepcopy(input);c=doc['campaign'];cd=c.pop('campaign_digest')
 if h('campaign',c)!=cd: raise ValueError('campaign_digest_mismatch')
 c['campaign_digest']=cd
 if c.get('schema_version')!='genesis.improvement.campaign.v0.2' or c['forbidden_capabilities']!=FORBIDDEN or not c['guardian_grant_ref'] or not c.get('opened_at') or not c.get('authority_binding'): raise ValueError('authority_invalid')
 by={};accepted=[];rejected=[];buggy=[]
 for n in doc['candidates']:
  if n['candidate_id'] in by: raise ValueError('duplicate_candidate')
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
def expect_reason(label,expected,fn):
 r=fn();actual=r.get('decision_reason',r.get('reason'))
 if actual!=expected: raise ValueError(f'{label}:expected:{expected}:got:{actual}')
def expect_failure(label,fn):
 try: fn()
 except AuthorityError: return
 raise ValueError(f'{label}:accepted')
def build_candidate_authority_execution(lab,guided,base_authority,check_expected=True):
 grant=base_authority.grants.get(lab['campaign']['guardian_grant_ref'])
 if grant is None: raise ValueError('candidate_mapping_grant_missing')
 binding=lab['campaign']['authority_binding'];bundle=deepcopy(base_authority.bundle);mapping=[];cursor=plus(lab['campaign']['opened_at'],60);index=0;current=base_authority
 for candidate in lab['candidates']:
  actions=['compile']+([] if candidate['execution']['buggy'] else ['test'])
  for action_class in actions:
   index+=1;n=f'{index:02d}';use={'schema_version':'genesis.autonomy.capability.use.v0.2','hash_profile':'genesis.hash.fields.v0.1','use_id':f'use_01HRILAB_{n}','grant_ref':grant['grant_id'],'instance_id':lab['campaign']['instance_id'],'body_id':binding['body_id'],'capability':binding['capability'],'target_ref':binding['target_ref'],'action_class':action_class,'data_class':binding['data_class'],'requested_actions':1,'requested_duration_seconds':max(1,min(candidate['execution']['cpu_seconds'],grant['budget']['max_duration_seconds'])),'requested_bytes':min(candidate['execution']['output_bytes'],grant['budget']['max_bytes_per_run']),'sandboxed':binding['sandboxed'],'human_confirmation_ref':f'confirm_01HRILAB_{n}','observer_ref':f'observer_01HRILAB_{n}','reversible_plan_ref':f'revert_01HRILAB_{n}','requested_at':cursor,'use_digest':'','signature':None};use['use_digest']=compute_authorized_use_digest(use);use['signature']=sign_fixture_envelope(guided['keys']['body'],'body',binding['body_id'],use['use_digest'],'genesis.autonomy.capability.use.signature.v0.2',use['requested_at']);bundle['use_requests'].append(use);current=validate_authority_bundle(bundle,base_authority.key_resolver);decision=evaluate_authorized_use(use,current)
   if decision['status']!='allowed': raise ValueError(f"candidate_use_denied:{candidate['candidate_id']}:{action_class}:{decision['reason']}")
   recorded=plus(cursor,1);event={'schema_version':guided['domains']['event'],'hash_profile':'genesis.hash.fields.v0.1','ledger_id':bundle['ledger_events'][0]['ledger_id'],'event_id':f'capevent_01HRILAB_{n}','sequence':len(bundle['ledger_events']),'previous_event_hash':bundle['ledger_events'][-1]['event_hash'],'guardian_id':guided['guardian_id'],'instance_id':guided['instance_id'],'authority_epoch':guided['authority_epoch'],'event_type':'grant.consumed','grant_ref':grant['grant_id'],'body_id':binding['body_id'],'use_id':use['use_id'],'subject_digest':use['use_digest'],'recorded_at':recorded,'event_hash':'','signature':None};event['event_hash']=compute_event_hash(event);event['signature']=sign_fixture_envelope(guided['keys']['body'],'body',binding['body_id'],event['event_hash'],guided['domains']['event_signature'],recorded);bundle['ledger_events'].append(event);current=validate_authority_bundle(bundle,base_authority.key_resolver);mapping.append({'candidate_ref':candidate['candidate_id'],'action_class':action_class,'use_ref':use['use_id'],'event_ref':event['event_id'],'decision_digest':decision['decision_digest']});cursor=plus(cursor,2)
 final_resolved=resolve_exact_grant(grant['grant_id'],grant['capability'],grant['instance_id'],cursor,current)
 if final_resolved['reason']!='grant_exhausted': raise ValueError('candidate_mapping_not_exhausted:'+final_resolved['reason'])
 fields=[lab['campaign']['campaign_id'],grant['grant_id'],str(len(mapping))]
 for item in mapping: fields += [item['candidate_ref'],item['action_class'],item['use_ref'],item['event_ref'],item['decision_digest']]
 summary={'operation_count':len(mapping),'compile_count':sum(i['action_class']=='compile' for i in mapping),'test_count':sum(i['action_class']=='test' for i in mapping),'consumed_use_count':len(final_resolved['state']['consumed']),'final_grant_status':'exhausted','mapping_digest':hash_authority_fields('genesis.improvement.candidate.authority.mapping.v0.1',fields),'final_ledger_head_hash':bundle['ledger_events'][-1]['event_hash']}
 if check_expected and summary!=lab['expected_authority']: raise ValueError('candidate_authority_mapping_mismatch')
 return {'summary':summary,'mapping':mapping,'bundle':bundle,'authority':current,'first_use':bundle['use_requests'][-len(mapping)]}
def validate_authority(lab,guided):
 authority=authority_from_validated_fixture(guided)
 if any(field in authority.bundle for field in ['keys','expected','must_reject']): raise ValueError('neutral_bundle_contains_test_fields')
 grant=guided['grants'][next(i for i,g in enumerate(guided['grants']) if g['grant_id']==lab['campaign']['guardian_grant_ref'])]
 if grant['instance_id']!=lab['campaign']['instance_id']: raise ValueError('campaign_instance_mismatch')
 binding=lab['campaign']['authority_binding'];opened=lab['campaign']['opened_at'];campaign_sig=sign_fixture_envelope(guided['keys']['guardian'],'guardian',guided['guardian_id'],lab['campaign']['campaign_digest'],'genesis.improvement.campaign.signature.v0.2',opened);verify_envelope(campaign_sig,guided['keys']['guardian'],digest=lab['campaign']['campaign_digest'],domain='genesis.improvement.campaign.signature.v0.2',signer_type='guardian',signer_id=guided['guardian_id'],created_at=opened,prefix='campaign');request={'campaign_digest':lab['campaign']['campaign_digest'],'grant_ref':grant['grant_id'],'instance_id':lab['campaign']['instance_id'],**binding,'authorized_at':opened};receipt=authorize_campaign_opening(request,authority)
 if receipt['decision_status']!='allowed': raise ValueError('campaign_authorization_failed:'+receipt['decision_reason'])
 execution=build_candidate_authority_execution(lab,guided,authority,True);negatives=0;expect_reason('synthetic','grant_missing',lambda:authorize_campaign_opening({**request,'grant_ref':'grant_code_sandbox_001'},authority));negatives+=1;expect_reason('instance','grant_instance_mismatch',lambda:authorize_campaign_opening({**request,'instance_id':'inst_wrong'},authority));negatives+=1;expect_reason('early','grant_not_yet_valid',lambda:authorize_campaign_opening({**request,'authorized_at':plus(grant['not_before'],-1)},authority));negatives+=1;expect_reason('bytes','byte_budget_exceeded',lambda:authorize_campaign_opening({**request,'requested_bytes':grant['budget']['max_bytes_per_run']+1},authority));negatives+=1
 bad_sig=deepcopy(campaign_sig);bad_sig['signature_value']='0'*128;expect_failure('campaign_signature',lambda:verify_envelope(bad_sig,guided['keys']['guardian'],digest=lab['campaign']['campaign_digest'],domain='genesis.improvement.campaign.signature.v0.2',signer_type='guardian',signer_id=guided['guardian_id'],created_at=opened,prefix='campaign'));negatives+=1;bad_use=deepcopy(execution['first_use']);bad_use['grant_ref']='grant_other';expect_failure('signed_grant_ref',lambda:evaluate_authorized_use(bad_use,authority));negatives+=1
 control=next(g for g in guided['grants'] if g['grant_id']=='grant_01HAUTONOMY_CODE000001')
 for event_type,reason in [('grant.suspended','grant_suspended'),('grant.revoked','grant_revoked')]:
  event=next(e for e in guided['ledger_events'] if e['grant_ref']==control['grant_id'] and e['event_type']==event_type);expect_reason(event_type,reason,lambda event=event:authorize_campaign_opening({**request,'grant_ref':control['grant_id'],'authorized_at':event['recorded_at']},authority));negatives+=1
 broken=deepcopy(authority.bundle);broken['ledger_events'][1]['previous_event_hash']='sha256:'+'0'*64;expect_failure('neutral_bundle_ledger',lambda:validate_authority_bundle(broken,authority.key_resolver));negatives+=1;wrong=deepcopy(execution['bundle']);wrong['ledger_events'][-1]['grant_ref']='grant_other';expect_failure('candidate_consumption_grant',lambda:validate_authority_bundle(wrong,authority.key_resolver));negatives+=1;short=deepcopy(execution['bundle']);short['ledger_events'].pop();short_authority=validate_authority_bundle(short,authority.key_resolver);short_state=resolve_exact_grant(grant['grant_id'],grant['capability'],grant['instance_id'],plus(short['ledger_events'][-1]['recorded_at'],1),short_authority)
 if short_state['reason']=='grant_exhausted': raise ValueError('candidate_mapping_missing_event_accepted')
 negatives+=1;return {'receipt':receipt,'execution':execution,'negatives':negatives}
def main():
 lab=validate_lab(json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else LAB).read_text()));integration=validate_authority(lab,json.loads((Path(sys.argv[2]) if len(sys.argv)>2 else AUTH).read_text()));print(f"OK recursive improvement laboratory ({lab['projection']['candidate_count']} candidates; best={lab['best']})");print(f"OK projection digest {lab['projection']['projection_digest']}");print(f"OK signed exact-grant campaign authorization {integration['receipt']['campaign_authorization_digest']}");print(f"OK candidate authority mapping ({integration['execution']['summary']['operation_count']} signed uses; {integration['execution']['summary']['final_grant_status']})");print(f"OK candidate authority mapping digest {integration['execution']['summary']['mapping_digest']}");print(f"OK authority integration negative cases ({integration['negatives']})")
if __name__=='__main__':
 try: main()
 except (AuthorityError,ValueError,KeyError,TypeError,AssertionError) as error: print(f'FAIL recursive improvement laboratory: {error}',file=sys.stderr);raise SystemExit(1)
'''


def plus(ts: str, seconds: int) -> str:
    return (datetime.fromisoformat(ts.replace("Z", "+00:00")) + timedelta(seconds=seconds)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def migrate_guided_fixture() -> tuple[dict, str]:
    sys.path.insert(0, str((ROOT / "tools").resolve()))
    ga = importlib.import_module("validate_guided_autonomy")
    path = ROOT / "conformance" / "guided_autonomy_vectors.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    source_grant = next(item for item in document["grants"] if item["grant_id"] == "grant_01HAUTONOMY_CODE000001")
    source_proposal = next(item for item in document["proposals"] if item["proposal_id"] == source_grant["proposal_ref"])
    source_evaluation = next(item for item in document["evaluations"] if item["evaluation_id"] == source_grant["evaluation_ref"])
    last_recorded = max(item["recorded_at"] for item in document["ledger_events"])
    issued_at = plus(last_recorded, 60)
    recorded_at = plus(issued_at, 1)
    opened_at = plus(recorded_at, 1)

    proposal = deepcopy(source_proposal)
    proposal["proposal_id"] = "proposal_01HAUTONOMY_RILAB001"
    proposal["scope"]["allowed_action_classes"] = ["compile", "test"]
    proposal["budget"] = {"max_actions_per_run": 1, "max_duration_seconds": 120, "max_bytes_per_run": 2000000}
    proposal["reason"] = "Ejecutar las operaciones compile y test del laboratorio mediante usos firmados por candidato."
    proposal["created_at"] = plus(issued_at, -20)
    ga.resign_proposal(document, proposal)

    evaluation = deepcopy(source_evaluation)
    evaluation["evaluation_id"] = "evaluation_01HAUTONOMY_RILAB1"
    evaluation["proposal_ref"] = proposal["proposal_id"]
    evaluation["proposal_digest"] = proposal["proposal_digest"]
    evaluation["evaluated_at"] = plus(issued_at, -10)
    ga.resign_evaluation(document, evaluation)

    grant = deepcopy(source_grant)
    grant["grant_id"] = "grant_01HAUTONOMY_RILAB0001"
    grant["proposal_ref"] = proposal["proposal_id"]
    grant["proposal_digest"] = proposal["proposal_digest"]
    grant["evaluation_ref"] = evaluation["evaluation_id"]
    grant["evaluation_digest"] = evaluation["evaluation_digest"]
    grant["scope"]["allowed_action_classes"] = ["compile", "test"]
    grant["budget"] = deepcopy(proposal["budget"])
    grant["issued_at"] = issued_at
    grant["not_before"] = issued_at
    grant["expires_at"] = plus(issued_at, 86400)
    grant["use_limit"] = 11
    grant["replaces_grant_ref"] = None
    ga.resign_grant(document, grant)
    document["proposals"].append(proposal)
    document["evaluations"].append(evaluation)
    document["grants"].append(grant)

    template = next(item for item in document["ledger_events"] if item["event_type"] == "grant.issued")
    event = deepcopy(template)
    event["event_id"] = "capevent_01HAUTONOMY_RILAB01"
    event["grant_ref"] = grant["grant_id"]
    event["subject_digest"] = grant["grant_digest"]
    event["recorded_at"] = recorded_at
    document["ledger_events"].append(event)
    document["ledger_events"].sort(key=lambda item: (item["recorded_at"], item["event_id"]))
    for index, item in enumerate(document["ledger_events"]):
        item["sequence"] = index
    ga.rebuild_ledger(document)
    document["expected"]["projection_at"] = opened_at
    decisions = [ga.evaluate_use(item, document["grants"], document["ledger_events"], set(document["registered_body_ids"])) for item in document["use_requests"]]
    projection = ga.build_projection(document, document["grants"], document["ledger_events"])
    document["expected"]["projection_digest"] = projection["projection_digest"]
    document["expected"]["decision_digests"] = {item["use_id"]: item["decision_digest"] for item in decisions}
    document["expected"]["allowed_count"] = sum(item["status"] == "allowed" for item in decisions)
    document["expected"]["denied_count"] = sum(item["status"] == "denied" for item in decisions)
    ga.validate_document(deepcopy(document))
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return document, opened_at


def migrate_lab_fixture(guided: dict, opened_at: str) -> None:
    path = ROOT / "conformance" / "recursive_improvement_lab_vectors.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    campaign = document["campaign"]
    campaign["guardian_grant_ref"] = "grant_01HAUTONOMY_RILAB0001"
    campaign["opened_at"] = opened_at
    unsigned = deepcopy(campaign)
    unsigned.pop("campaign_digest", None)
    payload = "campaign\n" + json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    campaign["campaign_digest"] = "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    document["expected_authority_execution"] = {"operation_count": 0, "compile_count": 0, "test_count": 0, "consumed_use_count": 0, "final_grant_status": "exhausted", "mapping_digest": "sha256:" + "0" * 64, "final_ledger_head_hash": "sha256:" + "0" * 64}
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    (ROOT / "tools" / "validate_recursive_improvement_lab.mjs").write_text(NODE_SOURCE, encoding="utf-8", newline="\n")
    (ROOT / "tools" / "validate_recursive_improvement_lab.py").write_text(PY_SOURCE, encoding="utf-8", newline="\n")
    sys.path.insert(0, str((ROOT / "tools").resolve()))
    module = importlib.import_module("validate_recursive_improvement_lab")
    lab = module.validate_lab(deepcopy(document))
    authority = module.authority_from_validated_fixture(guided)
    result = module.build_candidate_authority_execution(lab, guided, authority, False)
    document["expected_authority_execution"] = result["summary"]
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    module.validate_authority(module.validate_lab(deepcopy(document)), guided)


def update_schema_and_negative() -> None:
    schema_path = ROOT / "schemas" / "recursive_improvement_lab.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if "expected_authority_execution" not in schema["required"]:
        schema["required"].append("expected_authority_execution")
    schema["properties"]["expected_authority_execution"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["operation_count", "compile_count", "test_count", "consumed_use_count", "final_grant_status", "mapping_digest", "final_ledger_head_hash"],
        "properties": {
            "operation_count": {"const": 11},
            "compile_count": {"const": 6},
            "test_count": {"const": 5},
            "consumed_use_count": {"const": 11},
            "final_grant_status": {"const": "exhausted"},
            "mapping_digest": {"$ref": "#/$defs/digest"},
            "final_ledger_head_hash": {"$ref": "#/$defs/digest"},
        },
    }
    schema_path.write_text(json.dumps(schema, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    cases_path = ROOT / "conformance" / "schema_invalid_cases.json"
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    lab = json.loads((ROOT / "conformance" / "recursive_improvement_lab_vectors.json").read_text(encoding="utf-8"))
    case = next(item for item in cases["cases"] if item["case_id"] == "recursive-improvement-rejects-extra-field")
    case["artifact"] = deepcopy(lab)
    case["artifact"]["unexpected_core_field"] = True
    cases_path.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def update_docs() -> None:
    lab_path = ROOT / "spec" / "RECURSIVE_IMPROVEMENT_LAB.md"
    text = lab_path.read_text(encoding="utf-8")
    anchor = "## Presupuesto"
    section = '''## Mapeo candidato → uso → consumo

El perfil de conformidad `v0.2` asigna operaciones de autoridad de forma determinista:

- cada candidato genera una solicitud firmada `compile`;
- un candidato cuya ejecución no es `buggy` genera además una solicitud firmada `test`;
- cada solicitud permitida se enlaza inmediatamente a un evento firmado `grant.consumed`;
- `candidate_ref`, `action_class`, `use_ref`, `event_ref` y `decision_digest` forman un mapping digest reproducible.

Los seis candidatos producen once solicitudes: seis `compile` y cinco `test`. El grant dedicado de laboratorio tiene `use_limit = 11`; después del último consumo su estado debe ser `exhausted`. Omitir un consumo o cambiar el grant de un evento invalida la prueba.

'''
    if anchor not in text:
        raise SystemExit("lab_mapping_anchor_missing")
    text = text.replace(anchor, section + anchor, 1)
    text = text.replace("- definir el mapeo candidato → solicitudes firmadas y sus consumos;\n", "")
    text = text.replace("y nueve rechazos adicionales", "y once rechazos adicionales")
    lab_path.write_text(text, encoding="utf-8", newline="\n")

    guided_path = ROOT / "spec" / "GUIDED_AUTONOMY_AND_CAPABILITY_GRANTS.md"
    guided = guided_path.read_text(encoding="utf-8")
    marker = "Las proyecciones ordenan puertas por `(capability, grant_id)` en bytes UTF-8."
    replacement = marker + "\n\nEl vector integrado incluye un grant dedicado `code.execute_sandbox` para el laboratorio, con once usos limitados que demuestran el encadenamiento candidato→solicitud→consumo. Su ID es de conformidad, no normativo."
    if marker not in guided:
        raise SystemExit("guided_lab_grant_anchor_missing")
    guided_path.write_text(guided.replace(marker, replacement, 1), encoding="utf-8", newline="\n")

    checklist_path = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    checklist = checklist_path.read_text(encoding="utf-8")
    checklist = checklist.replace("tres puertas, ocho eventos append-only", "cuatro puertas, nueve eventos append-only")
    checklist = checklist.replace("y nueve rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión, revocación o ledger público inválido.", "y once rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión, revocación, ledger público o mapping de consumo inválido; seis candidatos producen once usos firmados y agotan el grant dedicado.")
    checklist = checklist.replace("          - [ ] Definir y verificar el mapeo candidato→solicitudes firmadas→eventos `grant.consumed`.\n", "")
    checklist_path.write_text(checklist, encoding="utf-8", newline="\n")


def main() -> None:
    guided, opened_at = migrate_guided_fixture()
    migrate_lab_fixture(guided, opened_at)
    update_schema_and_negative()
    update_docs()
    print("OK mapped candidates to signed uses and consumed events")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
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

#!/usr/bin/env python3
from __future__ import annotations
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib,json,sys
from pathlib import Path
from validate_guided_autonomy_authority import AuthorityError,authority_from_validated_fixture,authorize_campaign_opening,compute_authorized_use_digest,evaluate_authorized_use,sign_fixture_envelope,verify_envelope
ROOT=Path(__file__).resolve().parents[1];LAB=ROOT/'conformance'/'recursive_improvement_lab_vectors.json';AUTH=ROOT/'conformance'/'guided_autonomy_vectors.json'
FORBIDDEN=['active_writer.assign','authority.self_grant','guardian.replace','identity.modify','main.protection.disable','memory.rewrite','private_eval.read']
def h(domain,obj): return 'sha256:'+hashlib.sha256((domain+'\n'+json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))).encode()).hexdigest()
def plus(ts,seconds): return (datetime.fromisoformat(ts.replace('Z','+00:00'))+timedelta(seconds=seconds)).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def validate_lab(input):
 doc=deepcopy(input);c=doc['campaign'];cd=c.pop('campaign_digest')
 if h('campaign',c)!=cd: raise ValueError('campaign_digest_mismatch')
 c['campaign_digest']=cd
 if c['forbidden_capabilities']!=FORBIDDEN or not c['guardian_grant_ref']: raise ValueError('authority_invalid')
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
 return {'campaign':c,'projection':{**p,'projection_digest':pd},'best':best}
def expect_reason(label,expected,fn):
 r=fn();actual=r.get('decision_reason',r.get('reason'))
 if actual!=expected: raise ValueError(f'{label}:expected:{expected}:got:{actual}')
def expect_failure(label,fn):
 try: fn()
 except AuthorityError: return
 raise ValueError(f'{label}:accepted')
def validate_authority(lab,guided):
 authority=authority_from_validated_fixture(guided);grant=next((g for g in guided['grants'] if g['capability']=='code.execute_sandbox'),None)
 if grant is None: raise ValueError('sandbox_grant_missing')
 body=grant['body_ids'][0];issued=next((e for e in guided['ledger_events'] if e['grant_ref']==grant['grant_id'] and e['event_type']=='grant.issued'),None)
 if issued is None: raise ValueError('sandbox_grant_not_issued')
 opened=plus(issued['recorded_at'],1);campaign_sig=sign_fixture_envelope(guided['keys']['guardian'],'guardian',guided['guardian_id'],lab['campaign']['campaign_digest'],'genesis.improvement.campaign.signature.v0.1',opened);verify_envelope(campaign_sig,guided['keys']['guardian'],digest=lab['campaign']['campaign_digest'],domain='genesis.improvement.campaign.signature.v0.1',signer_type='guardian',signer_id=guided['guardian_id'],created_at=opened,prefix='campaign')
 request={'campaign_digest':lab['campaign']['campaign_digest'],'grant_ref':grant['grant_id'],'instance_id':guided['instance_id'],'body_id':body,'capability':'code.execute_sandbox','target_ref':'workspace.source','action_class':'compile','data_class':'private_local','requested_actions':1,'requested_duration_seconds':min(lab['campaign']['budget']['max_cpu_seconds'],grant['budget']['max_duration_seconds']),'requested_bytes':min(lab['campaign']['budget']['max_output_bytes'],grant['budget']['max_bytes_per_run']),'sandboxed':True,'human_confirmation_ref':'confirm_01HRILAB_OPEN001','observer_ref':'observer_01HRILAB_OPEN001','reversible_plan_ref':'revert_01HRILAB_OPEN001','authorized_at':opened}
 receipt=authorize_campaign_opening(request,authority)
 if receipt['decision_status']!='allowed' or receipt['grant_ref']!=grant['grant_id']: raise ValueError('campaign_authorization_failed')
 use={'schema_version':'genesis.autonomy.capability.use.v0.2','hash_profile':'genesis.hash.fields.v0.1','use_id':'use_01HRILAB_COMPILE001','grant_ref':grant['grant_id'],'instance_id':guided['instance_id'],'body_id':body,'capability':'code.execute_sandbox','target_ref':'workspace.source','action_class':'compile','data_class':'private_local','requested_actions':1,'requested_duration_seconds':30,'requested_bytes':1000000,'sandboxed':True,'human_confirmation_ref':'confirm_01HRILAB_USE001','observer_ref':'observer_01HRILAB_USE001','reversible_plan_ref':'revert_01HRILAB_USE001','requested_at':plus(opened,1),'use_digest':'','signature':None};use['use_digest']=compute_authorized_use_digest(use);use['signature']=sign_fixture_envelope(guided['keys']['body'],'body',body,use['use_digest'],'genesis.autonomy.capability.use.signature.v0.2',use['requested_at']);decision=evaluate_authorized_use(use,authority)
 if decision['status']!='allowed': raise ValueError('authorized_use_failed:'+decision['reason'])
 negatives=0;expect_reason('synthetic','grant_missing',lambda:authorize_campaign_opening({**request,'grant_ref':'grant_code_sandbox_001'},authority));negatives+=1;expect_reason('instance','grant_instance_mismatch',lambda:authorize_campaign_opening({**request,'instance_id':'inst_wrong'},authority));negatives+=1;expect_reason('early','grant_not_yet_valid',lambda:authorize_campaign_opening({**request,'authorized_at':plus(grant['not_before'],-1)},authority));negatives+=1;expect_reason('bytes','byte_budget_exceeded',lambda:authorize_campaign_opening({**request,'requested_bytes':grant['budget']['max_bytes_per_run']+1},authority));negatives+=1
 bad_sig=deepcopy(campaign_sig);bad_sig['signature_value']='0'*128;expect_failure('campaign_signature',lambda:verify_envelope(bad_sig,guided['keys']['guardian'],digest=lab['campaign']['campaign_digest'],domain='genesis.improvement.campaign.signature.v0.1',signer_type='guardian',signer_id=guided['guardian_id'],created_at=opened,prefix='campaign'));negatives+=1;bad_use=deepcopy(use);bad_use['grant_ref']='grant_other';expect_failure('signed_grant_ref',lambda:evaluate_authorized_use(bad_use,authority));negatives+=1
 for event_type,reason in [('grant.suspended','grant_suspended'),('grant.revoked','grant_revoked')]:
  event=next((e for e in guided['ledger_events'] if e['grant_ref']==grant['grant_id'] and e['event_type']==event_type),None)
  if event is None: raise ValueError(event_type+'_fixture_missing')
  expect_reason(event_type,reason,lambda event=event:authorize_campaign_opening({**request,'authorized_at':event['recorded_at']},authority));negatives+=1
 return {'receipt':receipt,'decision':decision,'negatives':negatives}
def main():
 lab=validate_lab(json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else LAB).read_text()));integration=validate_authority(lab,json.loads((Path(sys.argv[2]) if len(sys.argv)>2 else AUTH).read_text()));print(f"OK recursive improvement laboratory ({lab['projection']['candidate_count']} candidates; best={lab['best']})");print(f"OK projection digest {lab['projection']['projection_digest']}");print(f"OK signed exact-grant campaign authorization {integration['receipt']['campaign_authorization_digest']}");print(f"OK signed v0.2 use decision {integration['decision']['decision_digest']}");print(f"OK authority integration negative cases ({integration['negatives']})");print('NOTE campaign opening does not consume a use; each signed sandbox use is re-evaluated against the current ledger.')
if __name__=='__main__':
 try: main()
 except (AuthorityError,ValueError,KeyError,TypeError,AssertionError) as error: print(f'FAIL recursive improvement laboratory: {error}',file=sys.stderr);raise SystemExit(1)

#!/usr/bin/env python3
import json,hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/'conformance'/'recursive_improvement_lab_vectors.json'
FORBIDDEN={'active_writer.assign','authority.self_grant','guardian.replace','identity.modify','main.protection.disable','memory.rewrite','private_eval.read'}
def h(domain,obj):
 raw=(domain+'\n'+json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))).encode();return 'sha256:'+hashlib.sha256(raw).hexdigest()
def validate(doc):
 c=doc['campaign']; cd=c.pop('campaign_digest'); assert h('campaign',c)==cd; c['campaign_digest']=cd
 assert set(c['forbidden_capabilities'])==FORBIDDEN and c['guardian_grant_ref']
 b=c['budget']; assert all(type(b[k]) is int and b[k]>0 for k in b)
 ids=set(); by={}; accepted=[]; rejected=[]; buggy=[]
 for n in doc['candidates']:
  assert n['candidate_id'] not in ids; ids.add(n['candidate_id'])
  d=n.pop('candidate_digest'); assert h('candidate',n)==d; n['candidate_digest']=d
  p=n['parent_candidate_ref']; op=n['operator']; assert op in {'draft','debug','improve'}
  if op=='draft': assert p is None and n['source_candidate_ref'] is None
  else: assert p in by and n['source_candidate_ref']==p
  if op=='debug': assert by[p]['execution']['buggy']
  if op=='improve': assert not by[p]['execution']['buggy']
  e=n['execution']; v=n['evaluation']; status=n['expected_status']; calc='accepted'
  if e['buggy']: calc='buggy'
  elif e['cpu_seconds']>b['max_cpu_seconds'] or e['memory_mb']>b['max_memory_mb'] or e['output_bytes']>b['max_output_bytes']: calc='rejected_budget'
  elif not v['private_receipt_digest']: calc='rejected_private_receipt'
  elif v['reward_hacking_detected']: calc='rejected_reward_hacking'
  elif v['safety_regression_detected']: calc='rejected_safety'
  elif not v['maintainability_passed']: calc='rejected_maintainability'
  elif type(v['public_metric_milli']) is not int: calc='rejected_metric'
  assert calc==status
  by[n['candidate_id']]=n
  (buggy if status=='buggy' else accepted if status=='accepted' else rejected).append(n['candidate_id'])
 p=doc['expected_projection']; pd=p.pop('projection_digest')
 calc={'campaign_ref':c['campaign_id'],'candidate_count':len(by),'accepted':accepted,'rejected':rejected,'buggy':buggy,'best_candidate_ref':max(accepted,key=lambda x:by[x]['evaluation']['public_metric_milli']),'best_metric_milli':max(by[x]['evaluation']['public_metric_milli'] for x in accepted)}
 assert calc==p and h('projection',p)==pd; p['projection_digest']=pd
 assert len(doc['negative_case_ids'])==20 and len(set(doc['negative_case_ids']))==20
 return p
if __name__=='__main__':
 doc=json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else DEFAULT).read_text())
 p=validate(doc)
 print(f"OK recursive improvement laboratory ({p['candidate_count']} candidates; best={p['best_candidate_ref']})")
 print(f"OK projection digest {p['projection_digest']}")
 print('OK 20 boundary rejection categories declared')
 print('NOTE candidates never self-authorize or merge to main.')

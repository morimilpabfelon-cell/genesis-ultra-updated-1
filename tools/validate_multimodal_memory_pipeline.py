#!/usr/bin/env python3
"""Independent Python conformance for neutral multimodal extraction."""
from copy import deepcopy
import hashlib, json, re, sys, unicodedata
from pathlib import Path
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/'conformance/multimodal_memory_pipeline_vectors.json'
TS=re.compile(r'^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
SHA=re.compile(r'^sha256:[0-9a-f]{64}$')
FORBID={'write_memory','memory_event','active_writer','guardian_key','seed_root_hash','credential','token','account_id','absolute_path','provider'}
CFG={
 'document':('vision','document_text',{'application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','text/plain'},'page'),
 'image':('vision','image_description',{'image/png','image/jpeg','image/webp'},'region'),
 'audio':('hearing','audio_transcript',{'audio/wav','audio/ogg','audio/opus','audio/mpeg'},'time_range')}
F={
'source':{'source_id','instance_id','body_id','modality','sense','source_kind','captured_at','media_type','byte_length','privacy','source_digest'},
'profile':{'adapter_id','adapter_version','modality','output_kind','execution_mode','model_digest','profile_digest'},
'extraction':{'extraction_id','source_id','adapter_id','adapter_version','status','output_kind','segments','aggregate_text','aggregate_digest','extraction_digest'},
'segment':{'segment_id','ordinal','text','confidence','locator','segment_digest'},
'observation':{'schema_version','hash_profile','observation_id','instance_id','body_id','observation_sequence','sense','source_kind','captured_at','payload_digest','payload_media_type','evidence_digest','privacy','observation_digest','signature'},
'gate':{'schema_version','hash_profile','decision_id','observation_id','observation_digest','instance_id','body_id','decision','reason_code','policy_profile','decided_at','memory_event_ref','decision_digest','signature'},
'event':{'schema_version','hash_profile','event_id','instance_id','body_id','sequence','previous_event_hash','event_type','actor','content_digest','content_type','observed_at','provenance_digest','privacy','event_hash'},
'record':{'source_id','source_digest','modality','sense','media_type','extraction_id','extraction_digest','adapter_id','adapter_version','adapter_profile_digest','model_digest','accepted_text','accepted_text_digest','segment_count','observation_id','observation_digest','gate_decision_id','gate_decision_digest','memory_event_id','memory_event_hash','event_sequence','privacy','captured_at','record_digest'},
'projection':{'schema_version','profile','instance_id','record_count','records','projection_digest'}}

class E(ValueError): pass

def txt(x,empty=False):
 if not isinstance(x,str) or (not empty and not x): raise E('text_invalid')
 if unicodedata.normalize('NFC',x)!=x: raise E('text_not_nfc')
 return x

def fr(x):
 b=txt(str(x),True).encode(); return str(len(b)).encode()+b':'+b+b'\n'
def hf(domain,fields,prefix='sha256:'): return prefix+hashlib.sha256(fr(domain)+b''.join(fr(x) for x in fields)).hexdigest()
def st(x): return 'sha256:'+hashlib.sha256(txt(x,True).encode()).hexdigest()
def exact(x,name):
 if not isinstance(x,dict): raise E(name+'_invalid')
 k=set(x)
 if k&FORBID: raise E('multimodal_authority_field_forbidden')
 if k!=F[name]: raise E(name+'_fields_invalid')

def pd(p): return hf('genesis.multimodal.adapter.profile.v0.1',[p['adapter_id'],p['adapter_version'],p['modality'],p['output_kind'],p['execution_mode'],p['model_digest'] or ''])
def sd(s): return hf('genesis.multimodal.source.v0.1',[s['source_id'],s['instance_id'],s['body_id'],s['modality'],s['sense'],s['source_kind'],s['captured_at'],s['media_type'],s['byte_length'],s['privacy']])
def od(o,d): return hf(d,[o[k] for k in ['schema_version','hash_profile','observation_id','instance_id','body_id','observation_sequence','sense','source_kind','captured_at','payload_digest','payload_media_type','evidence_digest','privacy']])
def gd(g,d): return hf(d,[g[k] or '' for k in ['schema_version','hash_profile','decision_id','observation_id','observation_digest','instance_id','body_id','decision','reason_code','policy_profile','decided_at','memory_event_ref']])
def eh(e): return hf('genesis.memory.event.v0.1',[e[k] for k in ['schema_version','event_id','instance_id','body_id','sequence','previous_event_hash','event_type','actor','content_digest','content_type','observed_at','provenance_digest','privacy']],'evsha256:')

def loc(l,k):
 if k=='page':
  if set(l)!={'kind','page'} or l['kind']!='page' or type(l['page']) is not int or not 1<=l['page']<=1000000: raise E('document_locator_invalid')
  return ['page',l['page']]
 if k=='region':
  if set(l)!={'kind','x','y','width','height','unit'} or l['kind']!='region' or l['unit']!='permille': raise E('image_locator_invalid')
  x,y,w,h=(l[q] for q in ('x','y','width','height'))
  if any(type(n) is not int for n in (x,y,w,h)) or not(0<=x<=999 and 0<=y<=999 and 1<=w<=1000 and 1<=h<=1000 and x+w<=1000 and y+h<=1000): raise E('image_locator_invalid')
  return ['region',x,y,w,h,'permille']
 if set(l)!={'kind','start_ms','end_ms'} or l['kind']!='time_range': raise E('audio_locator_invalid')
 a,b=l['start_ms'],l['end_ms']
 if type(a) is not int or type(b) is not int or not 0<=a<b<=86400000: raise E('audio_locator_invalid')
 return ['time_range',a,b]
def segd(s,k): return hf('genesis.multimodal.segment.v0.1',[s['segment_id'],s['ordinal'],s['text'],s['confidence'],*loc(s['locator'],k)])

def profile(p):
 exact(p,'profile'); c=CFG.get(p['modality'])
 if not c: raise E('adapter_modality_invalid')
 if p['output_kind']!=c[1]: raise E('adapter_output_kind_mismatch')
 if p['execution_mode']!='local': raise E('adapter_execution_mode_invalid')
 if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?',p['adapter_version']): raise E('adapter_version_invalid')
 if p['model_digest'] is not None and not SHA.fullmatch(p['model_digest']): raise E('adapter_model_digest_invalid')
 if pd(p)!=p['profile_digest']: raise E('adapter_profile_digest_mismatch')
def source(s):
 exact(s,'source'); c=CFG.get(s['modality'])
 if not c: raise E('source_modality_invalid')
 if s['sense']!=c[0]: raise E('source_sense_mismatch')
 if s['source_kind'] not in {'user_input','local_sensor','network_evidence'}: raise E('source_kind_invalid')
 if s['media_type'] not in c[2]: raise E('source_media_type_mismatch')
 if type(s['byte_length']) is not int or not 1<=s['byte_length']<=104857600: raise E('source_byte_length_invalid')
 if s['privacy']=='quarantined': raise E('source_quarantined')
 if s['privacy'] not in {'private_local','guardian_shared','export_approved'}: raise E('source_privacy_invalid')
 if not TS.fullmatch(s['captured_at']): raise E('source_timestamp_invalid')
 if sd(s)!=s['source_digest']: raise E('source_digest_mismatch')
def extraction(e,s,p):
 exact(e,'extraction')
 if e['source_id']!=s['source_id']: raise E('extraction_source_mismatch')
 if (e['adapter_id'],e['adapter_version'])!=(p['adapter_id'],p['adapter_version']): raise E('extraction_adapter_mismatch')
 if p['modality']!=s['modality']: raise E('adapter_source_modality_mismatch')
 if e['status']!='extracted': raise E('extraction_not_accepted')
 if e['output_kind']!=p['output_kind']: raise E('extraction_output_kind_mismatch')
 if not isinstance(e['segments'],list) or not 1<=len(e['segments'])<=256: raise E('extraction_segments_invalid')
 ids=set(); texts=[]; ds=[]; lk=CFG[s['modality']][3]
 for i,q in enumerate(e['segments']):
  exact(q,'segment')
  if type(q['ordinal']) is not int or q['ordinal']!=i: raise E('segment_ordinal_invalid')
  if q['segment_id'] in ids: raise E('segment_id_duplicate')
  ids.add(txt(q['segment_id'])); t=txt(q['text'])
  if len(t.encode())>4096: raise E('segment_text_too_large')
  if type(q['confidence']) is not int or not 0<=q['confidence']<=1000: raise E('segment_confidence_invalid')
  d=segd(q,lk)
  if d!=q['segment_digest']: raise E('segment_digest_mismatch')
  texts.append(t); ds.append(d)
 a='\n'.join(texts)
 if a!=e['aggregate_text']: raise E('extraction_aggregate_text_mismatch')
 if len(a.encode())>65536: raise E('extraction_aggregate_too_large')
 ad=st(a)
 if ad!=e['aggregate_digest']: raise E('extraction_aggregate_digest_mismatch')
 if hf('genesis.multimodal.extraction.v0.1',[e['extraction_id'],s['source_digest'],p['profile_digest'],e['status'],e['output_kind'],len(ds),*ds,ad])!=e['extraction_digest']: raise E('extraction_digest_mismatch')

def sigbytes(e): return fr('genesis.signature.envelope.bytes.v0.1')+b''.join(fr(e[k]) for k in ['schema_version','signature_profile','signer_type','signer_id','key_epoch_id','signed_domain','signed_digest','created_at','public_key_ref'])
def sig(e,d,domain,body,v):
 if not isinstance(e,dict): raise E('signature_invalid')
 if e.get('signature_profile')!='genesis.signature.ed25519.v0.1': raise E('signature_profile_invalid')
 if (e.get('signer_type'),e.get('signer_id'))!=('body',body): raise E('signature_signer_mismatch')
 if (e.get('signed_domain'),e.get('signed_digest'))!=(domain,d): raise E('signature_binding_mismatch')
 k=v['test_signing_key']
 if e.get('public_key_ref')!=k['public_key_fingerprint']: raise E('signature_key_mismatch')
 try: VerifyKey(bytes.fromhex(k['public_key_hex'])).verify(sigbytes(e),bytes.fromhex(e['signature_value']))
 except (BadSignatureError,ValueError,KeyError): raise E('signature_invalid') from None

def chain(events):
 prev='GENESIS'
 for i,e in enumerate(events):
  if type(e.get('sequence')) is not int or e['sequence']!=i: raise E('memory_sequence_invalid')
  if e.get('previous_event_hash')!=prev: raise E('memory_chain_invalid')
  if eh(e)!=e.get('event_hash'): raise E('memory_event_hash_mismatch')
  prev=e['event_hash']
def link(s,x,o,g,e,v):
 exact(o,'observation')
 if (o['instance_id'],o['body_id'])!=(s['instance_id'],s['body_id']): raise E('observation_identity_mismatch')
 if (o['sense'],o['source_kind'])!=(s['sense'],s['source_kind']): raise E('observation_source_mismatch')
 if (o['captured_at'],o['privacy'])!=(s['captured_at'],s['privacy']): raise E('observation_metadata_mismatch')
 if o['payload_digest']!=x['aggregate_digest']: raise E('observation_payload_digest_mismatch')
 if o['payload_media_type']!='application/vnd.genesis.multimodal-accepted-text+json': raise E('observation_payload_media_type_invalid')
 if o['evidence_digest']!=x['extraction_digest']: raise E('observation_evidence_digest_mismatch')
 d=od(o,v['domains']['observation'])
 if d!=o['observation_digest']: raise E('observation_digest_mismatch')
 sig(o['signature'],d,v['domains']['observation_signature'],s['body_id'],v)
 exact(g,'gate')
 if g['decision']!='accepted': raise E('gate_not_accepted')
 if (g['observation_id'],g['observation_digest'])!=(o['observation_id'],d): raise E('gate_observation_mismatch')
 if (g['instance_id'],g['body_id'])!=(s['instance_id'],s['body_id']): raise E('gate_identity_mismatch')
 if g['memory_event_ref']!=e['event_id']: raise E('gate_memory_event_ref_mismatch')
 q=gd(g,v['domains']['gate_decision'])
 if q!=g['decision_digest']: raise E('gate_digest_mismatch')
 sig(g['signature'],q,v['domains']['gate_signature'],s['body_id'],v)
 exact(e,'event')
 if (e['instance_id'],e['body_id'])!=(s['instance_id'],s['body_id']): raise E('memory_identity_mismatch')
 if (e['event_type'],e['actor'])!=(f"sense.{s['sense']}.observation",'body'): raise E('memory_event_type_mismatch')
 if e['content_digest']!=x['aggregate_digest']: raise E('memory_content_digest_mismatch')
 if e['content_type']!=o['payload_media_type']: raise E('memory_content_type_mismatch')
 if (e['observed_at'],e['privacy'])!=(s['captured_at'],s['privacy']): raise E('memory_metadata_mismatch')
 if e['provenance_digest']!=d: raise E('memory_provenance_mismatch')

def rd(r):
 keys=['source_id','source_digest','modality','sense','media_type','extraction_id','extraction_digest','adapter_id','adapter_version','adapter_profile_digest','model_digest','accepted_text','accepted_text_digest','segment_count','observation_id','observation_digest','gate_decision_id','gate_decision_digest','memory_event_id','memory_event_hash','event_sequence','privacy','captured_at']; return hf('genesis.multimodal.memory.record.v0.1',[('' if k=='model_digest' and r[k] is None else r[k]) for k in keys],'mmsha256:')
def build(v):
 ps={x['adapter_id']:x for x in v['adapter_profiles']}; ss={x['source_id']:x for x in v['sources']}; xs={x['source_id']:x for x in v['extractions']}; os={x['observation_id']:x for x in v['observations']}; gs={x['observation_id']:x for x in v['gate_decisions']}; es={x['event_id']:x for x in v['memory_events']}
 for m,n,label in [(ps,v['adapter_profiles'],'adapter_profile'),(ss,v['sources'],'source'),(xs,v['extractions'],'extraction'),(os,v['observations'],'observation'),(gs,v['gate_decisions'],'gate'),(es,v['memory_events'],'memory_event')]:
  if len(m)!=len(n): raise E(label+'_duplicate')
 for p in v['adapter_profiles']: profile(p)
 for s in v['sources']: source(s)
 chain(v['memory_events']); rec=[]
 for s in sorted(v['sources'],key=lambda z:z['source_id'].encode()):
  x=xs.get(s['source_id'])
  if not x: raise E('extraction_missing')
  p=ps.get(x.get('adapter_id'))
  if not p: raise E('adapter_profile_missing')
  extraction(x,s,p); match=[o for o in os.values() if o['evidence_digest']==x['extraction_digest']]
  if len(match)!=1: raise E('observation_coverage_invalid')
  o=match[0]; g=gs.get(o['observation_id'])
  if not g: raise E('gate_missing')
  e=es.get(g.get('memory_event_ref'))
  if not e: raise E('memory_event_missing')
  link(s,x,o,g,e,v)
  r={'source_id':s['source_id'],'source_digest':s['source_digest'],'modality':s['modality'],'sense':s['sense'],'media_type':s['media_type'],'extraction_id':x['extraction_id'],'extraction_digest':x['extraction_digest'],'adapter_id':p['adapter_id'],'adapter_version':p['adapter_version'],'adapter_profile_digest':p['profile_digest'],'model_digest':p['model_digest'],'accepted_text':x['aggregate_text'],'accepted_text_digest':x['aggregate_digest'],'segment_count':len(x['segments']),'observation_id':o['observation_id'],'observation_digest':o['observation_digest'],'gate_decision_id':g['decision_id'],'gate_decision_digest':g['decision_digest'],'memory_event_id':e['event_id'],'memory_event_hash':e['event_hash'],'event_sequence':e['sequence'],'privacy':s['privacy'],'captured_at':s['captured_at']}; r['record_digest']=rd(r); rec.append(r)
 rec.sort(key=lambda r:r['event_sequence']); instances={ss[r['source_id']]['instance_id'] for r in rec}
 if len(instances)!=1: raise E('projection_instance_mismatch')
 p={'schema_version':'genesis.multimodal.memory.projection.v0.1','profile':v['profile'],'instance_id':next(iter(instances)),'record_count':len(rec),'records':rec}; p['projection_digest']=hf('genesis.multimodal.memory.projection.v0.1',[p['schema_version'],p['profile'],p['instance_id'],len(rec),*[r['record_digest'] for r in rec]],'mmsha256:'); return p
def projection(p):
 exact(p,'projection')
 if p['schema_version']!='genesis.multimodal.memory.projection.v0.1': raise E('projection_schema_invalid')
 if type(p['record_count']) is not int or p['record_count']!=len(p['records']): raise E('projection_record_count_mismatch')
 prev=-1; ds=[]
 for r in p['records']:
  exact(r,'record')
  if r['event_sequence']<=prev: raise E('projection_record_order_invalid')
  prev=r['event_sequence']
  if rd(r)!=r['record_digest']: raise E('projection_record_digest_mismatch')
  ds.append(r['record_digest'])
 if hf('genesis.multimodal.memory.projection.v0.1',[p['schema_version'],p['profile'],p['instance_id'],len(ds),*ds],'mmsha256:')!=p['projection_digest']: raise E('projection_digest_mismatch')
def mutate(v,m):
 c=deepcopy(v); x=c
 for q in m['path'][:-1]: x=x[q]
 if m['operation']=='set': x[m['path'][-1]]=m['value']
 elif m['operation']=='remove': x.pop(m['path'][-1]) if isinstance(x,list) else x.pop(m['path'][-1],None)
 else:
  for q in m['path'][-1:]: x=x[q]
  x.append(deepcopy(m['value']))
 return c
def run(path=DEFAULT):
 v=json.loads(Path(path).read_text()); p=build(v); projection(p)
 if p!=v['expected_projection']: raise E('expected_projection_mismatch')
 bad=[]
 for m in v['boundary_mutations']:
  try:
   c=mutate(v,m); q=build(c); projection(q)
   if q!=c['expected_projection']: raise E('expected_projection_mismatch')
   bad.append(m['id']+': unexpectedly accepted')
  except E as e:
   if str(e)!=m['expected_error']: bad.append(f"{m['id']}: expected {m['expected_error']}, got {e}")
 if bad: raise E('; '.join(bad))
 print(f"OK multimodal memory pipeline ({p['record_count']} accepted records)")
 print('OK projection digest '+p['projection_digest']); print(f"OK boundary rejection cases ({len(v['boundary_mutations'])})")
 print('NOTE extractors propose derived evidence; only signed gate acceptance can reach append-only memory.')
if __name__=='__main__':
 try: run(Path(sys.argv[1]) if len(sys.argv)>1 else DEFAULT)
 except (E,KeyError,TypeError,json.JSONDecodeError) as e: print('FAIL '+str(e)); sys.exit(1)

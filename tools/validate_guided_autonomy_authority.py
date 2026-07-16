#!/usr/bin/env python3
"""Exact-grant authority adapter over the validated guided-autonomy conformance fixture."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Any
import unicodedata
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from validate_guided_autonomy import validate_document

TS_RE=__import__('re').compile(r'^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
USE_FIELDS={"schema_version","hash_profile","use_id","grant_ref","instance_id","body_id","capability","target_ref","action_class","data_class","requested_actions","requested_duration_seconds","requested_bytes","sandboxed","human_confirmation_ref","observer_ref","reversible_plan_ref","requested_at","use_digest","signature"}
SIG_FIELDS={"schema_version","signature_profile","signer_type","signer_id","key_epoch_id","signed_domain","signed_digest","signature_value","created_at","public_key_ref"}
class AuthorityError(ValueError): pass
def fail(code): raise AuthorityError(code)
def optional(v): return '' if v is None else str(v)
def btext(v): return 'true' if v else 'false'
def enc(v):
 if not isinstance(v,str) or unicodedata.normalize('NFC',v)!=v: fail('authority_text_invalid')
 raw=v.encode(); return str(len(raw)).encode()+b':'+raw+b'\n'
def hash_authority_fields(domain,fields): return 'sha256:'+hashlib.sha256(enc(domain)+b''.join(enc(v) for v in fields)).hexdigest()
def exact(v,fields,code):
 if not isinstance(v,dict) or set(v)!=fields: fail(code)
def parse_utc(v):
 if not isinstance(v,str) or not TS_RE.fullmatch(v): fail('authority_timestamp_invalid')
 return datetime.fromisoformat(v.replace('Z','+00:00'))
def sig_bytes(e):
 exact(e,SIG_FIELDS,'signature_fields_invalid'); vals=[e[k] for k in ['schema_version','signature_profile','signer_type','signer_id','key_epoch_id','signed_domain','signed_digest','created_at','public_key_ref']]; return enc('genesis.signature.envelope.bytes.v0.1')+b''.join(enc(v) for v in vals)
def sign_fixture_envelope(key,signer_type,signer_id,digest,domain,created_at):
 e={'schema_version':'genesis.signature.envelope.v0.1','signature_profile':'genesis.signature.ed25519.v0.1','signer_type':signer_type,'signer_id':signer_id,'key_epoch_id':key['key_epoch_id'],'signed_domain':domain,'signed_digest':digest,'signature_value':'','created_at':created_at,'public_key_ref':key['public_key_fingerprint']}; e['signature_value']=SigningKey(bytes.fromhex(key['seed_hex'])).sign(sig_bytes(e)).signature.hex(); return e
def verify_envelope(e,key,*,digest,domain,signer_type,signer_id,created_at,prefix):
 exact(e,SIG_FIELDS,f'{prefix}_signature_fields_invalid')
 if e['schema_version']!='genesis.signature.envelope.v0.1' or e['signature_profile']!='genesis.signature.ed25519.v0.1': fail(f'{prefix}_signature_profile_invalid')
 if e['signer_type']!=signer_type or e['signer_id']!=signer_id or e['key_epoch_id']!=key['key_epoch_id']: fail(f'{prefix}_signer_invalid')
 if e['signed_domain']!=domain or e['signed_digest']!=digest or e['created_at']!=created_at or e['public_key_ref']!=key['public_key_fingerprint']: fail(f'{prefix}_binding_invalid')
 try: VerifyKey(bytes.fromhex(key['public_key_hex'])).verify(sig_bytes(e),bytes.fromhex(e['signature_value']))
 except (BadSignatureError,ValueError,KeyError): fail(f'{prefix}_signature_invalid')
@dataclass(frozen=True)
class Authority:
 document:dict; grants:dict; registered:frozenset

def authority_from_validated_fixture(document):
 validate_document(__import__('copy').deepcopy(document)); grants={g['grant_id']:g for g in document['grants']}
 if len(grants)!=len(document['grants']): fail('grant_id_duplicate')
 return Authority(document,grants,frozenset(document['registered_body_ids']))
def state_at(grant,events,at):
 status='not_issued'; consumed=set(); head_ref=None; head_hash='GENESIS'
 for event in events:
  if parse_utc(event['recorded_at'])>at: break
  head_ref=event['event_id']; head_hash=event['event_hash']
  if event['grant_ref']!=grant['grant_id']: continue
  if event['event_type']=='grant.issued': status='active'
  elif event['event_type']=='grant.suspended': status='suspended'
  elif event['event_type']=='grant.resumed': status='active'
  elif event['event_type']=='grant.revoked': status='revoked'
  elif event['event_type']=='grant.consumed': consumed.add(event['use_id'])
 if grant['use_limit'] is not None and len(consumed)>=grant['use_limit'] and status=='active': status='exhausted'
 return {'status':status,'consumed':consumed,'head_ref':head_ref,'head_hash':head_hash}
def resolve_exact_grant(grant_ref,capability,instance_id,at_value,authority):
 if not isinstance(authority,Authority): fail('authority_not_validated')
 grant=authority.grants.get(grant_ref)
 if grant is None: return {'grant':None,'state':None,'reason':'grant_missing'}
 if grant['instance_id']!=instance_id: return {'grant':grant,'state':None,'reason':'grant_instance_mismatch'}
 if grant['capability']!=capability: return {'grant':grant,'state':None,'reason':'grant_capability_mismatch'}
 at=parse_utc(at_value); state=state_at(grant,authority.document['ledger_events'],at); reason='allowed'
 if at<parse_utc(grant['not_before']): reason='grant_not_yet_valid'
 elif grant['expires_at'] is not None and at>=parse_utc(grant['expires_at']): reason='grant_expired'
 elif state['status']!='active': reason='grant_'+state['status']
 return {'grant':grant,'state':state,'reason':reason}
def envelope_reason(r,g,a):
 if g['body_scope']=='specific_bodies' and r['body_id'] not in g['body_ids']: return 'body_not_authorized'
 if g['body_scope']=='registered_guardian_devices' and r['body_id'] not in a.registered: return 'body_not_authorized'
 if r['target_ref'] not in g['scope']['allowed_target_refs']: return 'target_not_authorized'
 if r['action_class'] not in g['scope']['allowed_action_classes']: return 'action_not_authorized'
 if r['data_class'] not in g['scope']['allowed_data_classes']: return 'data_class_not_authorized'
 if r['requested_actions']>g['budget']['max_actions_per_run']: return 'action_budget_exceeded'
 if r['requested_duration_seconds']>g['budget']['max_duration_seconds']: return 'duration_budget_exceeded'
 if r['requested_bytes']>g['budget']['max_bytes_per_run']: return 'byte_budget_exceeded'
 if g['controls']['sandbox_required'] and not r['sandboxed']: return 'sandbox_required'
 if g['controls']['human_confirmation_required'] and r['human_confirmation_ref'] is None: return 'human_confirmation_required'
 if g['controls']['observer_required'] and r['observer_ref'] is None: return 'observer_required'
 if g['controls']['reversible_required'] and r['reversible_plan_ref'] is None: return 'reversibility_required'
 return 'allowed'
def compute_authorized_use_digest(i): return hash_authority_fields('genesis.autonomy.capability.use.v0.2',[i['schema_version'],i['hash_profile'],i['use_id'],i['grant_ref'],i['instance_id'],i['body_id'],i['capability'],i['target_ref'],i['action_class'],i['data_class'],str(i['requested_actions']),str(i['requested_duration_seconds']),str(i['requested_bytes']),btext(i['sandboxed']),optional(i['human_confirmation_ref']),optional(i['observer_ref']),optional(i['reversible_plan_ref']),i['requested_at']])
def evaluate_authorized_use(i,a):
 exact(i,USE_FIELDS,'authorized_use_fields_invalid'); digest=compute_authorized_use_digest(i)
 if i['schema_version']!='genesis.autonomy.capability.use.v0.2' or i['hash_profile']!='genesis.hash.fields.v0.1': fail('authorized_use_profile_invalid')
 if i['use_digest']!=digest: fail('authorized_use_digest_mismatch')
 verify_envelope(i['signature'],a.document['keys']['body'],digest=digest,domain='genesis.autonomy.capability.use.signature.v0.2',signer_type='body',signer_id=i['body_id'],created_at=i['requested_at'],prefix='authorized_use')
 r=resolve_exact_grant(i['grant_ref'],i['capability'],i['instance_id'],i['requested_at'],a); reason=r['reason']
 if reason=='allowed': reason='use_already_consumed' if i['use_id'] in r['state']['consumed'] else envelope_reason(i,r['grant'],a)
 remaining=None if r['grant'] is None or r['grant']['use_limit'] is None else max(0,r['grant']['use_limit']-len(r['state']['consumed'])-(1 if reason=='allowed' else 0)); status='allowed' if reason=='allowed' else 'denied'
 return {'use_id':i['use_id'],'status':status,'reason':reason,'grant_ref':i['grant_ref'],'remaining_uses':remaining,'decision_digest':hash_authority_fields('genesis.autonomy.capability.use.decision.v0.2',[i['use_id'],i['use_digest'],i['grant_ref'],status,reason,optional(remaining)])}
def authorize_campaign_opening(r,a):
 x=resolve_exact_grant(r['grant_ref'],r['capability'],r['instance_id'],r['authorized_at'],a); reason=x['reason']
 if reason=='allowed': reason=envelope_reason(r,x['grant'],a)
 status='allowed' if reason=='allowed' else 'denied'; rd=hash_authority_fields('genesis.improvement.campaign.authority.request.v0.1',[r['campaign_digest'],r['grant_ref'],r['instance_id'],r['body_id'],r['capability'],r['target_ref'],r['action_class'],r['data_class'],str(r['requested_actions']),str(r['requested_duration_seconds']),str(r['requested_bytes']),btext(r['sandboxed']),optional(r['human_confirmation_ref']),optional(r['observer_ref']),optional(r['reversible_plan_ref']),r['authorized_at']]); gd='' if x['grant'] is None else x['grant']['grant_digest']; st=x['state']; digest=hash_authority_fields('genesis.improvement.campaign.authorization.v0.1',[r['campaign_digest'],r['grant_ref'],gd,str(a.document['authority_epoch']),a.document['ledger_events'][0]['ledger_id'],optional(None if st is None else st['head_ref']),'GENESIS' if st is None else st['head_hash'],r['authorized_at'],status,reason,rd,a.document['keys']['guardian']['key_epoch_id'],r['body_id']]); return {'decision_status':status,'decision_reason':reason,'grant_ref':r['grant_ref'],'grant_digest':gd or None,'authority_request_digest':rd,'campaign_authorization_digest':digest,'ledger_head_event_ref':None if st is None else st['head_ref'],'ledger_head_hash':'GENESIS' if st is None else st['head_hash']}

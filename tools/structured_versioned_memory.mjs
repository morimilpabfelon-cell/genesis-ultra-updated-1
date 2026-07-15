#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const MAX_INT = Number.MAX_SAFE_INTEGER;
const TS_RE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const SHA_RE = /^sha256:[0-9a-f]{64}$/;
const KINDS = new Set(['fact','preference','event','profile','relationship','goal','other']);
const OPERATIONS = new Set(['sets','updates','extends','retracts']);
const POLARITIES = new Set(['positive','negative','neutral']);
const PRIVACY = new Set(['private_local','guardian_shared','export_approved']);
const FORBIDDEN_FIELDS = new Set(['guardian_id','authority_epoch','active_writer','private_key','token','credential','absolute_path','raw_bytes','base64_payload','write_memory']);
const EVENT_FIELDS = new Set(['schema_version','hash_profile','event_id','instance_id','body_id','sequence','previous_event_hash','event_type','actor','content_digest','content_type','observed_at','provenance_digest','privacy','event_hash']);
const EVENT_HASH_FIELDS = ['schema_version','event_id','instance_id','body_id','sequence','previous_event_hash','event_type','actor','content_digest','content_type','observed_at','provenance_digest','privacy'];
const ASSERTION_FIELDS = new Set(['schema_version','hash_profile','assertion_id','instance_id','source_event_ref','source_event_hash','source_content_digest','source_sequence','source_ordinal','kind','entity','slot','version_key','operation','previous_assertion_ref','value','polarity','valid_from','valid_to','extractor_profile','extractor_digest','confidence_milli','asserted_at','privacy','scope','assertion_digest']);
const ASSERTION_DIGEST_FIELDS = ['schema_version','hash_profile','assertion_id','instance_id','source_event_ref','source_event_hash','source_content_digest','source_sequence','source_ordinal','kind','entity','slot','version_key','operation','previous_assertion_ref','value','polarity','valid_from','valid_to','extractor_profile','extractor_digest','confidence_milli','asserted_at','privacy','scope'];

class ConformanceError extends Error {}
function fail(code){ throw new ConformanceError(code); }
function encodeField(value){
  if(typeof value !== 'string') fail('field_must_be_string');
  if(value.normalize('NFC') !== value) fail('text_not_nfc');
  const raw=Buffer.from(value,'utf8');
  return Buffer.concat([Buffer.from(`${raw.length}:`,'ascii'),raw,Buffer.from('\n','ascii')]);
}
function hashFields(domain, fields, prefix='sha256:'){
  const data=Buffer.concat([encodeField(domain),...fields.map(encodeField)]);
  return prefix+crypto.createHash('sha256').update(data).digest('hex');
}
function sha256Text(value){ return 'sha256:'+crypto.createHash('sha256').update(Buffer.from(value,'utf8')).digest('hex'); }
function optionalText(value){ return value===null || value===undefined ? '' : String(value); }
function validateNfc(value){
  if(typeof value === 'string'){ if(value.normalize('NFC')!==value) fail('text_not_nfc'); }
  else if(Array.isArray(value)){ for(const child of value) validateNfc(child); }
  else if(value && typeof value === 'object'){ for(const [key,child] of Object.entries(value)){ validateNfc(key); validateNfc(child); } }
}
function ensureNoForbidden(value){
  if(Array.isArray(value)){ for(const child of value) ensureNoForbidden(child); return; }
  if(value && typeof value==='object'){
    for(const key of Object.keys(value)) if(FORBIDDEN_FIELDS.has(key)) fail('forbidden_authority_or_platform_field');
    for(const child of Object.values(value)) ensureNoForbidden(child);
  }
}
function setEquals(obj,set){ const keys=Object.keys(obj); return keys.length===set.size && keys.every(k=>set.has(k)); }
function computeEventHash(event){ return hashFields('genesis.memory.event.v0.1',EVENT_HASH_FIELDS.map(f=>f==='sequence'?String(event[f]):event[f]),'evsha256:'); }
function computeAssertionDigest(a){ return hashFields('genesis.memory.structured.assertion.v0.1',ASSERTION_DIGEST_FIELDS.map(f=>['source_sequence','source_ordinal','confidence_milli'].includes(f)?String(a[f]):optionalText(a[f])),'svasha256:'); }
function computeSlotId(instanceId,entity,slot){ return hashFields('genesis.memory.structured.slot.id.v0.1',[instanceId,entity,slot],'slotsha256:'); }
function computeHistoryDigest(item){ return hashFields('genesis.memory.structured.history.v0.1',[item.assertion_id,item.assertion_digest,item.source_event_ref,item.source_event_hash,String(item.source_sequence),String(item.source_ordinal),item.operation,item.value,item.value_digest,item.polarity,optionalText(item.valid_from),optionalText(item.valid_to),item.status_after],'svhsha256:'); }
function computeSlotDigest(slot){
  const fields=[slot.slot_id,slot.version_key,slot.kind,slot.entity,slot.slot,slot.privacy,slot.scope,slot.status,String(slot.current_items.length)];
  for(const item of slot.current_items) fields.push(item.value,item.value_digest,item.assertion_ref);
  fields.push(String(slot.history.length));
  for(const item of slot.history) fields.push(item.history_digest);
  return hashFields('genesis.memory.structured.slot.v0.1',fields,'slotsha256:');
}
function computeProjectionId(instanceId,lastHash,count){ return hashFields('genesis.memory.structured.projection.id.v0.1',[instanceId,lastHash,String(count)],'svpsha256:'); }
function computeProjectionDigest(p){
  const fields=[p.schema_version,p.hash_profile,p.projection_profile,p.projection_id,p.instance_id,String(p.source_first_sequence),String(p.source_last_sequence),String(p.source_event_count),p.source_last_event_hash,String(p.assertion_count),String(p.slot_count),String(p.active_slot_count),String(p.retracted_slot_count),...p.slots.map(s=>s.slot_digest)];
  return hashFields('genesis.memory.structured.projection.v0.1',fields,'svpsha256:');
}
function utf8Compare(a,b){ return Buffer.compare(Buffer.from(a,'utf8'),Buffer.from(b,'utf8')); }
function validateEvents(events,instanceId){
  if(!Array.isArray(events)||events.length===0) fail('source_events_required');
  const byId=new Map(); let previous='GENESIS';
  events.forEach((event,index)=>{
    validateNfc(event); ensureNoForbidden(event);
    if(!setEquals(event,EVENT_FIELDS)) fail('source_event_fields_invalid');
    if(event.schema_version!=='genesis.memory.event.v0.1'||event.hash_profile!=='genesis.hash.fields.v0.1') fail('source_event_profile_invalid');
    if(event.instance_id!==instanceId) fail('source_event_instance_mismatch');
    if(!Number.isSafeInteger(event.sequence)||event.sequence!==index) fail('source_event_sequence_invalid');
    if(event.previous_event_hash!==previous) fail('source_event_chain_invalid');
    if(!PRIVACY.has(event.privacy)) fail('source_event_privacy_invalid');
    if(!TS_RE.test(event.observed_at)) fail('source_event_timestamp_invalid');
    if(!SHA_RE.test(event.content_digest)||!SHA_RE.test(event.provenance_digest)) fail('source_event_digest_invalid');
    if(computeEventHash(event)!==event.event_hash) fail('source_event_hash_mismatch');
    if(byId.has(event.event_id)) fail('source_event_id_duplicate');
    byId.set(event.event_id,event); previous=event.event_hash;
  });
  return byId;
}
function validateAssertion(a,events,instanceId){
  validateNfc(a); ensureNoForbidden(a);
  if(!setEquals(a,ASSERTION_FIELDS)) fail('assertion_fields_invalid');
  if(a.schema_version!=='genesis.memory.structured.assertion.v0.1'||a.hash_profile!=='genesis.hash.fields.v0.1') fail('assertion_profile_invalid');
  if(a.instance_id!==instanceId) fail('assertion_instance_mismatch');
  const event=events.get(a.source_event_ref); if(!event) fail('assertion_source_event_missing');
  if(a.source_event_hash!==event.event_hash) fail('assertion_source_hash_mismatch');
  if(a.source_content_digest!==event.content_digest) fail('assertion_source_content_digest_mismatch');
  if(a.source_sequence!==event.sequence) fail('assertion_source_sequence_mismatch');
  if(a.asserted_at!==event.observed_at) fail('assertion_timestamp_mismatch');
  if(a.privacy!==event.privacy) fail('assertion_privacy_mismatch');
  if(!KINDS.has(a.kind)) fail('assertion_kind_invalid');
  if(!OPERATIONS.has(a.operation)) fail('assertion_operation_invalid');
  if(!POLARITIES.has(a.polarity)) fail('assertion_polarity_invalid');
  if(!PRIVACY.has(a.privacy)) fail('assertion_privacy_invalid');
  if(!a.entity||!a.slot||!a.scope||!a.value) fail('assertion_text_required');
  if(a.version_key!==`${a.entity}:${a.slot}`) fail('assertion_version_key_mismatch');
  if(!Number.isSafeInteger(a.source_ordinal)||a.source_ordinal<0||a.source_ordinal>MAX_INT) fail('assertion_source_ordinal_invalid');
  if(!Number.isSafeInteger(a.confidence_milli)||a.confidence_milli<0||a.confidence_milli>1000) fail('assertion_confidence_invalid');
  if(!SHA_RE.test(a.extractor_digest)) fail('assertion_extractor_digest_invalid');
  if(!TS_RE.test(a.asserted_at)) fail('assertion_timestamp_invalid');
  for(const f of ['valid_from','valid_to']) if(a[f]!==null&&!TS_RE.test(a[f])) fail('assertion_validity_timestamp_invalid');
  if(a.valid_from&&a.valid_to&&a.valid_from>a.valid_to) fail('assertion_validity_interval_invalid');
  if(computeAssertionDigest(a)!==a.assertion_digest) fail('assertion_digest_mismatch');
}
function applyAssertion(state,a){
  const op=a.operation;
  if(state===undefined){
    if(op!=='sets'||a.previous_assertion_ref!==null) fail('slot_first_operation_must_set');
    state={kind:a.kind,entity:a.entity,slot:a.slot,privacy:a.privacy,scope:a.scope,status:'retracted',items:new Map(),last_assertion_ref:null,history:[]};
  }else{
    for(const f of ['kind','entity','slot','privacy','scope']) if(state[f]!==a[f]) fail(`slot_${f}_drift`);
    if(a.previous_assertion_ref!==state.last_assertion_ref) fail('slot_previous_assertion_mismatch');
    if(op==='sets'&&state.status!=='retracted') fail('slot_set_while_active');
    if(op!=='sets'&&state.status!=='active') fail('slot_operation_requires_active');
  }
  const value=a.value;
  if(op==='sets'||op==='updates') state.items=new Map([[value,a.assertion_id]]);
  else if(op==='extends'){ if(state.items.has(value)) fail('slot_extend_duplicate_value'); state.items.set(value,a.assertion_id); }
  else if(op==='retracts'){ if(!state.items.has(value)) fail('slot_retract_value_missing'); state.items.delete(value); }
  state.status=state.items.size?'active':'retracted';
  const history={assertion_id:a.assertion_id,assertion_digest:a.assertion_digest,source_event_ref:a.source_event_ref,source_event_hash:a.source_event_hash,source_sequence:a.source_sequence,source_ordinal:a.source_ordinal,operation:op,value,value_digest:sha256Text(value),polarity:a.polarity,valid_from:a.valid_from,valid_to:a.valid_to,status_after:state.status};
  history.history_digest=computeHistoryDigest(history); state.history.push(history); state.last_assertion_ref=a.assertion_id; return state;
}
function buildProjection(document,{asOfSequence=null,allowedEventRefs=null,targetVersionKey=null}={}){
  validateNfc(document); ensureNoForbidden(document);
  if(document.profile!=='genesis.memory.structured_versioned.v0.1') fail('document_profile_invalid');
  const instanceId=document.instance_id; if(typeof instanceId!=='string'||!instanceId) fail('document_instance_invalid');
  const events=validateEvents(document.source_events,instanceId);
  const assertions=document.assertions; if(!Array.isArray(assertions)||assertions.length===0) fail('assertions_required');
  const expected=[...assertions].sort((x,y)=>x.source_sequence-y.source_sequence||x.source_ordinal-y.source_ordinal||utf8Compare(x.assertion_id,y.assertion_id));
  if(assertions.some((a,i)=>a!==expected[i])) fail('assertion_order_invalid');
  const seenIds=new Set(),seenPositions=new Set(),states=new Map(),included=[];
  for(const a of assertions){
    validateAssertion(a,events,instanceId);
    if(seenIds.has(a.assertion_id)) fail('assertion_id_duplicate'); seenIds.add(a.assertion_id);
    const pos=`${a.source_sequence}:${a.source_ordinal}`; if(seenPositions.has(pos)) fail('assertion_source_position_duplicate'); seenPositions.add(pos);
    if(asOfSequence!==null&&a.source_sequence>asOfSequence) continue;
    if(targetVersionKey!==null&&a.version_key!==targetVersionKey) continue;
    if(allowedEventRefs!==null&&!allowedEventRefs.has(a.source_event_ref)) continue;
    states.set(a.version_key,applyAssertion(states.get(a.version_key),a)); included.push(a);
  }
  const slots=[];
  for(const versionKey of [...states.keys()].sort(utf8Compare)){
    const state=states.get(versionKey);
    const current_items=[...state.items.keys()].sort(utf8Compare).map(value=>({value,value_digest:sha256Text(value),assertion_ref:state.items.get(value)}));
    const slot={slot_id:computeSlotId(instanceId,state.entity,state.slot),version_key:versionKey,kind:state.kind,entity:state.entity,slot:state.slot,privacy:state.privacy,scope:state.scope,status:state.status,current_items,history:state.history};
    slot.slot_digest=computeSlotDigest(slot); slots.push(slot);
  }
  const eventList=[...events.values()];
  const cutoff=asOfSequence===null?eventList.at(-1).sequence:Math.min(asOfSequence,eventList.at(-1).sequence);
  const cutoffEvents=eventList.filter(event=>event.sequence<=cutoff);
  const last=cutoffEvents.at(-1);
  const projection={schema_version:'genesis.memory.structured_versioned.projection.v0.1',hash_profile:'genesis.hash.fields.v0.1',projection_profile:'genesis.memory.structured_versioned.algorithm.v0.1',projection_id:computeProjectionId(instanceId,eventList.at(-1).event_hash,included.length),instance_id:instanceId,source_first_sequence:0,source_last_sequence:cutoff,source_event_count:cutoffEvents.length,source_last_event_hash:last.event_hash,assertion_count:included.length,slot_count:slots.length,active_slot_count:slots.filter(slot=>slot.status==='active').length,retracted_slot_count:slots.filter(slot=>slot.status==='retracted').length,slots};
  projection.projection_digest=computeProjectionDigest(projection);
  return projection;
}
function executeQuery(document,query){
  const fields=new Set(['query_id','version_key','as_of_sequence','allowed_event_refs','acl_decision_digest']);
  if(!setEquals(query,fields)) fail('query_fields_invalid');
  if(!Number.isSafeInteger(query.as_of_sequence)||query.as_of_sequence<0) fail('query_as_of_invalid');
  if(!SHA_RE.test(query.acl_decision_digest)) fail('query_acl_digest_invalid');
  const eventIds=new Set(document.source_events.map(event=>event.event_id));
  const allowed=query.allowed_event_refs;
  if(!Array.isArray(allowed)||new Set(allowed).size!==allowed.length||allowed.some(ref=>!eventIds.has(ref))) fail('query_allowed_event_refs_invalid');
  const relevant=document.assertions.filter(assertion=>assertion.version_key===query.version_key&&assertion.source_sequence<=query.as_of_sequence);
  let access,slotStatus,values,refs,historyCount;
  if(relevant.length===0){ access='not_found'; slotStatus=null; values=[]; refs=[]; historyCount=0; }
  else if(relevant.some(assertion=>!new Set(allowed).has(assertion.source_event_ref))){ access='redacted_chain'; slotStatus=null; values=[]; refs=[]; historyCount=0; }
  else{
    const projection=buildProjection(document,{asOfSequence:query.as_of_sequence,allowedEventRefs:new Set(allowed),targetVersionKey:query.version_key});
    if(projection.slots.length===0){ access='not_found'; slotStatus=null; values=[]; refs=[]; historyCount=0; }
    else{ const slot=projection.slots[0]; access='allowed'; slotStatus=slot.status; values=slot.current_items.map(item=>item.value); refs=slot.current_items.map(item=>item.assertion_ref); historyCount=slot.history.length; }
  }
  const result={query_id:query.query_id,version_key:query.version_key,as_of_sequence:query.as_of_sequence,access_status:access,slot_status:slotStatus,current_values:values,current_assertion_refs:refs,history_count:historyCount,acl_decision_digest:query.acl_decision_digest};
  result.result_digest=hashFields('genesis.memory.structured.query.result.v0.1',[result.query_id,result.version_key,String(result.as_of_sequence),result.access_status,optionalText(result.slot_status),String(values.length),...values,String(refs.length),...refs,String(historyCount),result.acl_decision_digest],'svqsha256:');
  return result;
}
function clone(value){ return structuredClone(value); }
function setPath(target,parts,value){ let cursor=target; for(const part of parts.slice(0,-1)) cursor=cursor[part]; cursor[parts.at(-1)]=value; }
function deletePath(target,parts){ let cursor=target; for(const part of parts.slice(0,-1)) cursor=cursor[part]; if(Array.isArray(cursor)) cursor.splice(parts.at(-1),1); else delete cursor[parts.at(-1)]; }
function applyMutation(base,mutation){
  const value=clone(base);
  if(mutation.action==='set') setPath(value,mutation.path,mutation.value);
  else if(mutation.action==='delete') deletePath(value,mutation.path);
  else if(mutation.action==='append'){ let cursor=value; for(const part of mutation.path) cursor=cursor[part]; cursor.push(clone(mutation.value)); }
  else if(mutation.action==='swap'){ let cursor=value; for(const part of mutation.path) cursor=cursor[part]; const [first,second]=mutation.indices; [cursor[first],cursor[second]]=[cursor[second],cursor[first]]; }
  else throw new Error(`unknown mutation action: ${mutation.action}`);
  return value;
}
function baseDocument(vectors){ return Object.fromEntries(['profile','instance_id','source_events','assertions','queries'].map(key=>[key,vectors[key]])); }
function validateVectors(vectors){
  const base=baseDocument(vectors);
  const projection=buildProjection(base);
  if(JSON.stringify(projection)!==JSON.stringify(vectors.expected_projection)) fail('expected_projection_mismatch');
  const results=vectors.queries.map(query=>executeQuery(base,query));
  if(JSON.stringify(results)!==JSON.stringify(vectors.expected_query_results)) fail('expected_query_results_mismatch');
  const failures=[];
  for(const testCase of vectors.negative_cases){
    const candidate=applyMutation(base,testCase.mutation);
    if(testCase.recompute_assertion_digests) for(const assertion of candidate.assertions) assertion.assertion_digest=computeAssertionDigest(assertion);
    try{
      buildProjection(candidate);
      if(testCase.expected_error.startsWith('query_')) executeQuery(candidate,candidate.queries[0]);
      failures.push([testCase.case_id,testCase.expected_error,'accepted']);
    }catch(error){
      if(!(error instanceof ConformanceError)) throw error;
      if(error.message!==testCase.expected_error) failures.push([testCase.case_id,testCase.expected_error,error.message]);
    }
  }
  if(failures.length) fail('negative_case_mismatch:'+JSON.stringify(failures));
  return {projection_digest:projection.projection_digest,slot_count:projection.slot_count,assertion_count:projection.assertion_count,query_count:results.length,negative_count:vectors.negative_cases.length};
}
function atomicWrite(destination,data){ fs.mkdirSync(path.dirname(destination),{recursive:true}); const temporary=`${destination}.tmp`; fs.writeFileSync(temporary,JSON.stringify(data,null,2)+'\n',{encoding:'utf8',flag:'w'}); fs.renameSync(temporary,destination); }
function load(file){ return JSON.parse(fs.readFileSync(file,'utf8')); }
function defaultVectors(){ return path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../conformance/structured_versioned_memory_vectors.json'); }
function usage(){ console.error('Usage: structured_versioned_memory.mjs validate [vectors] | build <vectors> <output> | sync <vectors> <output> | query <vectors> <query_id> | inspect <projection>'); }
function main(){
  const [command,...args]=process.argv.slice(2);
  try{
    if(command==='validate'){
      const file=args[0]??defaultVectors();
      const summary=validateVectors(load(file));
      console.log(`OK structured versioned memory (${summary.assertion_count} assertions, ${summary.slot_count} slots, ${summary.query_count} queries)`);
      console.log(`OK projection digest ${summary.projection_digest}`);
      console.log(`OK structured memory boundary rejection cases (${summary.negative_count})`);
      return;
    }
    if(command==='build'||command==='sync'){
      if(args.length!==2){ usage(); process.exitCode=2; return; }
      const vectors=load(args[0]);
      const projection=buildProjection(baseDocument(vectors));
      if(command==='build') fs.writeFileSync(args[1],JSON.stringify(projection,null,2)+'\n',{encoding:'utf8',flag:'wx'});
      else atomicWrite(args[1],projection);
      console.log(`${command==='build'?'built':'synced'} ${projection.projection_digest}`);
      return;
    }
    if(command==='query'){
      if(args.length!==2){ usage(); process.exitCode=2; return; }
      const vectors=load(args[0]);
      const query=vectors.queries.find(item=>item.query_id===args[1]);
      if(!query) fail('query_id_not_found');
      console.log(JSON.stringify(executeQuery(baseDocument(vectors),query),null,2));
      return;
    }
    if(command==='inspect'){
      if(args.length!==1){ usage(); process.exitCode=2; return; }
      const projection=load(args[0]);
      console.log(JSON.stringify({projection_id:projection.projection_id,instance_id:projection.instance_id,assertion_count:projection.assertion_count,slot_count:projection.slot_count,active_slot_count:projection.active_slot_count,retracted_slot_count:projection.retracted_slot_count,projection_digest:projection.projection_digest},null,2));
      return;
    }
    usage();
    process.exitCode=2;
  }catch(error){
    console.error(`FAIL structured versioned memory: ${error.message}`);
    process.exitCode=1;
  }
}

export { buildProjection, executeQuery, validateVectors, computeAssertionDigest, ConformanceError };
if(import.meta.url===`file://${process.argv[1]}`) main();

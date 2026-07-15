#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_VECTORS = path.join(ROOT, "conformance", "multimodal_memory_pipeline_vectors.json");
const TS = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const SHA = /^sha256:[0-9a-f]{64}$/;

const SOURCE_FIELDS = new Set(["source_id","instance_id","body_id","modality","sense","source_kind","captured_at","media_type","byte_length","privacy","source_digest"]);
const PROFILE_FIELDS = new Set(["adapter_id","adapter_version","modality","output_kind","execution_mode","model_digest","profile_digest"]);
const EXTRACTION_FIELDS = new Set(["extraction_id","source_id","adapter_id","adapter_version","status","output_kind","segments","aggregate_text","aggregate_digest","extraction_digest"]);
const SEGMENT_FIELDS = new Set(["segment_id","ordinal","text","confidence","locator","segment_digest"]);
const OBSERVATION_FIELDS = new Set(["schema_version","hash_profile","observation_id","instance_id","body_id","observation_sequence","sense","source_kind","captured_at","payload_digest","payload_media_type","evidence_digest","privacy","observation_digest","signature"]);
const GATE_FIELDS = new Set(["schema_version","hash_profile","decision_id","observation_id","observation_digest","instance_id","body_id","decision","reason_code","policy_profile","decided_at","memory_event_ref","decision_digest","signature"]);
const MEMORY_FIELDS = new Set(["schema_version","hash_profile","event_id","instance_id","body_id","sequence","previous_event_hash","event_type","actor","content_digest","content_type","observed_at","provenance_digest","privacy","event_hash"]);
const RECORD_FIELDS = new Set(["source_id","source_digest","modality","sense","media_type","extraction_id","extraction_digest","adapter_id","adapter_version","adapter_profile_digest","model_digest","accepted_text","accepted_text_digest","segment_count","observation_id","observation_digest","gate_decision_id","gate_decision_digest","memory_event_id","memory_event_hash","event_sequence","privacy","captured_at","record_digest"]);
const PROJECTION_FIELDS = new Set(["schema_version","profile","instance_id","record_count","records","projection_digest"]);
const FORBIDDEN = new Set(["write_memory","memory_event","active_writer","guardian_key","seed_root_hash","credential","token","account_id","absolute_path","provider"]);
const CONFIG = {
  document:{sense:"vision",output_kind:"document_text",media:new Set(["application/pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","text/plain"]),locator:"page"},
  image:{sense:"vision",output_kind:"image_description",media:new Set(["image/png","image/jpeg","image/webp"]),locator:"region"},
  audio:{sense:"hearing",output_kind:"audio_transcript",media:new Set(["audio/wav","audio/ogg","audio/opus","audio/mpeg"]),locator:"time_range"},
};

export class ConformanceError extends Error {}
const cmp = (a,b)=>Buffer.compare(Buffer.from(a,"utf8"),Buffer.from(b,"utf8"));
function text(value,label,{allowEmpty=false}={}){
  if(typeof value!=="string"||(!allowEmpty&&value.length===0)) throw new ConformanceError(`${label}_invalid`);
  if(value.normalize("NFC")!==value) throw new ConformanceError("text_not_nfc");
  return value;
}
function frame(value){const raw=Buffer.from(text(String(value),"field",{allowEmpty:true}),"utf8");return Buffer.concat([Buffer.from(`${raw.length}:`,"ascii"),raw,Buffer.from("\n","ascii")]);}
function hashFields(domain,fields,prefix="sha256:"){return `${prefix}${crypto.createHash("sha256").update(Buffer.concat([frame(domain),...fields.map(frame)])).digest("hex")}`;}
function shaText(value){return `sha256:${crypto.createHash("sha256").update(Buffer.from(text(value,"text",{allowEmpty:true}),"utf8")).digest("hex")}`;}
function exact(obj,fields,label){
  if(!obj||typeof obj!=="object"||Array.isArray(obj)) throw new ConformanceError(`${label}_invalid`);
  const keys=Object.keys(obj);
  if(keys.some(k=>FORBIDDEN.has(k))) throw new ConformanceError("multimodal_authority_field_forbidden");
  if(keys.length!==fields.size||keys.some(k=>!fields.has(k))) throw new ConformanceError(`${label}_fields_invalid`);
  return obj;
}
function computeProfileDigest(p){return hashFields("genesis.multimodal.adapter.profile.v0.1",[p.adapter_id,p.adapter_version,p.modality,p.output_kind,p.execution_mode,p.model_digest??""]);}
function validateProfile(p){
  exact(p,PROFILE_FIELDS,"adapter_profile"); const c=CONFIG[p.modality];
  if(!c) throw new ConformanceError("adapter_modality_invalid");
  if(p.output_kind!==c.output_kind) throw new ConformanceError("adapter_output_kind_mismatch");
  if(p.execution_mode!=="local") throw new ConformanceError("adapter_execution_mode_invalid");
  text(p.adapter_id,"adapter_id");
  if(!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(String(p.adapter_version))) throw new ConformanceError("adapter_version_invalid");
  if(p.model_digest!==null&&(!SHA.test(p.model_digest))) throw new ConformanceError("adapter_model_digest_invalid");
  if(computeProfileDigest(p)!==p.profile_digest) throw new ConformanceError("adapter_profile_digest_mismatch");
}
function computeSourceDigest(s){return hashFields("genesis.multimodal.source.v0.1",[s.source_id,s.instance_id,s.body_id,s.modality,s.sense,s.source_kind,s.captured_at,s.media_type,s.byte_length,s.privacy]);}
function validateSource(s){
  exact(s,SOURCE_FIELDS,"source"); const c=CONFIG[s.modality];
  if(!c) throw new ConformanceError("source_modality_invalid");
  if(s.sense!==c.sense) throw new ConformanceError("source_sense_mismatch");
  if(!new Set(["user_input","local_sensor","network_evidence"]).has(s.source_kind)) throw new ConformanceError("source_kind_invalid");
  if(!c.media.has(s.media_type)) throw new ConformanceError("source_media_type_mismatch");
  if(!Number.isSafeInteger(s.byte_length)||s.byte_length<1||s.byte_length>104857600) throw new ConformanceError("source_byte_length_invalid");
  if(s.privacy==="quarantined") throw new ConformanceError("source_quarantined");
  if(!new Set(["private_local","guardian_shared","export_approved"]).has(s.privacy)) throw new ConformanceError("source_privacy_invalid");
  if(typeof s.captured_at!=="string"||!TS.test(s.captured_at)) throw new ConformanceError("source_timestamp_invalid");
  if(computeSourceDigest(s)!==s.source_digest) throw new ConformanceError("source_digest_mismatch");
}
function locatorFields(locator,kind){
  if(kind==="page"){
    if(!locator||typeof locator!=="object"||Array.isArray(locator)||Object.keys(locator).sort().join(",")!=="kind,page"||locator.kind!=="page"||!Number.isSafeInteger(locator.page)||locator.page<1||locator.page>1000000) throw new ConformanceError("document_locator_invalid");
    return ["page",locator.page];
  }
  if(kind==="region"){
    const expected=["height","kind","unit","width","x","y"].join(",");
    if(!locator||typeof locator!=="object"||Array.isArray(locator)||Object.keys(locator).sort().join(",")!==expected||locator.kind!=="region"||locator.unit!=="permille") throw new ConformanceError("image_locator_invalid");
    const vals=[locator.x,locator.y,locator.width,locator.height];
    if(vals.some(v=>!Number.isSafeInteger(v))) throw new ConformanceError("image_locator_invalid");
    const [x,y,w,h]=vals;
    if(!(x>=0&&x<=999&&y>=0&&y<=999&&w>=1&&w<=1000&&h>=1&&h<=1000&&x+w<=1000&&y+h<=1000)) throw new ConformanceError("image_locator_invalid");
    return ["region",x,y,w,h,"permille"];
  }
  if(kind==="time_range"){
    if(!locator||typeof locator!=="object"||Array.isArray(locator)||Object.keys(locator).sort().join(",")!=="end_ms,kind,start_ms"||locator.kind!=="time_range"||!Number.isSafeInteger(locator.start_ms)||!Number.isSafeInteger(locator.end_ms)||locator.start_ms<0||locator.start_ms>=locator.end_ms||locator.end_ms>86400000) throw new ConformanceError("audio_locator_invalid");
    return ["time_range",locator.start_ms,locator.end_ms];
  }
  throw new ConformanceError("segment_locator_kind_invalid");
}
function computeSegmentDigest(seg,kind){return hashFields("genesis.multimodal.segment.v0.1",[seg.segment_id,seg.ordinal,seg.text,seg.confidence,...locatorFields(seg.locator,kind)]);}
function validateExtraction(e,s,p){
  exact(e,EXTRACTION_FIELDS,"extraction");
  if(e.source_id!==s.source_id) throw new ConformanceError("extraction_source_mismatch");
  if(e.adapter_id!==p.adapter_id||e.adapter_version!==p.adapter_version) throw new ConformanceError("extraction_adapter_mismatch");
  if(p.modality!==s.modality) throw new ConformanceError("adapter_source_modality_mismatch");
  if(e.status!=="extracted") throw new ConformanceError("extraction_not_accepted");
  if(e.output_kind!==p.output_kind) throw new ConformanceError("extraction_output_kind_mismatch");
  if(!Array.isArray(e.segments)||e.segments.length<1||e.segments.length>256) throw new ConformanceError("extraction_segments_invalid");
  const ids=new Set(),texts=[],digests=[],kind=CONFIG[s.modality].locator;
  e.segments.forEach((seg,i)=>{
    exact(seg,SEGMENT_FIELDS,"segment");
    if(!Number.isSafeInteger(seg.ordinal)||seg.ordinal!==i) throw new ConformanceError("segment_ordinal_invalid");
    const sid=text(seg.segment_id,"segment_id"); if(ids.has(sid)) throw new ConformanceError("segment_id_duplicate"); ids.add(sid);
    const t=text(seg.text,"segment_text"); if(Buffer.byteLength(t,"utf8")>4096) throw new ConformanceError("segment_text_too_large");
    if(!Number.isSafeInteger(seg.confidence)||seg.confidence<0||seg.confidence>1000) throw new ConformanceError("segment_confidence_invalid");
    const d=computeSegmentDigest(seg,kind); if(d!==seg.segment_digest) throw new ConformanceError("segment_digest_mismatch");
    texts.push(t); digests.push(d);
  });
  const aggregate=texts.join("\n"); if(e.aggregate_text!==aggregate) throw new ConformanceError("extraction_aggregate_text_mismatch");
  if(Buffer.byteLength(aggregate,"utf8")>65536) throw new ConformanceError("extraction_aggregate_too_large");
  const aggregateDigest=shaText(aggregate); if(e.aggregate_digest!==aggregateDigest) throw new ConformanceError("extraction_aggregate_digest_mismatch");
  const actual=hashFields("genesis.multimodal.extraction.v0.1",[e.extraction_id,s.source_digest,p.profile_digest,e.status,e.output_kind,e.segments.length,...digests,aggregateDigest]);
  if(e.extraction_digest!==actual) throw new ConformanceError("extraction_digest_mismatch");
}
function signatureBytes(e){return Buffer.concat([frame("genesis.signature.envelope.bytes.v0.1"),...[
  e.schema_version,e.signature_profile,e.signer_type,e.signer_id,e.key_epoch_id,e.signed_domain,e.signed_digest,e.created_at,e.public_key_ref
].map(frame)]);}
function publicKeyFromRaw(hex){const prefix=Buffer.from("302a300506032b6570032100","hex");return crypto.createPublicKey({key:Buffer.concat([prefix,Buffer.from(hex,"hex")]),format:"der",type:"spki"});}
function computeObservationDigest(o,domain){exact(o,OBSERVATION_FIELDS,"observation");return hashFields(domain,[o.schema_version,o.hash_profile,o.observation_id,o.instance_id,o.body_id,o.observation_sequence,o.sense,o.source_kind,o.captured_at,o.payload_digest,o.payload_media_type,o.evidence_digest,o.privacy]);}
function computeGateDigest(g,domain){exact(g,GATE_FIELDS,"gate");return hashFields(domain,[g.schema_version,g.hash_profile,g.decision_id,g.observation_id,g.observation_digest,g.instance_id,g.body_id,g.decision,g.reason_code,g.policy_profile,g.decided_at,g.memory_event_ref??""]);}
function validateSignature(e,{digest,domain,bodyId,vectors}){
  if(!e||typeof e!=="object") throw new ConformanceError("signature_invalid");
  if(e.signature_profile!=="genesis.signature.ed25519.v0.1") throw new ConformanceError("signature_profile_invalid");
  if(e.signer_type!=="body"||e.signer_id!==bodyId) throw new ConformanceError("signature_signer_mismatch");
  if(e.signed_domain!==domain||e.signed_digest!==digest) throw new ConformanceError("signature_binding_mismatch");
  const key=vectors.test_signing_key; if(e.public_key_ref!==key.public_key_fingerprint) throw new ConformanceError("signature_key_mismatch");
  let ok=false; try{ok=crypto.verify(null,signatureBytes(e),publicKeyFromRaw(key.public_key_hex),Buffer.from(e.signature_value,"hex"));}catch{}
  if(!ok) throw new ConformanceError("signature_invalid");
}
function computeMemoryHash(e){exact(e,MEMORY_FIELDS,"memory_event");return hashFields("genesis.memory.event.v0.1",[e.schema_version,e.event_id,e.instance_id,e.body_id,e.sequence,e.previous_event_hash,e.event_type,e.actor,e.content_digest,e.content_type,e.observed_at,e.provenance_digest,e.privacy],"evsha256:");}
function validateChain(events){let previous="GENESIS";events.forEach((e,i)=>{if(!Number.isSafeInteger(e.sequence)||e.sequence!==i)throw new ConformanceError("memory_sequence_invalid");if(e.previous_event_hash!==previous)throw new ConformanceError("memory_chain_invalid");if(computeMemoryHash(e)!==e.event_hash)throw new ConformanceError("memory_event_hash_mismatch");previous=e.event_hash;});}
function validateLink(s,e,o,g,event,vectors){
  exact(o,OBSERVATION_FIELDS,"observation");
  if(o.instance_id!==s.instance_id||o.body_id!==s.body_id) throw new ConformanceError("observation_identity_mismatch");
  if(o.sense!==s.sense||o.source_kind!==s.source_kind) throw new ConformanceError("observation_source_mismatch");
  if(o.captured_at!==s.captured_at||o.privacy!==s.privacy) throw new ConformanceError("observation_metadata_mismatch");
  if(o.payload_digest!==e.aggregate_digest) throw new ConformanceError("observation_payload_digest_mismatch");
  if(o.payload_media_type!=="application/vnd.genesis.multimodal-accepted-text+json") throw new ConformanceError("observation_payload_media_type_invalid");
  if(o.evidence_digest!==e.extraction_digest) throw new ConformanceError("observation_evidence_digest_mismatch");
  const od=computeObservationDigest(o,vectors.domains.observation); if(o.observation_digest!==od) throw new ConformanceError("observation_digest_mismatch");
  validateSignature(o.signature,{digest:od,domain:vectors.domains.observation_signature,bodyId:s.body_id,vectors});
  exact(g,GATE_FIELDS,"gate"); if(g.decision!=="accepted") throw new ConformanceError("gate_not_accepted");
  if(g.observation_id!==o.observation_id||g.observation_digest!==od) throw new ConformanceError("gate_observation_mismatch");
  if(g.instance_id!==s.instance_id||g.body_id!==s.body_id) throw new ConformanceError("gate_identity_mismatch");
  if(g.memory_event_ref!==event.event_id) throw new ConformanceError("gate_memory_event_ref_mismatch");
  const gd=computeGateDigest(g,vectors.domains.gate_decision); if(g.decision_digest!==gd) throw new ConformanceError("gate_digest_mismatch");
  validateSignature(g.signature,{digest:gd,domain:vectors.domains.gate_signature,bodyId:s.body_id,vectors});
  exact(event,MEMORY_FIELDS,"memory_event");
  if(event.instance_id!==s.instance_id||event.body_id!==s.body_id) throw new ConformanceError("memory_identity_mismatch");
  if(event.event_type!==`sense.${s.sense}.observation`||event.actor!=="body") throw new ConformanceError("memory_event_type_mismatch");
  if(event.content_digest!==e.aggregate_digest) throw new ConformanceError("memory_content_digest_mismatch");
  if(event.content_type!==o.payload_media_type) throw new ConformanceError("memory_content_type_mismatch");
  if(event.observed_at!==s.captured_at||event.privacy!==s.privacy) throw new ConformanceError("memory_metadata_mismatch");
  if(event.provenance_digest!==od) throw new ConformanceError("memory_provenance_mismatch");
}
function recordFields(r){return [r.source_id,r.source_digest,r.modality,r.sense,r.media_type,r.extraction_id,r.extraction_digest,r.adapter_id,r.adapter_version,r.adapter_profile_digest,r.model_digest??"",r.accepted_text,r.accepted_text_digest,r.segment_count,r.observation_id,r.observation_digest,r.gate_decision_id,r.gate_decision_digest,r.memory_event_id,r.memory_event_hash,r.event_sequence,r.privacy,r.captured_at];}
function computeRecordDigest(r){return hashFields("genesis.multimodal.memory.record.v0.1",recordFields(r),"mmsha256:");}
export function buildProjection(vectors){
  const profiles=new Map(vectors.adapter_profiles.map(p=>[p.adapter_id,p]));
  const sources=new Map(vectors.sources.map(s=>[s.source_id,s]));
  const extractions=new Map(vectors.extractions.map(e=>[e.source_id,e]));
  const observations=new Map(vectors.observations.map(o=>[o.observation_id,o]));
  const gates=new Map(vectors.gate_decisions.map(g=>[g.observation_id,g]));
  const events=new Map(vectors.memory_events.map(e=>[e.event_id,e]));
  if(profiles.size!==vectors.adapter_profiles.length) throw new ConformanceError("adapter_profile_duplicate");
  if(sources.size!==vectors.sources.length) throw new ConformanceError("source_duplicate");
  if(extractions.size!==vectors.extractions.length) throw new ConformanceError("extraction_duplicate");
  if(observations.size!==vectors.observations.length) throw new ConformanceError("observation_duplicate");
  if(gates.size!==vectors.gate_decisions.length) throw new ConformanceError("gate_duplicate");
  if(events.size!==vectors.memory_events.length) throw new ConformanceError("memory_event_duplicate");
  vectors.adapter_profiles.forEach(validateProfile); vectors.sources.forEach(validateSource); validateChain(vectors.memory_events);
  const records=[];
  [...vectors.sources].sort((a,b)=>cmp(a.source_id,b.source_id)).forEach(s=>{
    const e=extractions.get(s.source_id); if(!e) throw new ConformanceError("extraction_missing");
    const p=profiles.get(e.adapter_id); if(!p) throw new ConformanceError("adapter_profile_missing"); validateExtraction(e,s,p);
    const matches=[...observations.values()].filter(o=>o.evidence_digest===e.extraction_digest); if(matches.length!==1) throw new ConformanceError("observation_coverage_invalid");
    const o=matches[0],g=gates.get(o.observation_id); if(!g) throw new ConformanceError("gate_missing");
    const event=events.get(g.memory_event_ref); if(!event) throw new ConformanceError("memory_event_missing"); validateLink(s,e,o,g,event,vectors);
    const r={source_id:s.source_id,source_digest:s.source_digest,modality:s.modality,sense:s.sense,media_type:s.media_type,extraction_id:e.extraction_id,extraction_digest:e.extraction_digest,adapter_id:p.adapter_id,adapter_version:p.adapter_version,adapter_profile_digest:p.profile_digest,model_digest:p.model_digest,accepted_text:e.aggregate_text,accepted_text_digest:e.aggregate_digest,segment_count:e.segments.length,observation_id:o.observation_id,observation_digest:o.observation_digest,gate_decision_id:g.decision_id,gate_decision_digest:g.decision_digest,memory_event_id:event.event_id,memory_event_hash:event.event_hash,event_sequence:event.sequence,privacy:s.privacy,captured_at:s.captured_at};
    r.record_digest=computeRecordDigest(r); records.push(r);
  });
  records.sort((a,b)=>a.event_sequence-b.event_sequence); const instances=new Set(records.map(r=>sources.get(r.source_id).instance_id)); if(instances.size!==1) throw new ConformanceError("projection_instance_mismatch");
  const projection={schema_version:"genesis.multimodal.memory.projection.v0.1",profile:vectors.profile,instance_id:[...instances][0],record_count:records.length,records};
  projection.projection_digest=hashFields("genesis.multimodal.memory.projection.v0.1",[projection.schema_version,projection.profile,projection.instance_id,records.length,...records.map(r=>r.record_digest)],"mmsha256:");
  return projection;
}
export function validateProjection(p){
  exact(p,PROJECTION_FIELDS,"projection"); if(p.schema_version!=="genesis.multimodal.memory.projection.v0.1") throw new ConformanceError("projection_schema_invalid");
  if(!Number.isSafeInteger(p.record_count)||p.record_count!==p.records.length) throw new ConformanceError("projection_record_count_mismatch");
  let prev=-1; const ds=[]; for(const r of p.records){exact(r,RECORD_FIELDS,"projection_record");if(r.event_sequence<=prev)throw new ConformanceError("projection_record_order_invalid");prev=r.event_sequence;if(computeRecordDigest(r)!==r.record_digest)throw new ConformanceError("projection_record_digest_mismatch");ds.push(r.record_digest);}
  const actual=hashFields("genesis.multimodal.memory.projection.v0.1",[p.schema_version,p.profile,p.instance_id,ds.length,...ds],"mmsha256:");if(actual!==p.projection_digest)throw new ConformanceError("projection_digest_mismatch");
}
function deepClone(v){return JSON.parse(JSON.stringify(v));}
function setPath(target,path,value){let c=target;for(const part of path.slice(0,-1))c=c[part];c[path.at(-1)]=value;}
function removePath(target,path){let c=target;for(const part of path.slice(0,-1))c=c[part];if(Array.isArray(c))c.splice(path.at(-1),1);else delete c[path.at(-1)];}
function applyMutation(v,m){const c=deepClone(v);if(m.operation==="set")setPath(c,m.path,m.value);else if(m.operation==="remove")removePath(c,m.path);else if(m.operation==="append"){let x=c;for(const p of m.path)x=x[p];x.push(deepClone(m.value));}else throw new Error(m.operation);return c;}
function equal(a,b){return JSON.stringify(a)===JSON.stringify(b);}
export function runValidation(vectorPath=DEFAULT_VECTORS){
  const vectors=JSON.parse(fs.readFileSync(vectorPath,"utf8")); const projection=buildProjection(vectors); validateProjection(projection); if(!equal(projection,vectors.expected_projection))throw new ConformanceError("expected_projection_mismatch");
  const failures=[]; for(const m of vectors.boundary_mutations){const c=applyMutation(vectors,m);try{const p=buildProjection(c);validateProjection(p);if(!equal(p,c.expected_projection))throw new ConformanceError("expected_projection_mismatch");failures.push(`${m.id}: unexpectedly accepted`);}catch(err){if(!(err instanceof ConformanceError))throw err;if(err.message!==m.expected_error)failures.push(`${m.id}: expected ${m.expected_error}, got ${err.message}`);}}
  if(failures.length)throw new ConformanceError(failures.join("; "));
  console.log(`OK multimodal memory pipeline (${projection.record_count} accepted records)`);console.log(`OK projection digest ${projection.projection_digest}`);console.log(`OK boundary rejection cases (${vectors.boundary_mutations.length})`);console.log("NOTE extractors propose derived evidence; only signed gate acceptance can reach append-only memory.");return projection;
}
function atomicWrite(target,value){const dir=path.dirname(path.resolve(target));fs.mkdirSync(dir,{recursive:true});const tmp=path.join(dir,`.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`);fs.writeFileSync(tmp,JSON.stringify(value,null,2)+"\n",{encoding:"utf8",flag:"wx"});fs.renameSync(tmp,target);}
function main(){
  const [command="validate",...args]=process.argv.slice(2);
  if(command==="validate"){runValidation(args[0]??DEFAULT_VECTORS);return;}
  if(command==="build"||command==="sync"){const [input=DEFAULT_VECTORS,output]=args;if(!output)throw new ConformanceError("output_path_required");const vectors=JSON.parse(fs.readFileSync(input,"utf8"));const projection=buildProjection(vectors);validateProjection(projection);if(command==="sync")atomicWrite(output,projection);else fs.writeFileSync(output,JSON.stringify(projection,null,2)+"\n","utf8");console.log(`${command.toUpperCase()} ${output}`);console.log(projection.projection_digest);return;}
  if(command==="inspect"){const [input]=args;if(!input)throw new ConformanceError("projection_path_required");const p=JSON.parse(fs.readFileSync(input,"utf8"));validateProjection(p);console.log(JSON.stringify({schema_version:p.schema_version,instance_id:p.instance_id,record_count:p.record_count,modalities:[...new Set(p.records.map(r=>r.modality))].sort(cmp),event_sequences:p.records.map(r=>r.event_sequence),projection_digest:p.projection_digest},null,2));return;}
  throw new ConformanceError("command_invalid");
}
if(import.meta.url===`file://${process.argv[1]}`){try{main();}catch(err){console.error(`FAIL ${err.message}`);process.exit(1);}}

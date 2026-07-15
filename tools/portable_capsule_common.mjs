import crypto from "node:crypto";

export const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export const DIGEST = /^(?:sha256|evsha256|aclsha256|capsha256|cpsha256|msha256|rcptsha256|tmsha256):[0-9a-f]{64}$/;
export const PRIVACY = new Set(["private_local","guardian_shared","export_approved","quarantined"]);
export const RECIPIENTS = new Set(["body","guardian_archive","offline_backup"]);
export const PARTS = new Set(["canonical_events","continuity_anchors","acl_receipt","retrieval_projection","temporal_projection"]);
export const REQUIRED_PARTS = new Set(["canonical_events","continuity_anchors","acl_receipt"]);
export const AUTHORITY = new Set(["active_writer","write_memory","authority_grant","guardian_key","seed_root_hash","private_key","secret","password","token"]);
export class CapsuleError extends Error {}

export const cmp = (a,b) => Buffer.compare(Buffer.from(a,"utf8"),Buffer.from(b,"utf8"));
export const sorted = (values) => [...values].sort(cmp);
export function text(value,label,empty=false){
  if(typeof value!=="string"||(!empty&&value.length===0)) throw new CapsuleError(`${label}_invalid`);
  if(value.normalize("NFC")!==value) throw new CapsuleError("capsule_text_not_nfc");
  return value;
}
export function stable(value){
  if(value===null||typeof value!=="object") return JSON.stringify(value);
  if(Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value).sort(cmp).map(k=>`${JSON.stringify(k)}:${stable(value[k])}`).join(",")}}`;
}
export const sha=(value,prefix="sha256:")=>`${prefix}${crypto.createHash("sha256").update(Buffer.from(value,"utf8")).digest("hex")}`;
function frame(value){const raw=Buffer.from(String(value),"utf8");return Buffer.concat([Buffer.from(`${raw.length}:`,"ascii"),raw,Buffer.from("\n")]);}
export function hashFields(domain,fields,prefix="sha256:"){
  return `${prefix}${crypto.createHash("sha256").update(Buffer.concat([frame(domain),...fields.map(frame)])).digest("hex")}`;
}
export function exact(value,fields,label){
  if(!value||typeof value!=="object"||Array.isArray(value)) throw new CapsuleError(`${label}_invalid`);
  const keys=Object.keys(value);
  if(keys.some(k=>AUTHORITY.has(k))) throw new CapsuleError("capsule_contains_authority");
  if(keys.length!==fields.size||keys.some(k=>!fields.has(k))) throw new CapsuleError(`${label}_fields_invalid`);
}
export function noAuthority(value){
  if(Array.isArray(value)) return value.forEach(noAuthority);
  if(value&&typeof value==="object"){
    const keys=Object.keys(value);
    if(keys.some(k=>AUTHORITY.has(k))) throw new CapsuleError("capsule_contains_authority");
    return Object.values(value).forEach(noAuthority);
  }
  if(typeof value==="string") text(value,"capsule_text",true);
}
export function unique(values,label,allowEmpty=true){
  if(!Array.isArray(values)||(!allowEmpty&&values.length===0)) throw new CapsuleError(`${label}_invalid`);
  values.forEach(v=>text(v,label));
  if(new Set(values).size!==values.length) throw new CapsuleError(`${label}_duplicate`);
}
export function eventHash(instanceId,event){
  return hashFields("genesis.memory.portable_capsule.source_event.v0.1",[instanceId,event.event_id,event.sequence,event.previous_event_hash,event.body_id,event.observed_at,event.content_type,event.content_digest,event.privacy],"evsha256:");
}
export function aclDigest(instanceId,decision){
  const refs=sorted(decision.allowed_event_refs);
  return hashFields("genesis.memory.portable_capsule.acl_decision.v0.1",[instanceId,decision.request_id,decision.purpose,decision.as_of_sequence,refs.length,...refs],"aclsha256:");
}
export function retrievalDigest(source){
  const rows=[...source.records].sort((a,b)=>cmp(a.event_id,b.event_id)),fields=[source.projection_id,rows.length];
  for(const row of rows) fields.push(row.event_id,row.frame_id,row.terms.length,...row.terms);
  return hashFields("genesis.memory.portable_capsule.retrieval_source.v0.1",fields);
}
export function temporalDigest(source){
  const rows=[...source.annotations].sort((a,b)=>cmp(a.event_id,b.event_id)),fields=[source.projection_id,rows.length];
  for(const row of rows) fields.push(row.event_id,row.annotation_digest,row.mentioned_start??"",row.mentioned_end??"");
  return hashFields("genesis.memory.portable_capsule.temporal_source.v0.1",fields);
}

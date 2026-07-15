import {
  CapsuleError,TS,RECIPIENTS,cmp,sorted,text,stable,sha,hashFields,exact,noAuthority,unique
} from "./portable_capsule_common.mjs";
import {validateDocument} from "./portable_capsule_document.mjs";

function entryDigest(entry){
  const fields=[entry.entry_kind,entry.sequence,entry.canonical_event_hash,entry.previous_event_hash];
  if(entry.entry_kind==="included_event") fields.push(entry.event_id,entry.body_id,entry.observed_at,entry.privacy,entry.content_type,entry.content_digest,entry.content);
  else fields.push(entry.redaction_reason);
  return hashFields("genesis.memory.portable_capsule.entry.v0.1",fields,"cpsha256:");
}
function component(path,role,refs,payload){
  return {path,role,media_type:"application/json",source_event_refs:sorted(refs),payload_digest:sha(stable(payload)),payload};
}
export function buildCapsule(doc,requestId){
  const state=validateDocument(doc),request=state.requestById.get(requestId);
  if(!request) throw new CapsuleError("capsule_request_not_found");
  const decision=state.decisionById.get(request.acl_request_id),requested=new Set(request.requested_event_refs);
  const source=doc.source_events.filter(event=>event.sequence<=decision.as_of_sequence),entries=[],included=[],anchors=[];
  for(const event of source){
    anchors.push({sequence:event.sequence,canonical_event_hash:event.event_hash,previous_event_hash:event.previous_event_hash,included:requested.has(event.event_id)});
    let entry;
    if(requested.has(event.event_id)){
      entry={entry_kind:"included_event",sequence:event.sequence,canonical_event_hash:event.event_hash,previous_event_hash:event.previous_event_hash,event_id:event.event_id,body_id:event.body_id,observed_at:event.observed_at,privacy:event.privacy,content_type:event.content_type,content_digest:event.content_digest,content:event.content,entry_digest:""};
      entry.entry_digest=entryDigest(entry);included.push(entry);
    }else{
      entry={entry_kind:"redacted_anchor",sequence:event.sequence,canonical_event_hash:event.event_hash,previous_event_hash:event.previous_event_hash,redaction_reason:"not_exported",entry_digest:""};
      entry.entry_digest=entryDigest(entry);
    }
    entries.push(entry);
  }
  const components=[
    component("events/accepted.json","canonical_subset",request.requested_event_refs,{events:included}),
    component("chain/continuity.json","continuity_evidence",request.requested_event_refs,{source_first_sequence:0,source_last_sequence:decision.as_of_sequence,source_chain_tip_hash:source.at(-1).event_hash,anchors}),
    component("receipts/access.json","access_receipt",request.requested_event_refs,{acl_request_id:decision.request_id,purpose:decision.purpose,as_of_sequence:decision.as_of_sequence,allowed_event_refs_digest:hashFields("genesis.memory.portable_capsule.allowed_refs.v0.1",[decision.allowed_event_refs.length,...sorted(decision.allowed_event_refs)]),decision_digest:decision.decision_digest})
  ];
  if(request.include_parts.includes("retrieval_projection")){
    const records=doc.derived_sources.retrieval.records.filter(row=>requested.has(row.event_id)).map(row=>structuredClone(row));
    components.push(component("projections/retrieval.json","rebuildable_projection",records.map(row=>row.event_id),{source_projection_id:doc.derived_sources.retrieval.projection_id,source_projection_digest:doc.derived_sources.retrieval.projection_digest,records}));
  }
  if(request.include_parts.includes("temporal_projection")){
    const annotations=doc.derived_sources.temporal.annotations.filter(row=>requested.has(row.event_id)).map(row=>structuredClone(row));
    components.push(component("projections/temporal.json","rebuildable_projection",annotations.map(row=>row.event_id),{source_projection_id:doc.derived_sources.temporal.projection_id,source_projection_digest:doc.derived_sources.temporal.projection_digest,annotations}));
  }
  components.sort((a,b)=>cmp(a.path,b.path));
  const files=components.map(item=>({path:item.path,role:item.role,media_type:item.media_type,size_bytes:Buffer.byteLength(stable(item.payload),"utf8"),digest:item.payload_digest}));
  const manifestFields=[files.length];for(const item of files) manifestFields.push(item.path,item.role,item.media_type,item.size_bytes,item.digest);
  const root=hashFields("genesis.memory.portable_capsule.manifest.v0.1",manifestFields,"msha256:");
  const manifest={format:"genesis-portable-json-capsule",format_version:1,file_count:files.length,files,root_digest:root};
  const tip=source.at(-1).event_hash;
  const capsuleId=hashFields("genesis.memory.portable_capsule.id.v0.1",[doc.instance_id,request.request_id,request.recipient_type,request.recipient_id,request.created_at,decision.as_of_sequence,tip,root],"capsha256:");
  const receipt={capsule_id:capsuleId,export_request_id:request.request_id,recipient_type:request.recipient_type,recipient_id:request.recipient_id,source_chain_tip_hash:tip,manifest_root_digest:root,acl_decision_digest:decision.decision_digest,receipt_digest:""};
  receipt.receipt_digest=hashFields("genesis.memory.portable_capsule.export_receipt.v0.1",[receipt.capsule_id,receipt.export_request_id,receipt.recipient_type,receipt.recipient_id,receipt.source_chain_tip_hash,receipt.manifest_root_digest,receipt.acl_decision_digest],"rcptsha256:");
  const capsule={schema_version:"genesis.memory.portable_capsule.v0.1",capsule_profile:"genesis.memory.portable_capsule.algorithm.v0.1",capsule_id:capsuleId,instance_id:doc.instance_id,export_request_id:request.request_id,recipient_type:request.recipient_type,recipient_id:request.recipient_id,created_at:request.created_at,source_as_of_sequence:decision.as_of_sequence,source_chain_tip_hash:tip,included_event_count:included.length,redacted_anchor_count:entries.length-included.length,entries,components,manifest,export_receipt:receipt,capsule_digest:""};
  capsule.capsule_digest=hashFields("genesis.memory.portable_capsule.digest.v0.1",[capsuleId,doc.instance_id,request.request_id,decision.as_of_sequence,tip,included.length,entries.length-included.length,root,receipt.receipt_digest],"cpsha256:");
  return verifyCapsule(capsule);
}
export function verifyCapsule(capsule){
  exact(capsule,new Set(["schema_version","capsule_profile","capsule_id","instance_id","export_request_id","recipient_type","recipient_id","created_at","source_as_of_sequence","source_chain_tip_hash","included_event_count","redacted_anchor_count","entries","components","manifest","export_receipt","capsule_digest"]),"portable_capsule");
  if(capsule.schema_version!=="genesis.memory.portable_capsule.v0.1") throw new CapsuleError("capsule_schema_version_invalid");
  if(capsule.capsule_profile!=="genesis.memory.portable_capsule.algorithm.v0.1") throw new CapsuleError("capsule_algorithm_profile_invalid");
  if(!RECIPIENTS.has(capsule.recipient_type)) throw new CapsuleError("capsule_recipient_type_invalid");
  text(capsule.recipient_id,"capsule_recipient_id");if(!TS.test(capsule.created_at)) throw new CapsuleError("capsule_created_at_invalid");
  if(!Array.isArray(capsule.entries)||capsule.entries.length===0) throw new CapsuleError("capsule_entries_invalid");
  let previous="GENESIS",includedCount=0,redactedCount=0;const includedRefs=[];
  capsule.entries.forEach((entry,index)=>{
    if(entry.entry_kind==="included_event"){
      exact(entry,new Set(["entry_kind","sequence","canonical_event_hash","previous_event_hash","event_id","body_id","observed_at","privacy","content_type","content_digest","content","entry_digest"]),"capsule_included_entry");
      if(sha(entry.content)!==entry.content_digest) throw new CapsuleError("capsule_entry_content_digest_mismatch");
      if(entry.privacy==="quarantined") throw new CapsuleError("capsule_entry_quarantined");
      includedRefs.push(entry.event_id);includedCount++;
    }else if(entry.entry_kind==="redacted_anchor"){
      exact(entry,new Set(["entry_kind","sequence","canonical_event_hash","previous_event_hash","redaction_reason","entry_digest"]),"capsule_redacted_entry");
      if(entry.redaction_reason!=="not_exported") throw new CapsuleError("capsule_redaction_reason_invalid");
      redactedCount++;
    }else throw new CapsuleError("capsule_entry_kind_invalid");
    if(entry.sequence!==index) throw new CapsuleError("capsule_entry_sequence_invalid");
    if(entry.previous_event_hash!==previous) throw new CapsuleError("capsule_entry_chain_invalid");
    if(entry.entry_digest!==entryDigest(entry)) throw new CapsuleError("capsule_entry_digest_mismatch");
    previous=entry.canonical_event_hash;
  });
  if(previous!==capsule.source_chain_tip_hash) throw new CapsuleError("capsule_tip_mismatch");
  if(includedCount!==capsule.included_event_count||redactedCount!==capsule.redacted_anchor_count) throw new CapsuleError("capsule_entry_count_mismatch");
  if(new Set(includedRefs).size!==includedRefs.length) throw new CapsuleError("capsule_included_event_duplicate");
  if(!Array.isArray(capsule.components)||capsule.components.length===0) throw new CapsuleError("capsule_components_invalid");
  const paths=[],files=[];
  for(const item of capsule.components){
    exact(item,new Set(["path","role","media_type","source_event_refs","payload_digest","payload"]),"capsule_component");
    text(item.path,"capsule_component_path");
    if(item.path.startsWith("/")||item.path.split(/[\\/]/).includes("..")) throw new CapsuleError("capsule_component_path_invalid");
    if(paths.includes(item.path)) throw new CapsuleError("capsule_component_duplicate");paths.push(item.path);
    if(item.media_type!=="application/json") throw new CapsuleError("capsule_component_media_type_invalid");
    unique(item.source_event_refs,"capsule_component_refs");
    if(item.source_event_refs.some(ref=>!includedRefs.includes(ref))) throw new CapsuleError("capsule_component_ref_not_included");
    noAuthority(item.payload);
    const payload=stable(item.payload),digest=sha(payload);
    if(item.payload_digest!==digest) throw new CapsuleError("capsule_component_digest_mismatch");
    files.push({path:item.path,role:item.role,media_type:item.media_type,size_bytes:Buffer.byteLength(payload,"utf8"),digest});
  }
  if(JSON.stringify(paths)!==JSON.stringify([...paths].sort(cmp))) throw new CapsuleError("capsule_component_order_invalid");
  exact(capsule.manifest,new Set(["format","format_version","file_count","files","root_digest"]),"capsule_manifest");
  if(capsule.manifest.format!=="genesis-portable-json-capsule"||capsule.manifest.format_version!==1) throw new CapsuleError("capsule_manifest_format_invalid");
  if(capsule.manifest.file_count!==files.length||stable(capsule.manifest.files)!==stable(files)) throw new CapsuleError("capsule_manifest_files_mismatch");
  const mf=[files.length];for(const item of files) mf.push(item.path,item.role,item.media_type,item.size_bytes,item.digest);
  const root=hashFields("genesis.memory.portable_capsule.manifest.v0.1",mf,"msha256:");
  if(capsule.manifest.root_digest!==root) throw new CapsuleError("capsule_manifest_root_mismatch");
  const receipt=capsule.export_receipt;
  exact(receipt,new Set(["capsule_id","export_request_id","recipient_type","recipient_id","source_chain_tip_hash","manifest_root_digest","acl_decision_digest","receipt_digest"]),"capsule_export_receipt");
  if(receipt.capsule_id!==capsule.capsule_id||receipt.export_request_id!==capsule.export_request_id||receipt.recipient_type!==capsule.recipient_type||receipt.recipient_id!==capsule.recipient_id||receipt.source_chain_tip_hash!==capsule.source_chain_tip_hash||receipt.manifest_root_digest!==root) throw new CapsuleError("capsule_receipt_binding_invalid");
  const receiptDigest=hashFields("genesis.memory.portable_capsule.export_receipt.v0.1",[receipt.capsule_id,receipt.export_request_id,receipt.recipient_type,receipt.recipient_id,receipt.source_chain_tip_hash,receipt.manifest_root_digest,receipt.acl_decision_digest],"rcptsha256:");
  if(receipt.receipt_digest!==receiptDigest) throw new CapsuleError("capsule_receipt_digest_mismatch");
  const id=hashFields("genesis.memory.portable_capsule.id.v0.1",[capsule.instance_id,capsule.export_request_id,capsule.recipient_type,capsule.recipient_id,capsule.created_at,capsule.source_as_of_sequence,capsule.source_chain_tip_hash,root],"capsha256:");
  if(capsule.capsule_id!==id) throw new CapsuleError("capsule_id_mismatch");
  const digest=hashFields("genesis.memory.portable_capsule.digest.v0.1",[capsule.capsule_id,capsule.instance_id,capsule.export_request_id,capsule.source_as_of_sequence,capsule.source_chain_tip_hash,capsule.included_event_count,capsule.redacted_anchor_count,root,receipt.receipt_digest],"cpsha256:");
  if(capsule.capsule_digest!==digest) throw new CapsuleError("capsule_digest_mismatch");
  noAuthority(capsule);return capsule;
}

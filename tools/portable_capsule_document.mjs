import {
  CapsuleError,TS,DIGEST,PRIVACY,RECIPIENTS,PARTS,REQUIRED_PARTS,
  text,exact,noAuthority,unique,eventHash,aclDigest,retrievalDigest,temporalDigest,sha as cryptoDigest
} from "./portable_capsule_common.mjs";

export function validateDocument(doc){
  exact(doc,new Set(["profile","hash_profile","instance_id","source_events","acl_decisions","derived_sources","export_requests","must_reject","must_reject_capsule"]),"capsule_document");
  if(doc.profile!=="genesis.memory.portable_capsule.conformance.v0.1") throw new CapsuleError("capsule_profile_invalid");
  if(doc.hash_profile!=="genesis.hash.fields.v0.1") throw new CapsuleError("capsule_hash_profile_invalid");
  text(doc.instance_id,"capsule_instance_id");
  if(!Array.isArray(doc.source_events)||doc.source_events.length===0) throw new CapsuleError("capsule_events_invalid");
  const eventIds=new Set();let previous="GENESIS";
  doc.source_events.forEach((event,index)=>{
    exact(event,new Set(["event_id","sequence","previous_event_hash","event_hash","body_id","observed_at","content_type","content","content_digest","privacy"]),"capsule_source_event");
    if(event.sequence!==index) throw new CapsuleError("capsule_event_sequence_invalid");
    text(event.event_id,"capsule_event_id");
    if(eventIds.has(event.event_id)) throw new CapsuleError("capsule_event_duplicate");
    eventIds.add(event.event_id);
    if(event.previous_event_hash!==previous) throw new CapsuleError("capsule_chain_link_invalid");
    text(event.body_id,"capsule_body_id");
    if(!TS.test(event.observed_at)) throw new CapsuleError("capsule_event_time_invalid");
    text(event.content_type,"capsule_content_type");text(event.content,"capsule_content",true);
    if(event.content_digest!==cryptoDigest(event.content)) throw new CapsuleError("capsule_content_digest_mismatch");
    if(!PRIVACY.has(event.privacy)) throw new CapsuleError("capsule_privacy_invalid");
    if(event.event_hash!==eventHash(doc.instance_id,event)) throw new CapsuleError("capsule_event_hash_mismatch");
    previous=event.event_hash;
  });
  const eventById=new Map(doc.source_events.map(e=>[e.event_id,e]));
  if(!Array.isArray(doc.acl_decisions)||doc.acl_decisions.length===0) throw new CapsuleError("capsule_acl_invalid");
  const decisionById=new Map();
  for(const decision of doc.acl_decisions){
    exact(decision,new Set(["request_id","purpose","as_of_sequence","allowed_event_refs","decision_digest"]),"capsule_acl_decision");
    text(decision.request_id,"capsule_acl_request_id");
    if(decisionById.has(decision.request_id)) throw new CapsuleError("capsule_acl_duplicate");
    if(decision.purpose!=="transfer_export") throw new CapsuleError("capsule_acl_purpose_invalid");
    if(!Number.isSafeInteger(decision.as_of_sequence)||decision.as_of_sequence<0||decision.as_of_sequence>=doc.source_events.length) throw new CapsuleError("capsule_acl_as_of_invalid");
    unique(decision.allowed_event_refs,"capsule_acl_refs");
    for(const ref of decision.allowed_event_refs){
      const event=eventById.get(ref);
      if(!event) throw new CapsuleError("capsule_acl_event_unknown");
      if(event.sequence>decision.as_of_sequence) throw new CapsuleError("capsule_acl_future_event");
      if(event.privacy==="quarantined") throw new CapsuleError("capsule_acl_quarantined");
    }
    if(decision.decision_digest!==aclDigest(doc.instance_id,decision)) throw new CapsuleError("capsule_acl_digest_mismatch");
    decisionById.set(decision.request_id,decision);
  }
  exact(doc.derived_sources,new Set(["retrieval","temporal"]),"capsule_derived_sources");
  const retrieval=doc.derived_sources.retrieval;
  exact(retrieval,new Set(["projection_id","projection_digest","records"]),"capsule_retrieval_source");
  text(retrieval.projection_id,"capsule_retrieval_projection_id");
  if(!Array.isArray(retrieval.records)) throw new CapsuleError("capsule_retrieval_records_invalid");
  const seenRetrieval=new Set();
  for(const record of retrieval.records){
    exact(record,new Set(["event_id","frame_id","terms"]),"capsule_retrieval_record");
    if(!eventById.has(record.event_id)) throw new CapsuleError("capsule_retrieval_event_unknown");
    if(seenRetrieval.has(record.event_id)) throw new CapsuleError("capsule_retrieval_duplicate");
    seenRetrieval.add(record.event_id);text(record.frame_id,"capsule_frame_id");unique(record.terms,"capsule_terms");
  }
  if(retrieval.projection_digest!==retrievalDigest(retrieval)) throw new CapsuleError("capsule_retrieval_digest_mismatch");
  const temporal=doc.derived_sources.temporal;
  exact(temporal,new Set(["projection_id","projection_digest","annotations"]),"capsule_temporal_source");
  text(temporal.projection_id,"capsule_temporal_projection_id");
  if(!Array.isArray(temporal.annotations)) throw new CapsuleError("capsule_temporal_annotations_invalid");
  const seenTemporal=new Set();
  for(const row of temporal.annotations){
    exact(row,new Set(["event_id","annotation_digest","mentioned_start","mentioned_end"]),"capsule_temporal_annotation");
    if(!eventById.has(row.event_id)) throw new CapsuleError("capsule_temporal_event_unknown");
    if(seenTemporal.has(row.event_id)) throw new CapsuleError("capsule_temporal_duplicate");
    seenTemporal.add(row.event_id);
    if(!DIGEST.test(row.annotation_digest)) throw new CapsuleError("capsule_temporal_digest_invalid");
    for(const key of ["mentioned_start","mentioned_end"]) if(row[key]!==null&&!TS.test(row[key])) throw new CapsuleError("capsule_temporal_time_invalid");
    if((row.mentioned_start===null)!==(row.mentioned_end===null)||(row.mentioned_start!==null&&row.mentioned_start>row.mentioned_end)) throw new CapsuleError("capsule_temporal_range_invalid");
  }
  if(temporal.projection_digest!==temporalDigest(temporal)) throw new CapsuleError("capsule_temporal_source_digest_mismatch");
  if(!Array.isArray(doc.export_requests)||doc.export_requests.length===0) throw new CapsuleError("capsule_requests_invalid");
  const requestById=new Map();
  for(const request of doc.export_requests){
    exact(request,new Set(["request_id","acl_request_id","recipient_type","recipient_id","created_at","requested_event_refs","include_parts","expected_capsule_digest","expected_manifest_root"]),"capsule_export_request");
    text(request.request_id,"capsule_request_id");
    if(requestById.has(request.request_id)) throw new CapsuleError("capsule_request_duplicate");
    const decision=decisionById.get(request.acl_request_id);
    if(!decision) throw new CapsuleError("capsule_request_acl_unknown");
    if(!RECIPIENTS.has(request.recipient_type)) throw new CapsuleError("capsule_recipient_type_invalid");
    text(request.recipient_id,"capsule_recipient_id");
    if(!TS.test(request.created_at)) throw new CapsuleError("capsule_created_at_invalid");
    unique(request.requested_event_refs,"capsule_requested_refs",false);
    for(const ref of request.requested_event_refs){
      const event=eventById.get(ref);
      if(!event) throw new CapsuleError("capsule_requested_event_unknown");
      if(!decision.allowed_event_refs.includes(ref)) throw new CapsuleError("capsule_requested_event_unauthorized");
      if(event.sequence>decision.as_of_sequence) throw new CapsuleError("capsule_requested_event_future");
      if(event.privacy==="quarantined") throw new CapsuleError("capsule_requested_event_quarantined");
    }
    unique(request.include_parts,"capsule_include_parts",false);
    if(request.include_parts.some(part=>!PARTS.has(part))) throw new CapsuleError("capsule_include_part_unknown");
    if([...REQUIRED_PARTS].some(part=>!request.include_parts.includes(part))) throw new CapsuleError("capsule_mandatory_part_missing");
    for(const field of ["expected_capsule_digest","expected_manifest_root"]) if(request[field]!==null&&!DIGEST.test(request[field])) throw new CapsuleError("capsule_expected_digest_invalid");
    requestById.set(request.request_id,request);
  }
  noAuthority(Object.fromEntries(Object.entries(doc).filter(([key])=>!["must_reject","must_reject_capsule"].includes(key))));
  return {eventById,decisionById,requestById};
}

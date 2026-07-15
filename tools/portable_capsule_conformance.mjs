import {CapsuleError} from "./portable_capsule_common.mjs";
import {buildCapsule,verifyCapsule} from "./portable_capsule_core.mjs";

function mutate(doc,m){
  const i=m.index??0,f=m.field,v=m.value;
  if(["event","event_add"].includes(m.target)) doc.source_events[i][f]=v;
  else if(m.target==="event_duplicate") doc.source_events.push(structuredClone(doc.source_events[i]));
  else if(m.target==="acl") doc.acl_decisions[i][f]=v;
  else if(m.target==="acl_add_ref") doc.acl_decisions[i].allowed_event_refs.push(v);
  else if(m.target==="request") doc.export_requests[i][f]=v;
  else if(m.target==="request_add_ref") doc.export_requests[i].requested_event_refs.push(v);
  else if(m.target==="request_add_part") doc.export_requests[i].include_parts.push(v);
  else if(m.target==="retrieval") doc.derived_sources.retrieval[f]=v;
  else if(m.target==="retrieval_record") doc.derived_sources.retrieval.records[i][f]=v;
  else if(m.target==="temporal") doc.derived_sources.temporal[f]=v;
  else if(m.target==="temporal_annotation") doc.derived_sources.temporal.annotations[i][f]=v;
  else throw new Error(`unknown mutation target:${m.target}`);
}
function mutateCapsule(c,m){
  const i=m.index??0;
  if(m.target==="capsule") c[m.field]=m.value;
  else if(m.target==="entry") c.entries[i][m.field]=m.value;
  else if(m.target==="component") c.components[i][m.field]=m.value;
  else if(m.target==="component_payload") c.components[i].payload[m.field]=m.value;
  else if(m.target==="manifest") c.manifest[m.field]=m.value;
  else if(m.target==="receipt") c.export_receipt[m.field]=m.value;
  else throw new Error(`unknown capsule mutation target:${m.target}`);
}
export function validateVector(doc){
  const capsules=doc.export_requests.map(request=>buildCapsule(doc,request.request_id));
  capsules.forEach((capsule,index)=>{
    const request=doc.export_requests[index];
    if(capsule.capsule_digest!==request.expected_capsule_digest) throw new Error(`capsule_expected_digest_mismatch:${request.request_id}`);
    if(capsule.manifest.root_digest!==request.expected_manifest_root) throw new Error(`capsule_expected_manifest_mismatch:${request.request_id}`);
  });
  let rejected=0;
  for(const test of doc.must_reject){
    const candidate=structuredClone(doc);mutate(candidate,test.mutation);
    try{buildCapsule(candidate,candidate.export_requests[0].request_id);}
    catch(error){
      if(!(error instanceof CapsuleError)) throw error;
      if(error.message!==test.expected_error) throw new Error(`${test.case_id}:expected:${test.expected_error}:got:${error.message}`);
      rejected++;continue;
    }
    throw new Error(`${test.case_id}:mutation_accepted`);
  }
  let tampered=0;
  for(const test of doc.must_reject_capsule){
    const candidate=structuredClone(capsules[0]);mutateCapsule(candidate,test.mutation);
    try{verifyCapsule(candidate);}
    catch(error){
      if(!(error instanceof CapsuleError)) throw error;
      if(error.message!==test.expected_error) throw new Error(`${test.case_id}:expected:${test.expected_error}:got:${error.message}`);
      tampered++;continue;
    }
    throw new Error(`${test.case_id}:tampered_capsule_accepted`);
  }
  return {capsules,rejected,tampered};
}

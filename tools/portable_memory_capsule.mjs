#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {fileURLToPath} from "node:url";
import {CapsuleError} from "./portable_capsule_common.mjs";
import {buildCapsule,verifyCapsule} from "./portable_capsule_core.mjs";
import {validateVector} from "./portable_capsule_conformance.mjs";

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const DEFAULT_VECTOR=path.join(ROOT,"conformance","portable_memory_capsule_vectors.json");

function atomicWrite(output,value){
  fs.mkdirSync(path.dirname(output),{recursive:true});
  const temp=`${output}.${process.pid}.tmp`,fd=fs.openSync(temp,"w");
  try{fs.writeFileSync(fd,`${JSON.stringify(value,null,2)}\n`);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(temp,output);
}
function main(){
  const [command="validate",inputArg=DEFAULT_VECTOR,requestId,outputArg]=process.argv.slice(2);
  const input=path.resolve(inputArg),doc=JSON.parse(fs.readFileSync(input,"utf8"));
  if(command==="validate"){
    const result=validateVector(doc);
    console.log(`OK portable memory capsules (${result.capsules.length} exports)`);
    console.log(`OK capsule digest ${result.capsules[0].capsule_digest}`);
    console.log(`OK source boundary rejection cases (${result.rejected})`);
    console.log(`OK capsule tamper rejection cases (${result.tampered})`);
    console.log("NOTE capsules carry authorized subsets and never grant identity, write, or authority.");
  }else if(["build","sync"].includes(command)){
    if(!requestId||!outputArg) throw new CapsuleError("capsule_usage_build");
    const output=path.resolve(outputArg);atomicWrite(output,buildCapsule(doc,requestId));console.log(output);
  }else if(command==="verify"){
    verifyCapsule(doc);console.log(`OK ${doc.capsule_id}`);console.log(`OK ${doc.capsule_digest}`);
  }else if(command==="inspect"){
    verifyCapsule(doc);
    console.log(JSON.stringify({
      capsule_id:doc.capsule_id,instance_id:doc.instance_id,recipient_type:doc.recipient_type,
      recipient_id:doc.recipient_id,source_as_of_sequence:doc.source_as_of_sequence,
      included_event_count:doc.included_event_count,redacted_anchor_count:doc.redacted_anchor_count,
      components:doc.components.map(({path:p,role,source_event_refs})=>({path:p,role,source_event_refs})),
      manifest_root_digest:doc.manifest.root_digest,capsule_digest:doc.capsule_digest
    },null,2));
  }else throw new CapsuleError("capsule_command_invalid");
}
if(path.resolve(process.argv[1]??"")===fileURLToPath(import.meta.url)){
  try{main();}catch(error){console.error(error.message);process.exit(1);}
}

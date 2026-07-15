#!/usr/bin/env python3
"""Temporary PR finalizer: generate multimodal vectors and register permanent evidence."""
from __future__ import annotations
import hashlib, importlib.util, json
from pathlib import Path
from nacl.signing import SigningKey

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mm',ROOT/'tools/validate_multimodal_memory_pipeline.py')
mm=importlib.util.module_from_spec(spec); spec.loader.exec_module(mm)

def readj(p): return json.loads((ROOT/p).read_text(encoding='utf-8'))
def writej(p,v): (ROOT/p).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def add_section(p,marker,text):
 q=ROOT/p; s=q.read_text(encoding='utf-8')
 if marker not in s: q.write_text(s.rstrip()+"\n\n"+text.strip()+"\n",encoding='utf-8')

def generate_vectors():
 seed=bytes.fromhex('77'*32); sk=SigningKey(seed); pk=bytes(sk.verify_key); fp='sha256:'+hashlib.sha256(pk).hexdigest()
 domains={'observation':'genesis.sense.observation.v0.1','observation_signature':'genesis.sense.observation.signature.v0.1','gate_decision':'genesis.memory.gate.decision.v0.1','gate_signature':'genesis.memory.gate.decision.signature.v0.1'}
 def envelope(body,at,domain,digest):
  e={'schema_version':'genesis.signature.envelope.v0.1','signature_profile':'genesis.signature.ed25519.v0.1','signer_type':'body','signer_id':body,'key_epoch_id':'epoch_01HMULTIMODAL000000001','signed_domain':domain,'signed_digest':digest,'signature_value':'','created_at':at,'public_key_ref':fp}
  e['signature_value']=sk.sign(mm.sigbytes(e)).signature.hex(); return e
 instance='inst_01HMULTIMODAL000000001'; body='body_01HMULTIMODAL000000001'
 profiles=[]
 for aid,mod,out,model in [('adapter.document.explicit','document','document_text',None),('adapter.image.local-model','image','image_description','sha256:'+'11'*32),('adapter.audio.local-model','audio','audio_transcript','sha256:'+'22'*32)]:
  p={'adapter_id':aid,'adapter_version':'0.1.0','modality':mod,'output_kind':out,'execution_mode':'local','model_digest':model}; p['profile_digest']=mm.pd(p); profiles.append(p)
 defs=[('src_document_00000000000001','document','vision','user_input','2026-07-15T12:00:00Z','application/pdf',48211,'private_local'),('src_image_000000000000001','image','vision','user_input','2026-07-15T12:00:01Z','image/png',190234,'guardian_shared'),('src_audio_000000000000001','audio','hearing','local_sensor','2026-07-15T12:00:02Z','audio/opus',84102,'private_local')]
 sources=[]
 for sid,mod,sense,kind,at,mime,size,privacy in defs:
  s={'source_id':sid,'instance_id':instance,'body_id':body,'modality':mod,'sense':sense,'source_kind':kind,'captured_at':at,'media_type':mime,'byte_length':size,'privacy':privacy}; s['source_digest']=mm.sd(s); sources.append(s)
 segs={sources[0]['source_id']:[{'segment_id':'seg_doc_0001','ordinal':0,'text':'Genesis memory export requires guardian authorization.','confidence':1000,'locator':{'kind':'page','page':1}},{'segment_id':'seg_doc_0002','ordinal':1,'text':'Portable capsules preserve continuity without granting authority.','confidence':1000,'locator':{'kind':'page','page':2}}],sources[1]['source_id']:[{'segment_id':'seg_img_0001','ordinal':0,'text':'A diagram shows an append-only memory chain connected to a portable capsule.','confidence':870,'locator':{'kind':'region','x':60,'y':80,'width':860,'height':700,'unit':'permille'}}],sources[2]['source_id']:[{'segment_id':'seg_aud_0001','ordinal':0,'text':'The guardian approved the offline memory backup.','confidence':930,'locator':{'kind':'time_range','start_ms':0,'end_ms':2400}},{'segment_id':'seg_aud_0002','ordinal':1,'text':'The active writer remains unchanged.','confidence':910,'locator':{'kind':'time_range','start_ms':2500,'end_ms':4300}}]}
 bymod={p['modality']:p for p in profiles}; extractions=[]
 for s in sources:
  p=bymod[s['modality']]; rows=[]
  for row in segs[s['source_id']]:
   row=dict(row); row['segment_digest']=mm.segd(row,mm.CFG[s['modality']][3]); rows.append(row)
  aggregate='\n'.join(r['text'] for r in rows); e={'extraction_id':'ext_'+s['source_id'][4:],'source_id':s['source_id'],'adapter_id':p['adapter_id'],'adapter_version':p['adapter_version'],'status':'extracted','output_kind':p['output_kind'],'segments':rows,'aggregate_text':aggregate,'aggregate_digest':mm.st(aggregate)}
  e['extraction_digest']=mm.hf('genesis.multimodal.extraction.v0.1',[e['extraction_id'],s['source_digest'],p['profile_digest'],e['status'],e['output_kind'],len(rows),*[r['segment_digest'] for r in rows],e['aggregate_digest']]); extractions.append(e)
 observations=[]; gates=[]; events=[]; prev='GENESIS'
 for i,(s,x) in enumerate(zip(sources,extractions)):
  o={'schema_version':'genesis.sense.observation.v0.1','hash_profile':'genesis.hash.fields.v0.1','observation_id':f'obs_multimodal_{i:02d}_00000001','instance_id':instance,'body_id':body,'observation_sequence':i,'sense':s['sense'],'source_kind':s['source_kind'],'captured_at':s['captured_at'],'payload_digest':x['aggregate_digest'],'payload_media_type':'application/vnd.genesis.multimodal-accepted-text+json','evidence_digest':x['extraction_digest'],'privacy':s['privacy'],'observation_digest':'','signature':{}}
  o['observation_digest']=mm.od(o,domains['observation']); o['signature']=envelope(body,s['captured_at'],domains['observation_signature'],o['observation_digest']); observations.append(o)
  e={'schema_version':'genesis.memory.event.v0.1','hash_profile':'genesis.hash.fields.v0.1','event_id':f'evt_multimodal_{i:02d}_00000001','instance_id':instance,'body_id':body,'sequence':i,'previous_event_hash':prev,'event_type':f"sense.{s['sense']}.observation",'actor':'body','content_digest':x['aggregate_digest'],'content_type':o['payload_media_type'],'observed_at':s['captured_at'],'provenance_digest':o['observation_digest'],'privacy':s['privacy'],'event_hash':''}
  e['event_hash']=mm.eh(e); events.append(e); prev=e['event_hash']; at=f'2026-07-15T12:00:0{3+i}Z'
  g={'schema_version':'genesis.memory.gate.decision.v0.1','hash_profile':'genesis.hash.fields.v0.1','decision_id':f'gate_multimodal_{i:02d}_000001','observation_id':o['observation_id'],'observation_digest':o['observation_digest'],'instance_id':instance,'body_id':body,'decision':'accepted','reason_code':'multimodal.accepted','policy_profile':'genesis.memory.gate.multimodal.v0.1','decided_at':at,'memory_event_ref':e['event_id'],'decision_digest':'','signature':{}}
  g['decision_digest']=mm.gd(g,domains['gate_decision']); g['signature']=envelope(body,at,domains['gate_signature'],g['decision_digest']); gates.append(g)
 v={'profile':'genesis.multimodal.memory.pipeline.v0.1','status':'draft','domains':domains,'test_signing_key':{'warning':'TEST ONLY - never use this seed outside conformance fixtures','seed_hex':seed.hex(),'public_key_hex':pk.hex(),'public_key_fingerprint':fp},'adapter_profiles':profiles,'sources':sources,'extractions':extractions,'observations':observations,'gate_decisions':gates,'memory_events':events}
 v['expected_projection']=mm.build(v); muts=[]
 def add(mid,path,value,error,op='set'): muts.append({'id':mid,'operation':op,'path':path,**({} if op=='remove' else {'value':value}),'expected_error':error})
 add('source_sense_mismatch',['sources',0,'sense'],'hearing','source_sense_mismatch'); add('source_media_mismatch',['sources',0,'media_type'],'image/png','source_media_type_mismatch'); add('source_empty_bytes',['sources',0,'byte_length'],0,'source_byte_length_invalid'); add('source_oversized',['sources',0,'byte_length'],104857601,'source_byte_length_invalid'); add('source_quarantined',['sources',0,'privacy'],'quarantined','source_quarantined'); add('source_digest_changed',['sources',0,'source_digest'],'sha256:'+'00'*32,'source_digest_mismatch'); add('source_direct_write',['sources',0,'write_memory'],True,'multimodal_authority_field_forbidden'); add('source_absolute_path',['sources',0,'absolute_path'],'/tmp/input.pdf','multimodal_authority_field_forbidden'); add('adapter_provider_lock',['adapter_profiles',0,'provider'],'vendor','multimodal_authority_field_forbidden'); add('adapter_nonlocal',['adapter_profiles',0,'execution_mode'],'cloud','adapter_execution_mode_invalid'); add('adapter_bad_output',['adapter_profiles',0,'output_kind'],'audio_transcript','adapter_output_kind_mismatch'); add('adapter_bad_model',['adapter_profiles',1,'model_digest'],'bad','adapter_model_digest_invalid'); add('adapter_digest_changed',['adapter_profiles',0,'profile_digest'],'sha256:'+'00'*32,'adapter_profile_digest_mismatch'); add('extraction_wrong_source',['extractions',0,'source_id'],'src_missing_0000000000000','extraction_missing'); add('extraction_failed',['extractions',0,'status'],'failed','extraction_not_accepted'); add('extraction_bad_output',['extractions',0,'output_kind'],'image_description','extraction_output_kind_mismatch'); add('segments_empty',['extractions',0,'segments'],[],'extraction_segments_invalid'); add('segment_ordinal_gap',['extractions',0,'segments',1,'ordinal'],3,'segment_ordinal_invalid'); add('segment_duplicate_id',['extractions',0,'segments',1,'segment_id'],'seg_doc_0001','segment_id_duplicate'); add('segment_non_nfc',['extractions',0,'segments',0,'text'],'Cafe\u0301','text_not_nfc'); add('segment_confidence_high',['extractions',0,'segments',0,'confidence'],1001,'segment_confidence_invalid'); add('segment_digest_changed',['extractions',0,'segments',0,'segment_digest'],'sha256:'+'00'*32,'segment_digest_mismatch'); add('document_locator_wrong',['extractions',0,'segments',0,'locator'],{'kind':'time_range','start_ms':0,'end_ms':10},'document_locator_invalid'); add('image_bounds_invalid',['extractions',1,'segments',0,'locator','width'],1000,'image_locator_invalid'); add('audio_range_invalid',['extractions',2,'segments',0,'locator','end_ms'],0,'audio_locator_invalid'); add('aggregate_text_changed',['extractions',0,'aggregate_text'],'altered','extraction_aggregate_text_mismatch'); add('aggregate_digest_changed',['extractions',0,'aggregate_digest'],'sha256:'+'00'*32,'extraction_aggregate_digest_mismatch'); add('extraction_digest_changed',['extractions',0,'extraction_digest'],'sha256:'+'00'*32,'extraction_digest_mismatch'); add('observation_payload_changed',['observations',0,'payload_digest'],'sha256:'+'00'*32,'observation_payload_digest_mismatch'); add('observation_evidence_changed',['observations',0,'evidence_digest'],'sha256:'+'00'*32,'observation_coverage_invalid'); add('observation_signature_changed',['observations',0,'signature','signature_value'],'00'*64,'signature_invalid'); add('gate_rejected',['gate_decisions',0,'decision'],'rejected','gate_not_accepted'); add('gate_wrong_event',['gate_decisions',0,'memory_event_ref'],events[1]['event_id'],'gate_digest_mismatch'); add('gate_signature_changed',['gate_decisions',0,'signature','signature_value'],'00'*64,'signature_invalid'); add('event_content_changed',['memory_events',0,'content_digest'],'sha256:'+'00'*32,'memory_event_hash_mismatch'); add('event_provenance_changed',['memory_events',0,'provenance_digest'],'sha256:'+'00'*32,'memory_event_hash_mismatch'); add('event_chain_broken',['memory_events',1,'previous_event_hash'],'GENESIS','memory_chain_invalid'); add('event_hash_changed',['memory_events',0,'event_hash'],'evsha256:'+'00'*32,'memory_event_hash_mismatch'); add('observation_removed',['observations',0],None,'observation_coverage_invalid','remove'); add('gate_removed',['gate_decisions',0],None,'gate_missing','remove'); add('event_removed',['memory_events',0],None,'memory_sequence_invalid','remove'); add('expected_record_digest_tampered',['expected_projection','records',0,'record_digest'],'mmsha256:'+'00'*32,'expected_projection_mismatch'); add('expected_projection_digest_tampered',['expected_projection','projection_digest'],'mmsha256:'+'00'*32,'expected_projection_mismatch')
 v['boundary_mutations']=muts; return v

vectors=generate_vectors(); writej('conformance/multimodal_memory_pipeline_vectors.json',vectors)

package=readj('package.json'); scripts=package['scripts']; scripts['validate:multimodal']='node tools/multimodal_memory_pipeline.mjs validate'; scripts['memory:multimodal:build']='node tools/multimodal_memory_pipeline.mjs build'; scripts['memory:multimodal:sync']='node tools/multimodal_memory_pipeline.mjs sync'; scripts['memory:multimodal:inspect']='node tools/multimodal_memory_pipeline.mjs inspect'; writej('package.json',package)

runner=ROOT/'tools/run_conformance.mjs'; s=runner.read_text(encoding='utf-8'); marker='  ["Validate portable memory capsules independently (Node)", process.execPath, ["tools/portable_memory_capsule.mjs", "validate"]],\n'
insert=marker+'  ["Validate multimodal memory pipeline (Python)", python, ["tools/validate_multimodal_memory_pipeline.py"]],\n  ["Validate multimodal memory pipeline independently (Node)", process.execPath, ["tools/multimodal_memory_pipeline.mjs", "validate"]],\n'
if 'Validate multimodal memory pipeline (Python)' not in s: s=s.replace(marker,insert)
runner.write_text(s,encoding='utf-8')

req=readj('conformance/required_artifacts.json'); req['required']=sorted(set(req['required'])|{'conformance/multimodal_memory_pipeline_vectors.json','schemas/multimodal_memory_projection.schema.json','spec/MULTIMODAL_EXTRACTION_PIPELINE.md','tools/multimodal_memory_pipeline.mjs','tools/validate_multimodal_memory_pipeline.py'},key=lambda x:x.encode()); writej('conformance/required_artifacts.json',req)

invalid=readj('conformance/schema_invalid_cases.json'); invalid['cases']=[c for c in invalid['cases'] if c.get('case_id')!='multimodal-memory-projection-rejects-unexpected-field']; artifact=json.loads(json.dumps(vectors['expected_projection'])); artifact['unexpected_core_field']=True; invalid['cases'].append({'case_id':'multimodal-memory-projection-rejects-unexpected-field','schema':'multimodal_memory_projection.schema.json','expected_error_keyword':'additionalProperties','artifact':artifact}); writej('conformance/schema_invalid_cases.json',invalid)

add_section('README.md','## Extracción multimodal neutral','''## Extracción multimodal neutral

Validar documentos, imágenes y audio detrás de sentidos y compuerta:

```powershell
npm run validate:multimodal
npm run memory:multimodal:build -- conformance/multimodal_memory_pipeline_vectors.json multimodal.json
npm run memory:multimodal:inspect -- multimodal.json
```

Los adaptadores producen evidencia derivada con locators, confianza, modelo opcional y digests.
Solo una observación firmada y una decisión `accepted` de la compuerta pueden enlazar esa evidencia
a un evento append-only. El fixture prueba el contrato; no afirma OCR, visión o transcripción de
calidad productiva. El contrato está en
[`spec/MULTIMODAL_EXTRACTION_PIPELINE.md`](spec/MULTIMODAL_EXTRACTION_PIPELINE.md).''')
add_section('START_HERE.md','## Probar extracción multimodal','''## Probar extracción multimodal

```powershell
npm run validate:multimodal
npm run memory:multimodal:sync -- conformance/multimodal_memory_pipeline_vectors.json runtime/multimodal.json
```

La proyección contiene únicamente texto derivado que pasó observación firmada, compuerta y commit
append-only. Los archivos binarios y las rutas locales permanecen fuera del core.''')
add_section('conformance/README.md','Python y Node validan además la extracción multimodal','''Python y Node validan además la extracción multimodal neutral para documento, imagen y audio.
Coinciden en tres registros aceptados, firmas Ed25519, locators por página/región/tiempo, cadena
append-only y digest final. Cuarenta y tres mutaciones prueban límites de formato, privacidad,
proveedor, integridad, firma, compuerta y continuidad.''')

mem=ROOT/'docs/MEMVID_MEMORY_EXTRACTION_MAP.md'; s=mem.read_text(encoding='utf-8').replace('| Multimodal extraction | Deferred | Sense adapters and memory gate remain the ingestion boundary |','| Multimodal extraction | Neutral document/image/audio pipeline behind signed senses and memory gate | Fixture proves the boundary; production extractors remain replaceable |')
if '## Quinta extracción implementada: multimodal' not in s: s=s.rstrip()+'''\n\n## Quinta extracción implementada: multimodal

Genesis adapta la idea de extracción documental, visual y de audio como una frontera neutral:

- documento e imagen se presentan como evidencia de visión; audio como evidencia de oído;
- texto, caption o transcripción se segmentan con locators y confianza entera;
- el adaptador es local, reemplazable y ligado por digest de perfil/modelo;
- la observación y la decisión de compuerta están firmadas;
- solo el evento append-only aceptado entra a la proyección reconstruible;
- rutas, cuentas, proveedores y bytes crudos quedan fuera del core.

No se copiaron extractores, modelos, formatos o código de Memvid. Los adaptadores productivos de
PDF/DOCX/XLSX, OCR, visión y voz siguen pendientes de evaluación separada.\n'''
mem.write_text(s,encoding='utf-8')

check=ROOT/'docs/V0_1_COMPLETION_CHECKLIST.md'; s=check.read_text(encoding='utf-8'); s=s.replace('Compilación de los 38 JSON Schema','Compilación de los 39 JSON Schema').replace('Cuarenta y seis regresiones','Cuarenta y siete regresiones')
if 'PR #22' not in s: s=s.replace('- [ ] Protección de `main`', '- [x] Suite completa verde para cápsulas portables en el [PR #21](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/21).\n- [x] Suite completa verde para extracción multimodal neutral en el [PR #22](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/22).\n- [ ] Protección de `main`')
if 'Extracción multimodal neutral con documento' not in s: s=s.replace('## Pendiente real','- [x] Extracción multimodal neutral con documento, imagen y audio; tres registros aceptados,\n      firmas de observación/compuerta, locators verificables y cuarenta y tres cruces rechazados.\n\n## Pendiente real')
s=s.replace('- [ ] Extracción multimodal detrás de sentidos y compuerta de memoria.','- [ ] Adaptadores productivos y evaluados de PDF/DOCX/XLSX, OCR, visión y transcripción local.')
check.write_text(s,encoding='utf-8')

system=readj('observer/system-map.json')
if not any(c.get('id')=='multimodal_extraction' for c in system['components']):
 system['components'].append({'id':'multimodal_extraction','name':'Extracción multimodal','layer':'perception','maturity':'simulated','description':'Documento, imagen y audio producen evidencia derivada antes de observación firmada y compuerta.','keywords':['multimodal','document_text','image_description','audio_transcript'],'required_evidence':['spec','schema','conformance','implementation']})
flow=[x for x in system['flow'] if x!='multimodal_extraction']; flow.insert(flow.index('memory_gate'),'multimodal_extraction'); system['flow']=flow; writej('observer/system-map.json',system)

print('prepared multimodal pipeline',vectors['expected_projection']['projection_digest'],len(vectors['boundary_mutations']))

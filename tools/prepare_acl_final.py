#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

cases_path = ROOT / "conformance" / "schema_invalid_cases.json"
data = json.loads(cases_path.read_text(encoding="utf-8"))
case_id = "memory-retrieval-acl-decision-rejects-unexpected-field"
if not any(item.get("case_id") == case_id for item in data["cases"]):
    data["cases"].append({
        "case_id": case_id,
        "schema": "memory_retrieval_acl_decision.schema.json",
        "expected_error_keyword": "additionalProperties",
        "artifact": {
            "schema_version": "genesis.memory.retrieval_acl.decision.v0.1",
            "request_id": "req_schema_acl",
            "policy_id": "acl_schema",
            "instance_id": "inst_01HACL000000000000001",
            "authority_epoch": 3,
            "purpose": "recall",
            "as_of_sequence": 0,
            "effective_scopes": ["core"],
            "allowed_event_refs": ["evt_01HACL000000000000001"],
            "denial_counts": {},
            "decision_digest": "aclsha256:" + "a" * 64,
            "write_memory": True
        }
    })
cases_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

readme = ROOT / "README.md"
text = readme.read_text(encoding="utf-8")
marker = "## Filtrar recuperación por scopes y ACL"
if marker not in text:
    block = '''\n## Filtrar recuperación por scopes y ACL\n\nValidar las políticas y decisiones:\n\n```powershell\nnpm run validate:retrieval-acl\n```\n\nInspeccionar una decisión de ejemplo:\n\n```powershell\nnpm run memory:acl:filter -- conformance/memory_retrieval_acl_vectors.json req_engine_mobility\n```\n\nLa ACL se aplica antes del ranking léxico o semántico. `quarantined` siempre se rechaza,\n`as_of_sequence` impide filtración futura y ningún permiso de lectura concede autoridad de escritura.\nEl contrato está en [`spec/MEMORY_RETRIEVAL_SCOPES_AND_ACL.md`](spec/MEMORY_RETRIEVAL_SCOPES_AND_ACL.md).\n'''
    text = text.replace("\n## Observabilidad local en vivo", block + "\n## Observabilidad local en vivo")
    readme.write_text(text, encoding="utf-8")

conf = ROOT / "conformance" / "README.md"
text = conf.read_text(encoding="utf-8")
if "memory_retrieval_acl_vectors.json" not in text:
    text = text.replace("## Archivos\n", "## Archivos\n\n- `memory_retrieval_acl_vectors.json`: seis eventos, cinco políticas, seis solicitudes y ocho mutaciones para scopes, privacidad, propósito, cuerpo e aislamiento histórico.\n")
    conf.write_text(text, encoding="utf-8")

checklist = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
text = checklist.read_text(encoding="utf-8")
if "Scopes y ACL de recuperación" not in text:
    text = text.replace("\n## Pendiente real", "\n- [x] Scopes y ACL de recuperación reproducidos por Python y Node: privacidad, propósito, cuerpo, época de autoridad, cuarentena e aislamiento histórico.\n\n## Pendiente real")
    checklist.write_text(text, encoding="utf-8")

system_map = ROOT / "observer" / "system-map.json"
obj = json.loads(system_map.read_text(encoding="utf-8"))
for component in obj["components"]:
    if component["id"] == "memory_retrieval":
        component["description"] = "Índice reconstruible con búsqueda léxica e híbrida, replay temporal, scopes y ACL previos al ranking."
        for keyword in ["memory_retrieval_acl", "retrieval_scopes"]:
            if keyword not in component["keywords"]:
                component["keywords"].append(keyword)
system_map.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

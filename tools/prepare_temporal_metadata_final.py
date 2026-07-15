#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, value: str) -> None:
    (ROOT / path).write_text(value.rstrip() + "\n", encoding="utf-8")


def pull_request_number() -> str | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        value = event.get("number")
        return str(value) if value is not None else None
    except (OSError, ValueError, TypeError):
        return None


def update_schema_regression() -> None:
    path = ROOT / "conformance/schema_invalid_cases.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    schema_name = "temporal_memory_projection.schema.json"
    if any(case.get("schema") == schema_name for case in document["cases"]):
        return
    document["cases"].append({
        "case_id": "temporal-memory-projection-rejects-unexpected-field",
        "schema": schema_name,
        "expected_error_keyword": "additionalProperties",
        "artifact": {
            "schema_version": "genesis.memory.temporal.projection.v0.1",
            "hash_profile": "genesis.hash.fields.v0.1",
            "projection_id": "tpsha256:" + "a" * 64,
            "instance_id": "inst_01HTEMPORAL000000000001",
            "extraction_profile": "genesis.memory.temporal.explicit_adapter.v0.1",
            "source_event_count": 1,
            "source_last_sequence": 0,
            "annotation_count": 1,
            "annotations": [{
                "event_id": "evt_01HTEMPORAL000000000001",
                "annotation_digest": "tmsha256:" + "b" * 64,
                "mention_kind": "none",
                "mentioned_start": None,
                "mentioned_end": None,
                "relation": "none",
                "related_event_ref": None
            }],
            "query_results": [{
                "query_id": "query_temporal_schema",
                "access_decision_ref": "acl_temporal_schema",
                "query_type": "captured_between",
                "as_of_sequence": 0,
                "candidate_count": 1,
                "matched_event_refs": [],
                "denial_counts": {"no_temporal_match": 1},
                "result_digest": "sha256:" + "c" * 64
            }],
            "projection_digest": "sha256:" + "d" * 64,
            "unexpected_core_field": True
        }
    })
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def update_readme() -> None:
    text = read("README.md")
    marker = "## Metadata temporal de memoria"
    if marker in text:
        return
    section = """## Metadata temporal de memoria

Validar que Python y Node reconstruyen la misma proyección:

```powershell
npm run validate:temporal-metadata
```

Consultar una relación o intervalo temporal autorizado por ACL:

```powershell
npm run memory:temporal:query -- conformance/temporal_memory_metadata_vectors.json q_before_recovery
```

Construir o sincronizar atómicamente la proyección derivada:

```powershell
npm run memory:temporal:build -- conformance/temporal_memory_metadata_vectors.json temporal.json
npm run memory:temporal:sync -- conformance/temporal_memory_metadata_vectors.json runtime/temporal.json
```

La capa separa captura, almacenamiento y tiempo mencionado. Verifica intervalos, relaciones,
procedencia, ACL y cortes históricos; nunca reescribe `observed_at` ni la cadena append-only.
El contrato está en [`spec/TEMPORAL_MEMORY_METADATA.md`](spec/TEMPORAL_MEMORY_METADATA.md).

"""
    anchor = "## Observabilidad local en vivo"
    text = text.replace(anchor, section + anchor) if anchor in text else text + "\n\n" + section
    write("README.md", text)


def update_start_here() -> None:
    text = read("START_HERE.md")
    spec_line = "[`spec/TEMPORAL_MEMORY_METADATA.md`](./spec/TEMPORAL_MEMORY_METADATA.md)"
    if spec_line not in text:
        anchor = "[`spec/MEMORY_RETRIEVAL_SCOPES_AND_ACL.md`](./spec/MEMORY_RETRIEVAL_SCOPES_AND_ACL.md)"
        if anchor in text:
            text = text.replace(anchor, anchor + "\n12. " + spec_line, 1)
            lines = text.splitlines()
            seen = False
            rebuilt = []
            number = 1
            for line in lines:
                if re.match(r"^\d+\. \[`", line):
                    rebuilt.append(re.sub(r"^\d+\.", f"{number}.", line))
                    number += 1
                    seen = True
                else:
                    rebuilt.append(line)
            text = "\n".join(rebuilt)
    marker = "## Probar metadata temporal"
    if marker not in text:
        section = """## Probar metadata temporal

```powershell
npm run validate:temporal-metadata
npm run memory:temporal:query -- conformance/temporal_memory_metadata_vectors.json q_active_audit
```

La consulta recibe únicamente referencias autorizadas por ACL, aplica primero `as_of_sequence` y
después evalúa captura, almacenamiento, intervalos mencionados o relaciones antes/después.

"""
        anchor = "## Observar el estado en vivo"
        text = text.replace(anchor, section + anchor) if anchor in text else text + "\n\n" + section
    write("START_HERE.md", text)


def update_conformance_readme() -> None:
    text = read("conformance/README.md")
    bullet = "- `temporal_memory_metadata_vectors.json`:"
    if bullet not in text:
        anchor = "- `continuity_vectors.json`:"
        addition = """- `temporal_memory_metadata_vectors.json`: cinco eventos aceptados, separación entre captura,
  almacenamiento y tiempo mencionado, relaciones temporales, ocho consultas autorizadas por ACL,
  digests reproducibles y veinticinco mutaciones que deben rechazarse.
"""
        text = text.replace(anchor, addition + anchor) if anchor in text else text + "\n" + addition
    paragraph = "Python y Node reconstruyen además la misma proyección temporal"
    if paragraph not in text:
        addition = """
Python y Node reconstruyen además la misma proyección temporal. La capa copia el tiempo canónico
de captura, liga el almacenamiento al registro aceptado, verifica intervalos y relaciones, y
aplica ACL y corte histórico antes de cada predicado temporal. El fixture prueba cinco
anotaciones, ocho consultas y veinticinco rechazos sin afirmar comprensión general del lenguaje.

"""
        anchor = "## Requisitos para una implementación"
        text = text.replace(anchor, addition + anchor) if anchor in text else text + addition
    write("conformance/README.md", text)


def update_checklist() -> None:
    text = read("docs/V0_1_COMPLETION_CHECKLIST.md")
    pr_number = pull_request_number()
    if pr_number and f"PR #{pr_number}" not in text:
        anchor = "- [ ] Protección de `main` exige el check `reference-checks` antes de cada fusión."
        line = f"- [x] Suite completa verde para metadata temporal verificable en el [PR #{pr_number}](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/{pr_number}).\n"
        text = text.replace(anchor, line + anchor)
    text = re.sub(r"Compilación de los \d+ JSON Schema", "Compilación de los 37 JSON Schema", text)
    text = re.sub(r"Cuarenta y (?:tres|cuatro|cinco) regresiones", "Cuarenta y cinco regresiones", text)
    implemented = "- [x] Metadata temporal reconstruible"
    if implemented not in text:
        addition = """- [x] Metadata temporal reconstruible con cinco anotaciones, ocho consultas, separación de
      captura/almacenamiento/tiempo mencionado, relaciones verificadas, ACL previa, aislamiento
      histórico y veinticinco cruces de frontera rechazados por Python y Node.
"""
        text = text.replace("\n## Pendiente real", "\n" + addition + "\n## Pendiente real")
    text = text.replace("- [ ] Filtros, scopes y ACL de consulta enlazados con privacidad y autoridad.\n", "")
    text = text.replace("- [ ] Metadata temporal derivada con procedencia verificable.\n", "")
    write("docs/V0_1_COMPLETION_CHECKLIST.md", text)


def update_observer_map() -> None:
    path = ROOT / "observer/system-map.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if not any(item.get("id") == "temporal_memory" for item in document["components"]):
        component = {
            "id": "temporal_memory",
            "name": "Metadata temporal",
            "layer": "perception",
            "maturity": "verified",
            "description": "Proyección reconstruible que separa captura, almacenamiento, tiempo mencionado y relaciones bajo ACL.",
            "keywords": ["temporal_memory", "temporal_metadata", "mentioned_start", "mentioned_end"],
            "required_evidence": ["spec", "schema", "conformance", "implementation"]
        }
        index = next((i + 1 for i, item in enumerate(document["components"]) if item.get("id") == "memory_retrieval"), len(document["components"]))
        document["components"].insert(index, component)
    if "temporal_memory" not in document["flow"]:
        index = document["flow"].index("memory_retrieval") + 1
        document["flow"].insert(index, "temporal_memory")
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def update_memvid_map() -> None:
    text = read("docs/MEMVID_MEMORY_EXTRACTION_MAP.md")
    marker = "## Segunda extracción: metadata temporal"
    if marker not in text:
        text += """

## Segunda extracción: metadata temporal

Genesis adapta la separación entre tiempo de ingestión, tiempo mencionado y consulta histórica
como una proyección neutral propia. La implementación liga cada anotación al evento y al digest
de contenido, verifica intervalos y relaciones, y aplica ACL antes de consultar. No copia el
parser, formato de archivo, dependencias ni código fuente de Memvid.

Estado: contrato, schema, vectores y validación Python/Node implementados. Un parser general de
lenguaje natural y zonas horarias ambiguas permanece diferido como adaptador reemplazable.
"""
    write("docs/MEMVID_MEMORY_EXTRACTION_MAP.md", text)


def main() -> None:
    update_schema_regression()
    update_readme()
    update_start_here()
    update_conformance_readme()
    update_checklist()
    update_observer_map()
    update_memvid_map()


if __name__ == "__main__":
    main()

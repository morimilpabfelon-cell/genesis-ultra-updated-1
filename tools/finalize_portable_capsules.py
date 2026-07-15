#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

def insert_before(text, marker, block):
    if block.strip() in text:
        return text
    if marker not in text:
        raise RuntimeError(f"missing marker: {marker}")
    return text.replace(marker, block.rstrip() + "\n\n" + marker, 1)

def update_inventory():
    path = ROOT / "conformance/required_artifacts.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    additions = {
        "conformance/portable_memory_capsule_vectors.json", "schemas/portable_memory_capsule.schema.json",
        "spec/PORTABLE_MEMORY_CAPSULES.md", "tools/portable_capsule_common.mjs",
        "tools/portable_capsule_document.mjs", "tools/portable_capsule_core.mjs",
        "tools/portable_capsule_conformance.mjs", "tools/portable_memory_capsule.mjs",
        "tools/portable_capsule_common.py", "tools/portable_capsule_document.py",
        "tools/portable_capsule_builder.py", "tools/portable_capsule_verify.py",
        "tools/validate_portable_memory_capsule.py",
    }
    data["required"] = sorted(set(data["required"]) | additions, key=lambda value: value.encode("utf-8"))
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def load_validator():
    target = ROOT / "tools/validate_portable_memory_capsule.py"
    spec = importlib.util.spec_from_file_location("capsule_validator", target)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module

def update_schema_regression():
    module = load_validator()
    vector = json.loads((ROOT / "conformance/portable_memory_capsule_vectors.json").read_text(encoding="utf-8"))
    capsule = module.build_capsule(vector, "export_portable_full")
    capsule["unexpected_core_field"] = True
    path = ROOT / "conformance/schema_invalid_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    case_id = "portable-memory-capsule-rejects-unexpected-field"
    data["cases"] = [case for case in data["cases"] if case.get("case_id") != case_id]
    data["cases"].append({"case_id": case_id, "schema": "portable_memory_capsule.schema.json", "expected_error_keyword": "additionalProperties", "artifact": capsule})
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def update_readme():
    path = ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    block = '''## Cápsulas portables de memoria

Validar que Python y Node producen las mismas cápsulas:

```powershell
npm run validate:portable-capsules
```

Construir una cápsula autorizada de un solo archivo:

```powershell
npm run memory:capsule:build -- conformance/portable_memory_capsule_vectors.json export_portable_full memoria.gencap.json
```

Verificar o inspeccionar una cápsula sin modificarla:

```powershell
npm run memory:capsule:verify -- memoria.gencap.json
npm run memory:capsule:inspect -- memoria.gencap.json
```

La cápsula incluye eventos autorizados, anclas redactadas de continuidad, proyecciones opcionales,
manifiesto y recibo enlazado a ACL. No es identidad, no concede escritura y no reemplaza la cadena
append-only. El contrato está en
[`spec/PORTABLE_MEMORY_CAPSULES.md`](spec/PORTABLE_MEMORY_CAPSULES.md).'''
    path.write_text(insert_before(text, "## Observabilidad local en vivo", block), encoding="utf-8")

def update_start():
    path = ROOT / "START_HERE.md"
    text = path.read_text(encoding="utf-8")
    block = '''## Probar cápsulas portables

```powershell
npm run validate:portable-capsules
npm run memory:capsule:build -- conformance/portable_memory_capsule_vectors.json export_portable_full memoria.gencap.json
npm run memory:capsule:verify -- memoria.gencap.json
```

La exportación recibe únicamente eventos permitidos por una decisión ACL `transfer_export`.
Los eventos omitidos se representan con anclas redactadas para conservar continuidad sin revelar
contenido. Importar una cápsula requiere una transacción separada.'''
    path.write_text(insert_before(text, "## Observar el estado en vivo", block), encoding="utf-8")

def update_conformance_readme():
    path = ROOT / "conformance/README.md"
    text = path.read_text(encoding="utf-8")
    bullet = '''- `portable_memory_capsule_vectors.json`: cinco eventos fuente, dos decisiones ACL,
  tres exportaciones portables, proyecciones opcionales, continuidad redactada, 35 mutaciones
  previas a exportación y 17 alteraciones de cápsula que deben rechazarse.'''
    if bullet not in text:
        marker = "- `temporal_memory_metadata_vectors.json`:"
        pos = text.find(marker)
        end = text.find("\n- ", pos + 2)
        if pos < 0 or end < 0:
            raise RuntimeError("vector bullet marker missing")
        text = text[:end+1] + bullet + "\n" + text[end+1:]
    paragraph = '''Python y Node construyen además cápsulas portables idénticas para cuerpo, archivo del
guardián y backup offline. El manifiesto compromete componentes, tamaños y digests; las anclas
redactadas preservan continuidad sin exponer eventos no exportados. La verificación rechaza
cuarentena, referencias fuera de ACL, rutas inválidas, autoridad incrustada y alteraciones.'''
    path.write_text(insert_before(text, "## Requisitos para una implementación", paragraph), encoding="utf-8")

def update_memvid_map():
    path = ROOT / "docs/MEMVID_MEMORY_EXTRACTION_MAP.md"
    text = path.read_text(encoding="utf-8")
    block = '''## Cuarta extracción implementada: cápsulas portables

La portabilidad de archivo único de Memvid se adaptó como un formato propio y neutral:

- JSON UTF-8 transparente en lugar de `.mv2`;
- subconjunto canónico autorizado por ACL;
- anclas redactadas para continuidad sin divulgación;
- proyecciones léxicas y temporales opcionales y reconstruibles;
- manifiesto de componentes con tamaño y SHA-256;
- recibo ligado a destinatario, cutoff y decisión ACL;
- verificación independiente Python/Node;
- salida atómica y operación sin servidor.

No se importaron el formato, codecs, índices o código de Memvid. Compresión, cifrado de destinatario
y contenedor binario permanecen diferidos para perfiles separados.'''
    if block not in text:
        text = text.rstrip() + "\n\n" + block + "\n"
    path.write_text(text, encoding="utf-8")

def update_checklist():
    path = ROOT / "docs/V0_1_COMPLETION_CHECKLIST.md"
    text = path.read_text(encoding="utf-8")
    evidence = "- [x] Suite completa verde para cápsulas portables verificables en el [PR #21](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/21)."
    anchor = "- [x] Suite completa verde para metadata temporal verificable en el [PR #20](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/20)."
    if evidence not in text:
        text = text.replace(anchor, anchor + "\n" + evidence, 1)
    text = text.replace("Compilación de los 37 JSON Schema", "Compilación de los 38 JSON Schema")
    text = text.replace("Cuarenta y cinco regresiones", "Cuarenta y seis regresiones")
    done = '''- [x] Cápsulas portables neutrales reproducidas por Python y Node: tres exportaciones,
      manifiesto de componentes, continuidad redactada, recibo ACL, proyecciones reconstruibles,
      35 cruces previos a exportación y 17 alteraciones posteriores rechazadas.'''
    if done not in text:
        text = text.replace("\n## Pendiente real", "\n" + done + "\n\n## Pendiente real", 1)
    text = text.replace("- [ ] Cápsulas portables neutrales y reconstruibles.\n", "")
    path.write_text(text, encoding="utf-8")

def update_system_map():
    path = ROOT / "observer/system-map.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    item = {"id": "portable_capsules", "name": "Cápsulas portables", "layer": "continuity", "maturity": "verified", "description": "Exporta subconjuntos ACL en cápsulas JSON verificables con continuidad redactada, manifiesto y recibo.", "keywords": ["portable_memory_capsule", "portable_capsules", "gencap"], "required_evidence": ["spec", "schema", "conformance", "implementation"]}
    data["components"] = [value for value in data["components"] if value["id"] != item["id"]]
    at = next((index + 1 for index, value in enumerate(data["components"]) if value["id"] == "memory_retrieval"), len(data["components"]))
    data["components"].insert(at, item)
    flow = [value for value in data["flow"] if value != item["id"]]
    if "memory_retrieval" in flow:
        flow.insert(flow.index("memory_retrieval") + 1, item["id"])
    data["flow"] = flow
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def cleanup():
    for relative in ["tools/finalize_portable_capsules.py", ".github/workflows/finalize-portable-capsules.yml"]:
        target = ROOT / relative
        if target.exists():
            target.unlink()

def main():
    update_inventory(); update_schema_regression(); update_readme(); update_start()
    update_conformance_readme(); update_memvid_map(); update_checklist(); update_system_map(); cleanup()

if __name__ == "__main__":
    main()

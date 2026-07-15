#!/usr/bin/env python3
"""Temporary, deterministic repository edit for the memory-gate retrieval bridge."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8", newline="\n")


def replace_once(path: str, old: str, new: str) -> None:
    content = read(path)
    if new in content:
        return
    if content.count(old) != 1:
        raise RuntimeError(f"replacement_anchor_invalid:{path}:{content.count(old)}")
    write(path, content.replace(old, new, 1))


def update_json(path: str, transform) -> None:
    value = json.loads(read(path))
    transform(value)
    write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


replace_once(
    "tools/validate_memory_retrieval.mjs",
    'if (!Array.isArray(queries) || queries.length === 0) throw new ConformanceError("retrieval_queries_invalid");',
    'if (!Array.isArray(queries)) throw new ConformanceError("retrieval_queries_invalid");',
)
replace_once(
    "tools/validate_memory_retrieval.py",
    'if not isinstance(queries, list) or not queries:\n        raise ConformanceError("retrieval_queries_invalid")',
    'if not isinstance(queries, list):\n        raise ConformanceError("retrieval_queries_invalid")',
)


def package_transform(value: dict) -> None:
    scripts = value["scripts"]
    additions = {
        "validate:retrieval-bridge": "node tools/memory_gate_retrieval_bridge.mjs validate",
        "memory:bridge:build": "node tools/memory_gate_retrieval_bridge.mjs build",
        "memory:bridge:sync": "node tools/memory_gate_retrieval_bridge.mjs sync",
        "memory:bridge:query": "node tools/memory_gate_retrieval_bridge.mjs query",
    }
    ordered: dict[str, str] = {}
    for key, command in scripts.items():
        ordered[key] = command
        if key == "validate:retrieval":
            ordered["validate:retrieval-bridge"] = additions.pop("validate:retrieval-bridge")
        if key == "memory:query":
            for addition in ["memory:bridge:build", "memory:bridge:sync", "memory:bridge:query"]:
                ordered[addition] = additions.pop(addition)
    ordered.update(additions)
    value["scripts"] = ordered


update_json("package.json", package_transform)

replace_once(
    "tools/run_conformance.mjs",
    '''  [
    "Validate deterministic memory retrieval independently (Node)",
    process.execPath,
    ["tools/validate_memory_retrieval.mjs"]
  ],''',
    '''  [
    "Validate deterministic memory retrieval independently (Node)",
    process.execPath,
    ["tools/validate_memory_retrieval.mjs"]
  ],
  [
    "Validate memory-gate retrieval bridge (Python)",
    python,
    ["tools/validate_memory_gate_retrieval_bridge.py"]
  ],
  [
    "Validate memory-gate retrieval bridge independently (Node)",
    process.execPath,
    ["tools/memory_gate_retrieval_bridge.mjs", "validate"]
  ],''',
)


def inventory_transform(value: dict) -> None:
    additions = {
        "conformance/memory_gate_retrieval_bridge_vectors.json",
        "schemas/memory_gate_retrieval_bridge.schema.json",
        "spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md",
        "tools/memory_gate_retrieval_bridge.mjs",
        "tools/validate_memory_gate_retrieval_bridge.py",
    }
    value["required"] = sorted(set(value["required"]) | additions, key=lambda item: item.encode("utf-8"))


update_json("conformance/required_artifacts.json", inventory_transform)


def schema_cases_transform(value: dict) -> None:
    case_id = "memory-gate-retrieval-bridge-rejects-unexpected-field"
    if any(case.get("case_id") == case_id for case in value["cases"]):
        return
    vector = json.loads(read("conformance/memory_gate_retrieval_bridge_vectors.json"))
    artifact = {key: child for key, child in vector.items() if key not in {"expected", "must_reject"}}
    artifact["unexpected_core_field"] = True
    value["cases"].append({
        "case_id": case_id,
        "schema": "memory_gate_retrieval_bridge.schema.json",
        "expected_error_keyword": "additionalProperties",
        "artifact": artifact,
    })


update_json("conformance/schema_invalid_cases.json", schema_cases_transform)

replace_once(
    "README.md",
    "La suite ejecuta los validadores Python y Node, compila los 34 JSON Schema, verifica en ambos",
    "La suite ejecuta los validadores Python y Node, compila los 35 JSON Schema, verifica en ambos",
)
replace_once(
    "README.md",
    "primeros sentidos, la compuerta firmada antes de memoria, la proyección asociativa y la\nrecuperación determinista reconstruible.",
    "primeros sentidos, la compuerta firmada antes de memoria, el puente firmado que conecta\nsolo eventos ya comprometidos con recuperación, la proyección asociativa y la recuperación\ndeterminista reconstruible.",
)
replace_once(
    "README.md",
    "## Observabilidad local en vivo",
    '''## Conectar la compuerta firmada con recuperación

Validar el puente completo:

```powershell
npm run validate:retrieval-bridge
```

Construir o sincronizar atómicamente un snapshot reconstruible después del commit append-only:

```powershell
npm run memory:bridge:build -- entrada-puente.json salida.json
npm run memory:bridge:sync -- entrada-puente.json runtime/retrieval.json
```

Consultar directamente un bundle verificado:

```powershell
npm run memory:bridge:query -- entrada-puente.json "workshop memory" --top-k 5
```

El puente verifica firmas Ed25519, decisión `accepted`, enlaces observación→compuerta→evento,
cadena append-only y vista textual ligada por digest. No crea eventos, no acepta decisiones
rechazadas o en cuarentena y nunca reemplaza la memoria autoritativa. El contrato está en
[`spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md`](spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md).

## Observabilidad local en vivo''',
)

replace_once(
    "START_HERE.md",
    "La búsqueda usa únicamente registros aceptados, devuelve eventos canónicos y permite replay\nmediante `--as-of N`. El índice es una proyección eliminable; la cadena append-only sigue siendo\nla memoria verdadera.",
    '''La búsqueda usa únicamente registros aceptados, devuelve eventos canónicos y permite replay
mediante `--as-of N`. El índice es una proyección eliminable; la cadena append-only sigue siendo
la memoria verdadera.

Para validar y sincronizar el puente firmado desde la compuerta:

```powershell
npm run validate:retrieval-bridge
npm run memory:bridge:sync -- entrada-puente.json runtime/retrieval.json
```

El host debe invocarlo únicamente después de comprometer el evento append-only.''',
)

replace_once(
    "conformance/README.md",
    "- `memory_retrieval_vectors.json`: cinco recuerdos aceptados, índice léxico determinista,\n  consultas asistidas por grafo, replay temporal, digests esperados y veintidós mutaciones de\n  autoridad, integridad, ranking o filtración futura que deben rechazarse.",
    '''- `memory_retrieval_vectors.json`: cinco recuerdos aceptados, índice léxico determinista,
  consultas asistidas por grafo, replay temporal, digests esperados y veintidós mutaciones de
  autoridad, integridad, ranking o filtración futura que deben rechazarse.
- `memory_gate_retrieval_bridge_vectors.json`: observación y compuerta firmadas, evento ya
  comprometido, vista textual ligada por digest, recibo de derivación y diecinueve ataques que
  intentan introducir firmas inválidas, cobertura incompleta, datos alterados o contenido futuro.''',
)
replace_once(
    "conformance/README.md",
    "El ranking solo selecciona evidencia y no concede autoridad ni convierte similitud en verdad.",
    '''El ranking solo selecciona evidencia y no concede autoridad ni convierte similitud en verdad.

Python y Node validan además el puente operacional entre la compuerta y recuperación. Solo una
decisión `accepted` firmada y enlazada a un evento append-only válido puede producir un registro.
La sincronización sustituye atómicamente el snapshot reconstruible y deja intacta la cadena.''',
)

replace_once(
    "docs/V0_1_COMPLETION_CHECKLIST.md",
    "- [x] Recuperación determinista de memoria aceptada con cinco frames, 38 términos, cuatro\n      consultas y cinco checkpoints de replay, reproducida por Python y Node con el mismo\n      digest y veintidós ataques de autoridad, integridad, ranking o filtración futura rechazados.",
    '''- [x] Recuperación determinista de memoria aceptada con cinco frames, 38 términos, cuatro
      consultas y cinco checkpoints de replay, reproducida por Python y Node con el mismo
      digest y veintidós ataques de autoridad, integridad, ranking o filtración futura rechazados.
- [x] Puente compuerta→evento append-only→recuperación con firmas Ed25519, cobertura exacta,
      vista textual ligada por digest, recibo reproducible y reemplazo atómico del snapshot,
      reproducido por Python y Node con diecinueve cruces de frontera rechazados.''',
)
replace_once(
    "docs/V0_1_COMPLETION_CHECKLIST.md",
    "- [ ] Adaptadores y pruebas de journal con almacenamiento real en Android, Apple y Windows.",
    '''- [ ] Adaptadores y pruebas de journal con almacenamiento real en Android, Apple y Windows.
- [ ] Invocación persistente del puente desde runtimes reales después de cada commit append-only;
      el bridge actual es operativo bajo demanda, no un daemon ni un escritor autónomo.''',
)


def system_map_transform(value: dict) -> None:
    for component in value["components"]:
        if component["id"] == "memory_gate":
            component["description"] = "Decide qué observaciones pueden convertirse en eventos aceptados y prueba el enlace firmado hacia recuperación."
            component["keywords"] = sorted(set(component["keywords"]) | {"memory_gate_retrieval_bridge"})
        if component["id"] == "memory_retrieval":
            component["description"] = "Índice reconstruible con búsqueda léxica, replay temporal, ranking asistido por grafo y entrada verificada desde la compuerta."
            component["keywords"] = sorted(set(component["keywords"]) | {"memory_gate_retrieval_bridge"})


update_json("observer/system-map.json", system_map_transform)
print("Prepared memory-gate retrieval bridge repository integration.")

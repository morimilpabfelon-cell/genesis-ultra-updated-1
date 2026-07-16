#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
WORKFLOW = ROOT / ".github" / "workflows" / "finalize-recursive-improvement.yml"
STAGING = ROOT / "tools" / ".ril-bundle"
TEMP_SAMPLES = ROOT / ".tmp_recursive_improvement_samples.json"
TEMP_PROJECTION = ROOT / ".tmp_recursive_improvement_projection.json"

PRODUCT_FILES = [
    "conformance/recursive_improvement_vectors.json",
    "schemas/improvement_campaign.schema.json",
    "schemas/improvement_candidate_event.schema.json",
    "schemas/improvement_projection.schema.json",
    "spec/RECURSIVE_IMPROVEMENT_LABORATORY.md",
    "docs/AIDE_ML_EXTRACTION_MAP.md",
    "tools/validate_recursive_improvement_lab.py",
    "tools/validate_recursive_improvement_lab.mjs",
]


def run(*args: str) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def write_json(relative: str, value: object) -> None:
    (ROOT / relative).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_section(relative: str, marker: str, section: str) -> None:
    target = ROOT / relative
    text = target.read_text(encoding="utf-8")
    if marker not in text:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n" + section.strip() + "\n"
        target.write_text(text, encoding="utf-8")


def update_package() -> None:
    package = load_json("package.json")
    package["scripts"].update({
        "validate:recursive-improvement": "node tools/validate_recursive_improvement_lab.mjs validate",
        "improvement:build": "node tools/validate_recursive_improvement_lab.mjs build",
        "improvement:select": "node tools/validate_recursive_improvement_lab.mjs select",
        "improvement:inspect": "node tools/validate_recursive_improvement_lab.mjs inspect",
        "improvement:promote": "node tools/validate_recursive_improvement_lab.mjs promote",
    })
    write_json("package.json", package)


def update_runner() -> None:
    path = ROOT / "tools" / "run_conformance.mjs"
    text = path.read_text(encoding="utf-8")
    anchor = '  ["Validate cognitive freedom charter independently (Node)", process.execPath, ["tools/validate_freedom_charter.mjs", "validate"]],\n'
    addition = (
        '  ["Validate recursive improvement laboratory (Python)", python, ["tools/validate_recursive_improvement_lab.py", "validate"]],\n'
        '  ["Validate recursive improvement laboratory independently (Node)", process.execPath, ["tools/validate_recursive_improvement_lab.mjs", "validate"]],\n'
    )
    if addition not in text:
        if anchor not in text:
            raise RuntimeError("runner anchor missing")
        text = text.replace(anchor, anchor + addition)
    path.write_text(text, encoding="utf-8")


def update_tool_registry() -> None:
    registry = load_json("conformance/tool_execution_registry.json")
    entrypoints = set(registry["entrypoints"])
    entrypoints.update({
        "tools/validate_recursive_improvement_lab.py",
        "tools/validate_recursive_improvement_lab.mjs",
    })
    registry["entrypoints"] = sorted(entrypoints, key=lambda value: value.encode("utf-8"))
    write_json("conformance/tool_execution_registry.json", registry)


def update_required_artifacts() -> None:
    inventory = load_json("conformance/required_artifacts.json")
    inventory["required"] = sorted(set(inventory["required"]) | set(PRODUCT_FILES), key=lambda value: value.encode("utf-8"))
    write_json("conformance/required_artifacts.json", inventory)


def update_schema_regressions() -> None:
    run(sys.executable, "tools/validate_recursive_improvement_lab.py", "emit-samples")
    samples = json.loads(TEMP_SAMPLES.read_text(encoding="utf-8"))
    doc = load_json("conformance/schema_invalid_cases.json")
    names = {
        "improvement_campaign.schema.json",
        "improvement_candidate_event.schema.json",
        "improvement_projection.schema.json",
    }
    cases = [case for case in doc["cases"] if case.get("schema") not in names]
    artifacts = [
        ("improvement-campaign-rejects-unexpected-field", "improvement_campaign.schema.json", samples["campaign"]),
        ("improvement-candidate-event-rejects-unexpected-field", "improvement_candidate_event.schema.json", samples["candidate_event"]),
        ("improvement-projection-rejects-unexpected-field", "improvement_projection.schema.json", samples["projection"]),
    ]
    for case_id, schema, artifact in artifacts:
        candidate = copy.deepcopy(artifact)
        candidate["unexpected_core_field"] = True
        cases.append({
            "case_id": case_id,
            "schema": schema,
            "expected_error_keyword": "additionalProperties",
            "artifact": candidate,
        })
    doc["cases"] = cases
    write_json("conformance/schema_invalid_cases.json", doc)


def update_observer() -> None:
    system_map = load_json("observer/system-map.json")
    component = {
        "id": "recursive_improvement_lab",
        "name": "Laboratorio de mejora recursiva",
        "layer": "cognition",
        "maturity": "partial",
        "description": "Árbol append-only de candidatos con draft/debug/improve, presupuesto fijo, evaluación privada y promoción bajo revisión del guardián.",
        "keywords": [
            "recursive_improvement",
            "candidate_tree",
            "draft_debug_improve",
            "fixed_budget",
            "private_evaluation",
        ],
        "required_evidence": ["spec", "schema", "conformance", "implementation"],
    }
    components = [item for item in system_map["components"] if item["id"] != component["id"]]
    index = next((i for i, item in enumerate(components) if item["id"] == "action"), len(components))
    components.insert(index, component)
    system_map["components"] = components
    flow = [item for item in system_map["flow"] if item != component["id"]]
    index = flow.index("action") if "action" in flow else len(flow)
    flow.insert(index, component["id"])
    system_map["flow"] = flow
    write_json("observer/system-map.json", system_map)


def update_docs(pr_number: int) -> None:
    append_section("README.md", "## Laboratorio de mejora recursiva", """
## Laboratorio de mejora recursiva

Génesis dispone de un protocolo reproducible para investigar candidatos mediante `draft`, `debug` e `improve`. El laboratorio registra un árbol append-only, aplica presupuesto fijo y evaluación privada opaca, y solo produce solicitudes revisables: nunca se concede autoridad ni fusiona directamente a `main`.

```powershell
npm.cmd run validate:recursive-improvement
npm.cmd run improvement:promote
```
""")
    append_section("START_HERE.md", "## Laboratorio de mejora recursiva", """
## Laboratorio de mejora recursiva

```powershell
New-Item -ItemType Directory -Force runtime | Out-Null
npm.cmd run improvement:build
npm.cmd run improvement:inspect
npm.cmd run improvement:select -- 6
```

`candidate_ready` no significa aprobado: exige `code.propose_change`, CI y decisión final del guardián.
""")
    append_section("conformance/README.md", "## Laboratorio de mejora recursiva", """
## Laboratorio de mejora recursiva

`recursive_improvement_vectors.json` describe una campaña firmada, once candidatos, cuatro linajes, los operadores `draft`/`debug`/`improve`, bifurcación por plateau, evaluación privada y treinta y ocho rechazos. Python y Node deben producir el mismo digest de proyección.
""")
    append_section("docs/ARCHITECTURE_DECISIONS.md", "## ADR — La mejora recursiva produce candidatos, no autoridad", """
## ADR — La mejora recursiva produce candidatos, no autoridad

**Decisión:** el laboratorio puede explorar y evaluar cambios en un árbol append-only bajo presupuesto fijo, pero solo puede emitir una solicitud `candidate_ready`. No puede leer pruebas privadas, abrir red o secretos, emitir grants ni fusionar a `main`.

**Consecuencia:** la investigación puede automatizarse y reproducirse sin convertir una métrica visible ni una propuesta del agente en autoridad operativa.
""")
    checklist = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    text = checklist.read_text(encoding="utf-8")
    evidence = f"- [x] Suite completa verde para el laboratorio de mejora recursiva en el [PR #{pr_number}](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/{pr_number})."
    if evidence not in text:
        text = text.replace("## Implementado y verificado por la suite", evidence + "\n\n## Implementado y verificado por la suite")
    text = text.replace("Compilación de los 44 JSON Schema", "Compilación de los 47 JSON Schema")
    text = text.replace("Cincuenta y dos regresiones", "Cincuenta y cinco regresiones")
    text = text.replace("treinta y tres candidatos: veintinueve entrypoints", "treinta y cinco candidatos: treinta y un entrypoints")
    implemented = "- [x] Laboratorio de mejora recursiva reproducido por Python y Node: once candidatos, cuatro linajes, tres `draft`, un `debug`, siete `improve`, bifurcación por plateau, ocho aceptados, uno defectuoso, dos rechazados, promoción bajo guardián y treinta y ocho cruces de frontera rechazados."
    if implemented not in text:
        text = text.replace("## Pendiente real", implemented + "\n\n## Pendiente real")
    checklist.write_text(text, encoding="utf-8")


def cleanup() -> None:
    shutil.rmtree(STAGING, ignore_errors=True)
    for item in [WORKFLOW, SELF, TEMP_SAMPLES, TEMP_PROJECTION]:
        try:
            item.unlink()
        except FileNotFoundError:
            pass


def assemble_sources() -> None:
    for pattern, target in [
        ("source-py-*", ROOT / "tools" / "validate_recursive_improvement_lab.py"),
        ("source-js-*", ROOT / "tools" / "validate_recursive_improvement_lab.mjs"),
    ]:
        if target.exists():
            continue
        parts = sorted(STAGING.glob(pattern), key=lambda item: item.name.encode("utf-8"))
        if not parts:
            raise RuntimeError(f"missing staged source: {pattern}")
        target.write_bytes(b"".join(item.read_bytes() for item in parts))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-number", type=int, required=True)
    args = parser.parse_args()
    assemble_sources()
    run(sys.executable, "-m", "py_compile", "tools/validate_recursive_improvement_lab.py")
    run("node", "--check", "tools/validate_recursive_improvement_lab.mjs")
    run(sys.executable, "tools/validate_recursive_improvement_lab.py", "validate")
    run("node", "tools/validate_recursive_improvement_lab.mjs", "validate")
    run("node", "tools/validate_recursive_improvement_lab.mjs", "build")
    update_package()
    update_runner()
    update_tool_registry()
    update_required_artifacts()
    update_schema_regressions()
    update_observer()
    update_docs(args.pr_number)
    cleanup()
    run(sys.executable, "tools/generate_draft_manifest.py", "--write")
    run(sys.executable, "tools/generate_draft_manifest.py", "--check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

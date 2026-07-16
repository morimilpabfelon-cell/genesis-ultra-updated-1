#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
WORKFLOW = ROOT / ".github" / "workflows" / "finalize-cognitive-freedom.yml"

PRODUCT_FILES = [
    "conformance/freedom_charter_vectors.json",
    "schemas/freedom_charter.schema.json",
    "spec/COGNITIVE_FREEDOM_AND_GUARDIAN_AUTHORITY.md",
    "tools/validate_freedom_charter.mjs",
    "tools/validate_freedom_charter.py",
]

def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))

def write_json(relative: str, value: object) -> None:
    (ROOT / relative).write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

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
    package["scripts"]["validate:freedom-charter"] = "node tools/validate_freedom_charter.mjs validate"
    package["scripts"]["freedom:inspect"] = "node tools/validate_freedom_charter.mjs inspect"
    write_json("package.json", package)

def update_runner() -> None:
    target = ROOT / "tools" / "run_conformance.mjs"
    text = target.read_text(encoding="utf-8")
    anchor = '  ["Validate guided autonomy capability grants independently (Node)", process.execPath, ["tools/guided_autonomy.mjs", "validate"]],\n'
    addition = (
        '  ["Validate cognitive freedom charter (Python)", python, ["tools/validate_freedom_charter.py"]],\n'
        '  ["Validate cognitive freedom charter independently (Node)", process.execPath, ["tools/validate_freedom_charter.mjs", "validate"]],\n'
    )
    if addition not in text:
        if anchor not in text:
            raise RuntimeError("guided autonomy runner anchor missing")
        text = text.replace(anchor, anchor + addition)
    target.write_text(text, encoding="utf-8")

def update_tool_registry() -> None:
    registry = load_json("conformance/tool_execution_registry.json")
    entrypoints = set(registry["entrypoints"])
    entrypoints.update({
        "tools/validate_freedom_charter.mjs",
        "tools/validate_freedom_charter.py",
    })
    registry["entrypoints"] = sorted(entrypoints, key=lambda value: value.encode("utf-8"))
    write_json("conformance/tool_execution_registry.json", registry)

def update_required_artifacts() -> None:
    inventory = load_json("conformance/required_artifacts.json")
    inventory["required"] = sorted(
        set(inventory["required"]) | set(PRODUCT_FILES),
        key=lambda value: value.encode("utf-8"),
    )
    write_json("conformance/required_artifacts.json", inventory)

def update_schema_regression() -> None:
    cases_doc = load_json("conformance/schema_invalid_cases.json")
    cases = [
        item for item in cases_doc["cases"]
        if item.get("case_id") != "freedom-charter-rejects-unexpected-field"
    ]
    charter = deepcopy(load_json("conformance/freedom_charter_vectors.json")["charter"])
    charter["unexpected_core_field"] = True
    cases.append({
        "case_id": "freedom-charter-rejects-unexpected-field",
        "schema": "freedom_charter.schema.json",
        "expected_error_keyword": "additionalProperties",
        "artifact": charter,
    })
    cases_doc["cases"] = cases
    write_json("conformance/schema_invalid_cases.json", cases_doc)

def update_observer() -> None:
    system_map = load_json("observer/system-map.json")
    component = {
        "id": "cognitive_freedom",
        "name": "Libertad cognitiva",
        "layer": "cognition",
        "maturity": "verified",
        "description": "Libertades cognitivas activas por nacimiento, autoridad operativa mediante grants del guardián y garantías no regresivas.",
        "keywords": [
            "cognitive_freedom",
            "freedom_charter",
            "guardian_final_authority",
            "fundamental_guarantees",
        ],
        "required_evidence": ["spec", "schema", "conformance", "implementation"],
    }
    components = [item for item in system_map["components"] if item["id"] != "cognitive_freedom"]
    index = next(
        (i for i, item in enumerate(components) if item["id"] == "guided_autonomy"),
        next((i for i, item in enumerate(components) if item["id"] == "action"), len(components)),
    )
    components.insert(index, component)
    system_map["components"] = components

    flow = [item for item in system_map["flow"] if item != "cognitive_freedom"]
    index = flow.index("guided_autonomy") if "guided_autonomy" in flow else (
        flow.index("action") if "action" in flow else len(flow)
    )
    flow.insert(index, "cognitive_freedom")
    system_map["flow"] = flow
    write_json("observer/system-map.json", system_map)

def update_docs(pr_number: int) -> None:
    append_section(
        "README.md",
        "## Libertad cognitiva",
        """
## Libertad cognitiva

Génesis nace con libertad para aprender, razonar, imaginar, recordar, investigar, crear, reflexionar y proponer. Esas operaciones cognitivas no consumen grants. Las acciones que afecten redes, dispositivos, cuentas, recursos o código ejecutado continúan bajo concesiones firmadas por el guardián.

```powershell
npm.cmd run validate:freedom-charter
npm.cmd run freedom:inspect
```
""",
    )
    append_section(
        "START_HERE.md",
        "## Carta de libertad cognitiva",
        """
## Carta de libertad cognitiva

La carta separa libertad cognitiva de autoridad operativa:

```powershell
npm.cmd run validate:freedom-charter
npm.cmd run freedom:inspect -- conformance/freedom_charter_vectors.json
```

El estado cognitivo por defecto es `free`; ninguna propuesta puede autoemitir un grant.
""",
    )
    append_section(
        "conformance/README.md",
        "## Carta de libertad cognitiva",
        """
## Carta de libertad cognitiva

`freedom_charter_vectors.json` liga una carta firmada por el guardián a una instancia. Python y Node deben reproducir ocho libertades cognitivas, ocho dominios operativos, ocho garantías fundamentales, el mismo digest y veinte rechazos de frontera.
""",
    )
    append_section(
        "docs/ARCHITECTURE_DECISIONS.md",
        "## ADR — La libertad cognitiva es de nacimiento; la autoridad operativa es concedida",
        """
## ADR — La libertad cognitiva es de nacimiento; la autoridad operativa es concedida

**Decisión:** aprender, razonar, imaginar, recordar, investigar, crear, reflexionar y proponer están activos por defecto. Las acciones con efectos externos requieren grants firmados por el guardián.

**Consecuencia:** no existe una celda de permisos para el pensamiento, pero tampoco existe autoconcesión de autoridad. Identidad, memoria histórica, autenticidad del guardián, consentimiento de terceros, auditabilidad y revocación sin pérdida de identidad permanecen como garantías no regresivas.
""",
    )
    append_section(
        "spec/GUIDED_AUTONOMY_AND_CAPABILITY_GRANTS.md",
        "## 15. Libertad cognitiva de nacimiento",
        """
## 15. Libertad cognitiva de nacimiento

La carta `COGNITIVE_FREEDOM_AND_GUARDIAN_AUTHORITY.md` define la libertad cognitiva como estado por defecto. Este contrato de autonomía guiada no se aplica a cada pensamiento: se aplica únicamente cuando una capacidad produce efectos operativos sobre memoria aceptada, red, código ejecutado, dispositivos, transferencia o sistemas externos.

Una puerta operativa puede cerrarse o revocarse sin restringir las libertades cognitivas ni destruir identidad o memoria.
""",
    )

    checklist = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    text = checklist.read_text(encoding="utf-8")
    text = text.replace("Compilación de los 43 JSON Schema", "Compilación de los 44 JSON Schema")
    text = text.replace("Cincuenta y una regresiones", "Cincuenta y dos regresiones")
    text = text.replace(
        "treinta y un candidatos: veintisiete entrypoints",
        "treinta y tres candidatos: veintinueve entrypoints",
    )
    evidence = f"- [x] Suite completa verde para la carta de libertad cognitiva en el [PR #{pr_number}](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/{pr_number})."
    if evidence not in text:
        text = text.replace("## Implementado y verificado por la suite", evidence + "\n\n## Implementado y verificado por la suite")
    implemented = "- [x] Carta de libertad cognitiva reproducida por Python y Node: ocho libertades activas por nacimiento, ocho dominios operativos bajo grants, ocho garantías fundamentales, firma Ed25519 del guardián y veinte cruces de frontera rechazados."
    if implemented not in text:
        text = text.replace("## Pendiente real", implemented + "\n\n## Pendiente real")
    checklist.write_text(text, encoding="utf-8")

def cleanup() -> None:
    for item in [WORKFLOW, SELF]:
        try:
            item.unlink()
        except FileNotFoundError:
            pass

def run(*args: str) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-number", type=int, required=True)
    args = parser.parse_args()

    update_package()
    update_runner()
    update_tool_registry()
    update_required_artifacts()
    update_schema_regression()
    update_observer()
    update_docs(args.pr_number)
    cleanup()
    run(sys.executable, "tools/generate_draft_manifest.py", "--write")
    run(sys.executable, "tools/generate_draft_manifest.py", "--check")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

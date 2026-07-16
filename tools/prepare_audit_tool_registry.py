#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "conformance" / "required_artifacts.json"
CHECKLIST = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
SELF = ROOT / "tools" / "prepare_audit_tool_registry.py"
WORKFLOW = ROOT / ".github" / "workflows" / "finalize_audit_tool_registry.yml"

NEW_ARTIFACTS = {
    "conformance/tool_execution_registry.json",
    "docs/AUDIT_TOOL_EXECUTION_REPORT.md",
    "tools/validate_tool_execution_registry.py",
}


def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def main() -> int:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    required = set(inventory["required"])
    required.update(NEW_ARTIFACTS)
    inventory["required"] = sorted(required, key=utf8_key)
    INVENTORY.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    checklist = CHECKLIST.read_text(encoding="utf-8")
    marker = "- [x] Registro autocontrolado de ejecución de herramientas"
    if marker not in checklist:
        insertion = (
            "\n- [x] Registro autocontrolado de ejecución de herramientas con treinta candidatos: "
            "veintiséis entrypoints exigidos en el runner y cuatro bibliotecas importadas por "
            "consumidores alcanzables; cualquier herramienta nueva sin clasificar rompe `npm test`.\n"
        )
        pending = "\n## Pendiente real\n"
        if pending not in checklist:
            raise RuntimeError("checklist_pending_marker_missing")
        checklist = checklist.replace(pending, insertion + pending, 1)
        CHECKLIST.write_text(checklist, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "tools/generate_draft_manifest.py", "--write"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        return result.returncode

    SELF.unlink(missing_ok=True)
    WORKFLOW.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

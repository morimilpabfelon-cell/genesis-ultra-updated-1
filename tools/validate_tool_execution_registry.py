#!/usr/bin/env python3
"""Verifica que las herramientas de validación estén ejecutadas o conectadas como bibliotecas."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "conformance" / "tool_execution_registry.json"
RUNNER_PATH = ROOT / "tools" / "run_conformance.mjs"
EXPECTED_SCHEMA = "genesis.tool.execution.registry.v0.1"
TOP_LEVEL_FIELDS = {"schema_version", "purpose", "discovery", "entrypoints", "libraries"}
DISCOVERY_FIELDS = {"include", "exclude"}
LIBRARY_FIELDS = {"path", "used_by", "purpose"}
RUNNER_PATH_RE = re.compile(r"""["'](tools/[A-Za-z0-9_.\-/]+)["']""")


class RegistryError(RuntimeError):
    pass


def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def require_exact_fields(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise RegistryError(f"{label}_fields_invalid")


def require_sorted_unique_strings(values: object, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise RegistryError(f"{label}_invalid")
    if any(not isinstance(item, str) or not item for item in values):
        raise RegistryError(f"{label}_invalid")
    if len(values) != len(set(values)):
        raise RegistryError(f"{label}_duplicate")
    if values != sorted(values, key=utf8_key):
        raise RegistryError(f"{label}_order_invalid")
    return values


def safe_repo_path(value: str, label: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != value:
        raise RegistryError(f"{label}_path_invalid:{value}")
    resolved = ROOT / candidate
    if not resolved.is_file():
        raise RegistryError(f"{label}_missing:{value}")
    return resolved


def discover_candidates(include: list[str], exclude: set[str]) -> list[str]:
    discovered: set[str] = set()
    for pattern in include:
        if not pattern.startswith("tools/") or ".." in Path(pattern).parts:
            raise RegistryError(f"registry_discovery_pattern_invalid:{pattern}")
        for candidate in ROOT.glob(pattern):
            if candidate.is_file():
                discovered.add(candidate.relative_to(ROOT).as_posix())
    return sorted(discovered - exclude, key=utf8_key)


def runner_tool_paths() -> set[str]:
    text = RUNNER_PATH.read_text(encoding="utf-8")
    return set(RUNNER_PATH_RE.findall(text))


def python_imports_module(consumer: Path, module_name: str) -> bool:
    tree = ast.parse(consumer.read_text(encoding="utf-8"), filename=str(consumer))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == module_name or alias.name.endswith(f".{module_name}")
                for alias in node.names
            ):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == module_name or node.module.endswith(f".{module_name}"):
                return True
    return False


def javascript_imports_file(consumer: Path, filename: str) -> bool:
    text = consumer.read_text(encoding="utf-8")
    import_re = re.compile(
        r"""(?:from\s*|import\s*)["']([^"']+)["']""",
        re.MULTILINE,
    )
    return any(Path(specifier).name == filename for specifier in import_re.findall(text))


def consumer_imports_library(consumer: Path, library: Path) -> bool:
    if library.suffix == ".py" and consumer.suffix == ".py":
        return python_imports_module(consumer, library.stem)
    if library.suffix == ".mjs" and consumer.suffix == ".mjs":
        return javascript_imports_file(consumer, library.name)
    return library.name in consumer.read_text(encoding="utf-8")


def validate_registry() -> tuple[int, int, int]:
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    require_exact_fields(document, TOP_LEVEL_FIELDS, "registry")
    if document["schema_version"] != EXPECTED_SCHEMA:
        raise RegistryError("registry_schema_version_invalid")
    if not isinstance(document["purpose"], str) or not document["purpose"]:
        raise RegistryError("registry_purpose_invalid")

    discovery = document["discovery"]
    require_exact_fields(discovery, DISCOVERY_FIELDS, "registry_discovery")
    include = require_sorted_unique_strings(
        discovery["include"], "registry_discovery_include"
    )
    exclude = require_sorted_unique_strings(
        discovery["exclude"], "registry_discovery_exclude"
    )
    for path in exclude:
        safe_repo_path(path, "registry_discovery_exclude")

    entrypoints = require_sorted_unique_strings(
        document["entrypoints"], "registry_entrypoints"
    )
    entrypoint_set = set(entrypoints)
    for path in entrypoints:
        safe_repo_path(path, "registry_entrypoint")

    libraries = document["libraries"]
    if not isinstance(libraries, list) or not libraries:
        raise RegistryError("registry_libraries_invalid")
    if any(not isinstance(item, dict) for item in libraries):
        raise RegistryError("registry_libraries_invalid")
    library_paths = [item.get("path") for item in libraries]
    if any(not isinstance(path, str) or not path for path in library_paths):
        raise RegistryError("registry_library_path_invalid")
    if library_paths != sorted(library_paths, key=utf8_key):
        raise RegistryError("registry_library_order_invalid")
    if len(library_paths) != len(set(library_paths)):
        raise RegistryError("registry_library_duplicate")
    if entrypoint_set.intersection(library_paths):
        raise RegistryError("registry_role_overlap")

    runner_paths = runner_tool_paths()
    missing_from_runner = sorted(entrypoint_set - runner_paths, key=utf8_key)
    if missing_from_runner:
        raise RegistryError(
            f"registry_entrypoint_not_in_runner:{','.join(missing_from_runner)}"
        )

    for item in libraries:
        require_exact_fields(item, LIBRARY_FIELDS, "registry_library")
        library_path = safe_repo_path(item["path"], "registry_library")
        if item["path"] in runner_paths:
            raise RegistryError(f"registry_library_executed_directly:{item['path']}")
        if not isinstance(item["purpose"], str) or not item["purpose"]:
            raise RegistryError(f"registry_library_purpose_invalid:{item['path']}")
        used_by = require_sorted_unique_strings(
            item["used_by"], f"registry_library_used_by:{item['path']}"
        )
        reachable = False
        for consumer_path_text in used_by:
            consumer_path = safe_repo_path(
                consumer_path_text, "registry_library_consumer"
            )
            if not consumer_imports_library(consumer_path, library_path):
                raise RegistryError(
                    f"registry_library_import_missing:{item['path']}:{consumer_path_text}"
                )
            if consumer_path_text in runner_paths:
                reachable = True
        if not reachable:
            raise RegistryError(
                f"registry_library_not_reachable_from_runner:{item['path']}"
            )

    classified = sorted(entrypoints + library_paths, key=utf8_key)
    discovered = discover_candidates(include, set(exclude))
    missing = sorted(set(discovered) - set(classified), key=utf8_key)
    extra = sorted(set(classified) - set(discovered), key=utf8_key)
    if missing or extra:
        details = []
        if missing:
            details.append(f"unclassified={','.join(missing)}")
        if extra:
            details.append(f"not_discovered={','.join(extra)}")
        raise RegistryError(f"registry_coverage_mismatch:{';'.join(details)}")

    return len(discovered), len(entrypoints), len(libraries)


def main() -> int:
    candidate_count, entrypoint_count, library_count = validate_registry()
    print(
        "OK tool execution registry "
        f"({candidate_count} candidates: {entrypoint_count} entrypoints, "
        f"{library_count} libraries)"
    )
    print("OK every entrypoint is registered in tools/run_conformance.mjs")
    print("OK every library is imported by a runner-reachable consumer")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RegistryError, json.JSONDecodeError, SyntaxError) as error:
        print(f"FAIL tool execution registry: {error}", file=sys.stderr)
        raise SystemExit(1)

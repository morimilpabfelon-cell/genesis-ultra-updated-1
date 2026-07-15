#!/usr/bin/env python3
"""Temporarily update tracked documentation for neutral hybrid retrieval."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"missing_expected_text:{path}:{old[:40]}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def update_readme() -> None:
    replace_once(
        "README.md",
        "- puente verificable desde la compuerta firmada hacia recuperación, solo después del commit\n  append-only y sin conceder autoridad al índice;\n- especificación y vectores independientes del lenguaje.",
        "- puente verificable desde la compuerta firmada hacia recuperación, solo después del commit\n  append-only y sin conceder autoridad al índice;\n- búsqueda híbrida neutral que combina evidencia léxica, semántica opcional, grafo y tiempo,\n  con fallback léxico cuando el adaptador semántico no está disponible;\n- especificación y vectores independientes del lenguaje."
    )
    replace_once(
        "README.md",
        "La suite ejecuta los validadores Python y Node, compila los 34 JSON Schema, verifica en ambos\nlenguajes el nombre canónico, el digest de identidad, los adaptadores neutrales de los tres\nprimeros sentidos, la compuerta firmada antes de memoria, el puente firmado hacia recuperación,\nla proyección asociativa y la recuperación determinista reconstruible.",
        "La suite ejecuta los validadores Python y Node, compila los 35 JSON Schema, verifica en ambos\nlenguajes el nombre canónico, el digest de identidad, los adaptadores neutrales de los tres\nprimeros sentidos, la compuerta firmada antes de memoria, el puente firmado hacia recuperación,\nla proyección asociativa, la recuperación determinista y la búsqueda híbrida neutral."
    )
    replace_once(
        "README.md",
        "## Conectar la compuerta firmada con recuperación",
        "## Probar la búsqueda híbrida neutral\n\nValidar que Python y Node producen la misma proyección híbrida y el mismo fallback:\n\n```powershell\nnpm run validate:hybrid-retrieval\n```\n\nConsulta léxica sin vector semántico:\n\n```powershell\nnpm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json \"workshop\" --top-k 3\n```\n\nConsulta con evidencia semántica cuantizada:\n\n```powershell\nnpm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json \"move to another device\" --semantic-vector 0,1000,0,0 --top-k 3\n```\n\nEl vector del ejemplo es evidencia de conformidad del protocolo, no un modelo entrenado. Un\nadaptador real debe declarar el digest exacto de su modelo y transformar su salida al perfil\nneutral. Si el adaptador falta o falla, Génesis conserva la búsqueda léxica. El contrato está en\n[`spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md`](spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md).\n\n## Conectar la compuerta firmada con recuperación"
    )


def update_start_here() -> None:
    replace_once(
        "START_HERE.md",
        "10. [`spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md`](./spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md)\n11. [`spec/CONTINUITY_AND_MIGRATION.md`](./spec/CONTINUITY_AND_MIGRATION.md)\n12. [`spec/HASH_PROFILE_DRAFT.md`](./spec/HASH_PROFILE_DRAFT.md)\n13. [`spec/CONTINUITY_HASHES.md`](./spec/CONTINUITY_HASHES.md)\n14. [`spec/DRAFT_INTEGRITY_MANIFEST.md`](./spec/DRAFT_INTEGRITY_MANIFEST.md)\n15. [`spec/CONFORMANCE_LEVELS.md`](./spec/CONFORMANCE_LEVELS.md)\n16. [`schemas/`](./schemas)\n17. [`conformance/`](./conformance)",
        "10. [`spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md`](./spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md)\n11. [`spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md`](./spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md)\n12. [`spec/CONTINUITY_AND_MIGRATION.md`](./spec/CONTINUITY_AND_MIGRATION.md)\n13. [`spec/HASH_PROFILE_DRAFT.md`](./spec/HASH_PROFILE_DRAFT.md)\n14. [`spec/CONTINUITY_HASHES.md`](./spec/CONTINUITY_HASHES.md)\n15. [`spec/DRAFT_INTEGRITY_MANIFEST.md`](./spec/DRAFT_INTEGRITY_MANIFEST.md)\n16. [`spec/CONFORMANCE_LEVELS.md`](./spec/CONFORMANCE_LEVELS.md)\n17. [`schemas/`](./schemas)\n18. [`conformance/`](./conformance)"
    )
    replace_once(
        "START_HERE.md",
        "## Probar la entrada desde la compuerta",
        "## Probar la búsqueda híbrida neutral\n\nValidar los resultados híbridos y el fallback léxico en Python y Node:\n\n```powershell\nnpm run validate:hybrid-retrieval\n```\n\nProbar una consulta semántica reproducible:\n\n```powershell\nnpm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json \"move to another device\" --semantic-vector 0,1000,0,0 --top-k 3\n```\n\nLos vectores cuantizados del fixture prueban la frontera y el ranking; no constituyen un modelo\nsemántico entrenado. Sin vector semántico, el mismo comando usa `lexical_fallback`.\n\n## Probar la entrada desde la compuerta"
    )


def update_conformance_readme() -> None:
    replace_once(
        "conformance/README.md",
        "- `memory_retrieval_vectors.json`: cinco recuerdos aceptados, índice léxico determinista,\n  consultas asistidas por grafo, replay temporal, digests esperados y veintidós mutaciones de\n  autoridad, integridad, ranking o filtración futura que deben rechazarse.",
        "- `memory_retrieval_vectors.json`: cinco recuerdos aceptados, índice léxico determinista,\n  consultas asistidas por grafo, replay temporal, digests esperados y veintidós mutaciones de\n  autoridad, integridad, ranking o filtración futura que deben rechazarse.\n- `hybrid_memory_retrieval_vectors.json`: cinco consultas híbridas, vectores enteros ligados\n  por digest, recuperación semántica sin coincidencia literal, fallback léxico, aislamiento\n  histórico y veinticuatro cruces de autoridad, integridad, proveedor o cobertura rechazados."
    )
    replace_once(
        "conformance/README.md",
        "- `schema_invalid_cases.json`: cuarenta y dos artefactos que los JSON Schema reales deben\n  rechazar, con regresiones conectadas a los contratos existentes. Los 34 schemas se compilan",
        "- `schema_invalid_cases.json`: cuarenta y tres artefactos que los JSON Schema reales deben\n  rechazar, con regresiones conectadas a los contratos existentes. Los 35 schemas se compilan"
    )
    replace_once(
        "conformance/README.md",
        "Python y Node validan además el puente operacional entre la compuerta y recuperación.",
        "Python y Node reproducen además la misma búsqueda híbrida neutral. La capa semántica usa\nvectores enteros ligados al contenido, perfil y consulta mediante digest; combina evidencia\nléxica, semántica, del grafo y temporal sin modificar la proyección v0.1. Una consulta sin vector\nsemántico entra en `lexical_fallback`, y los filtros históricos se aplican antes de la similitud.\nLos fixtures prueban comportamiento del protocolo, no calidad de un modelo entrenado.\n\nPython y Node validan además el puente operacional entre la compuerta y recuperación."
    )
    replace_once(
        "conformance/README.md",
        "- recuperación semántica opcional mediante modelos neutrales y evaluada por separado;",
        "- adaptadores semánticos reales con modelos neutrales, digests versionados y evaluación de calidad;"
    )


def update_system_map() -> None:
    target = ROOT / "observer" / "system-map.json"
    document = json.loads(target.read_text(encoding="utf-8"))
    component = next(item for item in document["components"] if item["id"] == "memory_retrieval")
    component["description"] = (
        "Índice reconstruible con búsqueda léxica, semántica opcional, replay temporal, "
        "ranking asistido por grafo y fallback verificable."
    )
    keywords = set(component["keywords"])
    keywords.update(["hybrid_memory_retrieval", "neutral_hybrid_memory_retrieval"])
    component["keywords"] = sorted(keywords)
    target.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    update_readme()
    update_start_here()
    update_conformance_readme()
    update_system_map()
    print("Updated hybrid retrieval documentation and observer map")


if __name__ == "__main__":
    main()

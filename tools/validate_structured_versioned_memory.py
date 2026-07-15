#!/usr/bin/env python3
from __future__ import annotations
import json
import sys
from pathlib import Path
from structured_versioned_memory_common import build_projection, execute_query, apply_mutation, compute_assertion_digest, ConformanceError

ROOT = Path(__file__).resolve().parents[1] if Path(__file__).resolve().parent.name == "tools" else Path(__file__).resolve().parent
DEFAULT = ROOT / "conformance" / "structured_versioned_memory_vectors.json" if (ROOT / "conformance").exists() else ROOT / "structured_versioned_memory_vectors.json"

def base_document(vectors: dict) -> dict:
    return {k: vectors[k] for k in ("profile", "instance_id", "source_events", "assertions", "queries")}

def validate(path: Path) -> dict:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    base = base_document(vectors)
    projection = build_projection(base)
    if projection != vectors["expected_projection"]:
        raise ConformanceError("expected_projection_mismatch")
    results = [execute_query(base, query) for query in vectors["queries"]]
    if results != vectors["expected_query_results"]:
        raise ConformanceError("expected_query_results_mismatch")
    failures = []
    for case in vectors["negative_cases"]:
        candidate = apply_mutation(base, case["mutation"])
        if case.get("recompute_assertion_digests"):
            for assertion in candidate["assertions"]:
                assertion["assertion_digest"] = compute_assertion_digest(assertion)
        try:
            build_projection(candidate)
            if case["expected_error"].startswith("query_"):
                execute_query(candidate, candidate["queries"][0])
        except ConformanceError as exc:
            if str(exc) != case["expected_error"]:
                failures.append((case["case_id"], case["expected_error"], str(exc)))
        else:
            failures.append((case["case_id"], case["expected_error"], "accepted"))
    if failures:
        raise ConformanceError("negative_case_mismatch:" + json.dumps(failures, ensure_ascii=False))
    return {
        "projection_digest": projection["projection_digest"],
        "slot_count": projection["slot_count"],
        "assertion_count": projection["assertion_count"],
        "query_count": len(results),
        "negative_count": len(vectors["negative_cases"]),
    }

def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    try:
        summary = validate(path)
    except (OSError, json.JSONDecodeError, ConformanceError, KeyError, TypeError) as exc:
        print(f"FAIL structured versioned memory: {exc}")
        return 1
    print(f"OK structured versioned memory ({summary['assertion_count']} assertions, {summary['slot_count']} slots, {summary['query_count']} queries)")
    print(f"OK projection digest {summary['projection_digest']}")
    print(f"OK structured memory boundary rejection cases ({summary['negative_count']})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

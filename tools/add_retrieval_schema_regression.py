#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_memory_retrieval import build_projection  # noqa: E402

vectors_path = ROOT / "conformance" / "memory_retrieval_vectors.json"
cases_path = ROOT / "conformance" / "schema_invalid_cases.json"
case_id = "memory-retrieval-projection-rejects-unexpected-field"

vectors = json.loads(vectors_path.read_text(encoding="utf-8"))
cases_document = json.loads(cases_path.read_text(encoding="utf-8"))
if any(item.get("case_id") == case_id for item in cases_document["cases"]):
    print("Retrieval schema regression already present.")
    raise SystemExit(0)

artifact = build_projection(vectors)
artifact["unexpected_core_field"] = True
case = {
    "case_id": case_id,
    "schema": "memory_retrieval_projection.schema.json",
    "expected_error_keyword": "additionalProperties",
    "artifact": artifact,
}
cases_document["cases"].insert(1, case)
cases_path.write_text(json.dumps(cases_document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Added {case_id}")

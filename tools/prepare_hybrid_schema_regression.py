#!/usr/bin/env python3
"""Temporarily register the required negative regression for the hybrid schema."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "conformance" / "schema_invalid_cases.json"
CASE_ID = "hybrid-memory-retrieval-projection-rejects-unexpected-field"


def repeated(prefix: str, character: str) -> str:
    return prefix + character * 64


def main() -> None:
    document = json.loads(TARGET.read_text(encoding="utf-8"))
    cases = document["cases"]
    if any(item.get("case_id") == CASE_ID for item in cases):
        print(f"Regression already registered: {CASE_ID}")
        return
    cases.append({
        "case_id": CASE_ID,
        "schema": "hybrid_memory_retrieval_projection.schema.json",
        "expected_error_keyword": "additionalProperties",
        "artifact": {
            "schema_version": "genesis.memory.hybrid_retrieval.projection.v0.1",
            "hash_profile": "genesis.hash.fields.v0.1",
            "projection_id": repeated("hrpsha256:", "a"),
            "instance_id": "inst_01HHYBRIDSCHEMA0000001",
            "projection_profile": "genesis.memory.hybrid_retrieval.algorithm.v0.1",
            "base_projection_digest": repeated("sha256:", "b"),
            "semantic_profile_digest": None,
            "semantic_coverage_status": "disabled",
            "source_event_count": 1,
            "source_last_sequence": 0,
            "semantic_frame_count": 0,
            "semantic_frames": [],
            "query_results": [{
                "query_id": "query_schema",
                "base_query_digest": repeated("rqsha256:", "c"),
                "semantic_query_digest": None,
                "hybrid_query_digest": repeated("hqsha256:", "d"),
                "mode": "lexical_fallback",
                "normalized_terms": ["memory"],
                "as_of_sequence": 0,
                "top_k": 1,
                "candidate_count": 1,
                "results": [{
                    "rank": 1,
                    "event_id": "evt_01HHYBRIDSCHEMA000001",
                    "frame_id": repeated("rfsha256:", "e"),
                    "sequence": 0,
                    "score": 1,
                    "lexical_score": 1,
                    "semantic_score": 0,
                    "graph_score": 0,
                    "temporal_score": 0,
                    "matched_terms": ["memory"],
                    "reason_codes": ["lexical_match"]
                }],
                "result_digest": repeated("sha256:", "f")
            }],
            "projection_digest": repeated("sha256:", "1"),
            "unexpected_core_field": True
        }
    })
    TARGET.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Registered {CASE_ID}")


if __name__ == "__main__":
    main()

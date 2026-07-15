#!/usr/bin/env python3
"""Expand compact retrieval vectors and run the independent Python validator."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_memory_retrieval import build_projection, main as validate_main  # noqa: E402

VECTORS = ROOT / "conformance" / "memory_retrieval_vectors.json"


def expand(document: dict) -> dict:
    projection = build_projection(document)
    expected = document.get("expected", {})
    actual = {
        "projection_id": projection["projection_id"],
        "projection_digest": projection["projection_digest"],
        "frame_count": len(projection["frames"]),
        "lexicon_count": len(projection["lexicon"]),
        "checkpoint_count": len(projection["checkpoints"]),
        "query_result_digests": [item["result_digest"] for item in projection["query_results"]],
    }
    if actual != expected:
        raise AssertionError("retrieval_expected_vectors_mismatch")
    expanded = dict(document)
    expanded["projection"] = projection
    return expanded


def main() -> int:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    expanded = expand(document)
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        json.dump(expanded, handle, ensure_ascii=False)
        temp_path = Path(handle.name)
    original_argv = sys.argv
    try:
        sys.argv = [original_argv[0], str(temp_path)]
        return validate_main()
    finally:
        sys.argv = original_argv
        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())

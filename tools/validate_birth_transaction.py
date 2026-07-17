#!/usr/bin/env python3
"""Valida el vector canónico de nacimiento transaccional en Python."""

from __future__ import annotations

import argparse
import json

from birth_protocol import (
    VECTOR_PATH,
    BirthError,
    build_vector,
    evaluate_negative_case,
    validate_fixture,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-vector",
        action="store_true",
        help="Regenera el vector determinista de conformidad antes de validarlo.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_vector:
        VECTOR_PATH.write_text(
            json.dumps(build_vector(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    if vector.get("profile") != "genesis.birth.conformance.v0.1":
        raise BirthError("birth_vector_profile_invalid")
    validate_fixture(vector["fixture"])
    for case in vector["negative_cases"]:
        actual = evaluate_negative_case(case, vector["fixture"])
        if actual != case["expected_error"]:
            raise BirthError(
                f"birth_negative_case_mismatch:{case['case_id']}:expected={case['expected_error']}:actual={actual}"
            )
    expected = vector["expected"]
    if expected != {
        "phase_count": len(vector["fixture"]["journal_entries"]),
        "negative_case_count": len(vector["negative_cases"]),
        "restart_case_count": len(vector["restart_expectations"]),
        "birth_state_digest": vector["fixture"]["birth_state"]["state_digest"],
        "receipt_digest": vector["fixture"]["birth_receipt"]["receipt_digest"],
        "active_writer_count": 1,
    }:
        raise BirthError("birth_expected_summary_invalid")
    print(f"OK atomic birth state {expected['birth_state_digest']}")
    print(f"OK birth receipt {expected['receipt_digest']}")
    print(f"OK birth journal phases ({expected['phase_count']})")
    print(f"OK birth negative cases ({expected['negative_case_count']})")
    print("NOTE Guardian signature is witness evidence, never ownership or movement permission.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BirthError, KeyError, TypeError, ValueError) as error:
        print(f"FAIL birth transaction: {error}")
        raise SystemExit(1)

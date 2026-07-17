#!/usr/bin/env python3
"""Inyecta reinicios y corrupciones en cada fase del nacimiento transaccional."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

from nacl.signing import SigningKey

from birth_protocol import (
    BODY_EPOCH_ID,
    BODY_ID,
    BODY_SEED,
    VECTOR_PATH,
    make_signature,
    validate_fixture,
)
from validate_transaction_journal import (
    SIGNATURE_DOMAIN,
    compute_journal_digest,
    evaluate_restart,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-output", type=Path)
    return parser.parse_args()


def rebind(entry: dict, signing_key: SigningKey) -> None:
    entry["journal_digest"] = compute_journal_digest(entry)
    entry["signature"] = make_signature(
        signing_key,
        entry["journal_digest"],
        signer_type="body",
        signer_id=BODY_ID,
        key_epoch_id=BODY_EPOCH_ID,
        domain=SIGNATURE_DOMAIN,
        created_at=entry["updated_at"],
    )


def main() -> int:
    args = parse_args()
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    fixture = vector["fixture"]
    validate_fixture(fixture)
    entries = fixture["journal_entries"]
    previous = fixture["absent_state_digest"]
    candidate = fixture["birth_state"]["state_digest"]
    finalization = fixture["birth_receipt"]["receipt_digest"]
    signing_key = SigningKey(BODY_SEED)
    verify_key = signing_key.verify_key

    restart_cases = []
    for case in vector["restart_expectations"]:
        observed = previous if case["observed"] == "absent" else candidate
        result = evaluate_restart(
            entries[: case["latest_sequence"] + 1],
            verify_key=verify_key,
            observed_state_digest=observed,
            expected_previous_state_digest=previous,
            expected_candidate_state_digest=candidate,
            trusted_finalization_digest=finalization,
        )
        restart_cases.append(
            {
                **case,
                "observed_state_digest": observed,
                "actual_action": result["action"],
                "authoritative_state_digest": result["authoritative_state_digest"],
                "passed": result["error"] is None and result["action"] == case["expected_action"],
            }
        )

    negative_cases = []

    def expect_error(case_id: str, expected_error: str, candidate_entries: list[dict], **overrides) -> None:
        result = evaluate_restart(
            candidate_entries,
            verify_key=verify_key,
            observed_state_digest=overrides.get("observed", candidate),
            expected_previous_state_digest=overrides.get("previous", previous),
            expected_candidate_state_digest=overrides.get("candidate", candidate),
            trusted_finalization_digest=overrides.get("finalization", finalization),
        )
        negative_cases.append(
            {
                "case_id": case_id,
                "expected_error": expected_error,
                "actual_error": result["error"],
                "detected": result["error"] == expected_error,
            }
        )

    mutated = deepcopy(entries)
    mutated[-1]["sequence"] = 99
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-sequence-gap", "journal_sequence_invalid", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["previous_journal_digest"] = "sha256:" + "11" * 32
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-broken-link", "journal_chain_broken", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["instance_id"] = "inst_01HOTHERBIRTH000000000001"
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-cross-instance", "journal_identity_changed", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["phase"] = "body_bound"
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-phase-regression", "journal_phase_regression", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["commit_marker_digest"] = "sha256:" + "22" * 32
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-false-marker", "journal_commit_marker_mismatch", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["previous_state_digest"] = "sha256:" + "33" * 32
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-absent-state-changed", "journal_previous_state_changed", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["candidate_state_digest"] = "sha256:" + "44" * 32
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-candidate-changed", "journal_candidate_state_changed", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["finalization_digest"] = "sha256:" + "55" * 32
    mutated[-1]["commit_marker_digest"] = mutated[-1]["finalization_digest"]
    rebind(mutated[-1], signing_key)
    expect_error("birth-journal-receipt-changed", "journal_finalization_changed", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["signature"]["signer_id"] = "body_01HOTHERBIRTH00000000001"
    expect_error("birth-journal-signature-detached", "journal_signature_unbound", mutated)

    mutated = deepcopy(entries)
    mutated[-1]["signature"]["signature_value"] = "00" * 64
    expect_error("birth-journal-signature-forged", "journal_signature_invalid", mutated)

    mutated = deepcopy(entries)
    appended = deepcopy(mutated[-1])
    appended["sequence"] = len(mutated)
    appended["previous_journal_digest"] = mutated[-1]["journal_digest"]
    appended["status"] = "pending"
    appended["commit_marker_digest"] = None
    appended["updated_at"] = "2026-07-16T00:00:01Z"
    rebind(appended, signing_key)
    mutated.append(appended)
    expect_error("birth-journal-entry-after-born", "journal_entry_after_terminal", mutated)

    expect_error(
        "birth-journal-unknown-observed-state",
        "journal_observed_state_unknown",
        entries,
        observed="sha256:" + "66" * 32,
    )
    expect_error(
        "birth-journal-untrusted-receipt",
        "journal_finalization_untrusted",
        entries,
        finalization="sha256:" + "77" * 32,
    )

    guardian_release_required = any(
        "guardian" in (case["actual_action"] or "") for case in restart_cases
    )
    half_born_state_accepted = any(
        case["latest_sequence"] < len(entries) - 1
        and case["authoritative_state_digest"] == candidate
        for case in restart_cases
    )
    active_writer_count_after_commit = sum(
        record["status"] == "active_writer"
        for record in fixture["initial_body_registry"]["bodies"]
    )
    all_passed = (
        all(case["passed"] for case in restart_cases)
        and all(case["detected"] for case in negative_cases)
        and not guardian_release_required
        and not half_born_state_accepted
        and active_writer_count_after_commit == 1
    )
    result = {
        "schema_version": "genesis.birth.crash.simulation.v0.1",
        "birth_id": fixture["birth_state"]["birth_id"],
        "instance_id": fixture["birth_state"]["instance_id"],
        "absent_state_digest": previous,
        "birth_state_digest": candidate,
        "receipt_digest": finalization,
        "restart_cases": restart_cases,
        "negative_cases": negative_cases,
        "guardian_release_required": guardian_release_required,
        "half_born_state_accepted": half_born_state_accepted,
        "active_writer_count_after_commit": active_writer_count_after_commit,
        "all_passed": all_passed,
    }
    if args.artifacts_output:
        args.artifacts_output.parent.mkdir(parents=True, exist_ok=True)
        args.artifacts_output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "simulation": result["schema_version"],
                "restart_cases": len(restart_cases),
                "negative_cases": len(negative_cases),
                "guardian_release_required": result["guardian_release_required"],
                "half_born_state_accepted": result["half_born_state_accepted"],
                "active_writer_count_after_commit": active_writer_count_after_commit,
                "all_passed": all_passed,
            },
            indent=2,
        )
    )
    if not all_passed:
        return 1
    print(f"\n{len(restart_cases)} REINICIOS Y {len(negative_cases)} ATAQUES DE JOURNAL: todos seguros")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

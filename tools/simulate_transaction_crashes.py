#!/usr/bin/env python3
"""Simula reinicios en cada fase de un cambio de autoridad recovery B -> C."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

from nacl.signing import SigningKey

from simulate_backup_recovery import BODY_C, BODY_C_EPOCH
from simulate_transfer import make_signature_envelope, verify_signature
from validate_transaction_journal import (
    SIGNATURE_DOMAIN,
    compute_journal_digest,
    evaluate_restart,
    validate_journal_chain,
)


JOURNAL_ID = "journal_01HSIM_RECOVERY0000001"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transfer-artifacts", type=Path, required=True)
    parser.add_argument("--recovery-artifacts", type=Path, required=True)
    parser.add_argument("--artifacts-output", type=Path, required=True)
    return parser.parse_args()


def active_writer_count(registry: dict) -> int:
    return sum(body["status"] == "active_writer" for body in registry["bodies"])


def make_entry(
    entries: list[dict],
    *,
    phase: str,
    status: str,
    instance_id: str,
    recovery_id: str,
    previous_state_digest: str,
    candidate_state_digest: str | None,
    finalization_digest: str | None,
    commit_marker_digest: str | None,
    updated_at: str,
    signing_key: SigningKey,
) -> dict:
    entry = {
        "schema_version": "genesis.transaction.journal.v0.1",
        "journal_id": JOURNAL_ID,
        "sequence": len(entries),
        "previous_journal_digest": "GENESIS" if not entries else entries[-1]["journal_digest"],
        "operation_kind": "recovery",
        "operation_id": recovery_id,
        "instance_id": instance_id,
        "coordinator_body_id": BODY_C,
        "phase": phase,
        "status": status,
        "previous_state_digest": previous_state_digest,
        "candidate_state_digest": candidate_state_digest,
        "finalization_digest": finalization_digest,
        "commit_marker_digest": commit_marker_digest,
        "updated_at": updated_at,
    }
    entry["journal_digest"] = compute_journal_digest(entry)
    entry["signature"] = make_signature_envelope(
        signing_key,
        entry["journal_digest"],
        signer_type="body",
        signer_id=BODY_C,
        key_epoch_id=BODY_C_EPOCH,
        signed_domain=SIGNATURE_DOMAIN,
        created_at=updated_at,
    )
    verify_signature(entry["signature"], signing_key.verify_key)
    entries.append(entry)
    return entry


def rebind(entry: dict, signing_key: SigningKey) -> None:
    entry["journal_digest"] = compute_journal_digest(entry)
    previous_signature = entry["signature"]
    entry["signature"] = make_signature_envelope(
        signing_key,
        entry["journal_digest"],
        signer_type=previous_signature["signer_type"],
        signer_id=previous_signature["signer_id"],
        key_epoch_id=previous_signature["key_epoch_id"],
        signed_domain=previous_signature["signed_domain"],
        created_at=entry["updated_at"],
    )


def main() -> int:
    args = parse_args()
    transfer = json.loads(args.transfer_artifacts.read_text(encoding="utf-8"))
    recovery = json.loads(args.recovery_artifacts.read_text(encoding="utf-8"))

    previous_registry = transfer["body_registry"]
    candidate_registry = recovery["body_registry_after"]
    previous_digest = previous_registry["registry_digest"]
    candidate_digest = candidate_registry["registry_digest"]
    finalization_digest = recovery["recovery_finalization"]["finalization_digest"]
    recovery_id = recovery["recovery_record"]["recovery_id"]
    instance_id = recovery["recovery_record"]["instance_id"]

    assert previous_registry["instance_id"] == candidate_registry["instance_id"] == instance_id
    assert previous_digest != candidate_digest
    assert active_writer_count(previous_registry) == 1
    assert active_writer_count(candidate_registry) == 1

    signing_key_c = SigningKey(bytes([0xD4]) * 32)
    entries: list[dict] = []
    phases = [
        ("discovered", "pending", None, None, None, "2026-07-12T03:00:30Z"),
        ("verified", "pending", None, None, None, "2026-07-12T03:00:40Z"),
        ("authorized", "pending", None, None, None, "2026-07-12T03:01:10Z"),
        ("restored", "pending", candidate_digest, None, None, "2026-07-12T03:05:10Z"),
        (
            "finalizing",
            "pending",
            candidate_digest,
            finalization_digest,
            None,
            "2026-07-12T03:05:50Z",
        ),
        (
            "finalized",
            "committed",
            candidate_digest,
            finalization_digest,
            finalization_digest,
            "2026-07-12T03:06:00Z",
        ),
    ]
    for phase, status, candidate, finalization, marker, updated_at in phases:
        make_entry(
            entries,
            phase=phase,
            status=status,
            instance_id=instance_id,
            recovery_id=recovery_id,
            previous_state_digest=previous_digest,
            candidate_state_digest=candidate,
            finalization_digest=finalization,
            commit_marker_digest=marker,
            updated_at=updated_at,
            signing_key=signing_key_c,
        )

    assert validate_journal_chain(entries, signing_key_c.verify_key) is None

    restart_inputs = [
        ("crash-after-discovered", 0, previous_digest, "retain_previous_authority"),
        ("crash-after-verified", 1, previous_digest, "retain_previous_authority"),
        ("crash-after-authorized", 2, previous_digest, "retain_previous_authority"),
        ("crash-after-restored-before-state-write", 3, previous_digest, "retain_previous_authority"),
        (
            "crash-after-uncommitted-candidate-write",
            4,
            candidate_digest,
            "rollback_uncommitted_authority",
        ),
        ("crash-finalizing-before-state-write", 4, previous_digest, "retain_previous_authority"),
        ("crash-after-commit-before-state-write", 5, previous_digest, "replay_committed_authority"),
        ("restart-after-committed-state", 5, candidate_digest, "accept_committed_authority"),
    ]
    restart_cases: list[dict] = []
    for case_id, latest_sequence, observed, expected_action in restart_inputs:
        result = evaluate_restart(
            entries[: latest_sequence + 1],
            verify_key=signing_key_c.verify_key,
            observed_state_digest=observed,
            expected_previous_state_digest=previous_digest,
            expected_candidate_state_digest=candidate_digest,
            trusted_finalization_digest=finalization_digest,
        )
        restart_cases.append(
            {
                "case_id": case_id,
                "latest_sequence": latest_sequence,
                "observed_state_digest": observed,
                "expected_action": expected_action,
                "actual_action": result["action"],
                "authoritative_state_digest": result["authoritative_state_digest"],
                "passed": result["error"] is None and result["action"] == expected_action,
            }
        )

    negative_cases: list[dict] = []

    def expect_error(case_id: str, expected_error: str, candidate_entries: list[dict], **overrides) -> None:
        result = evaluate_restart(
            candidate_entries,
            verify_key=signing_key_c.verify_key,
            observed_state_digest=overrides.get("observed", candidate_digest),
            expected_previous_state_digest=overrides.get("previous", previous_digest),
            expected_candidate_state_digest=overrides.get("candidate", candidate_digest),
            trusted_finalization_digest=overrides.get("finalization", finalization_digest),
        )
        negative_cases.append(
            {
                "case_id": case_id,
                "expected_error": expected_error,
                "actual_error": result["error"],
                "detected": result["error"] == expected_error,
            }
        )

    candidate = deepcopy(entries)
    candidate[-1]["sequence"] = 99
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-sequence-gap", "journal_sequence_invalid", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["previous_journal_digest"] = "sha256:" + "11" * 32
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-broken-link", "journal_chain_broken", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["instance_id"] = "inst_01HSIM_OTHER000000000001"
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-cross-instance", "journal_identity_changed", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["phase"] = "verified"
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-phase-regression", "journal_phase_regression", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["commit_marker_digest"] = "sha256:" + "22" * 32
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-false-commit-marker", "journal_commit_marker_mismatch", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["previous_state_digest"] = "sha256:" + "33" * 32
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-previous-state-changed", "journal_previous_state_changed", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["candidate_state_digest"] = "sha256:" + "44" * 32
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-candidate-state-changed", "journal_candidate_state_changed", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["finalization_digest"] = "sha256:" + "55" * 32
    candidate[-1]["commit_marker_digest"] = candidate[-1]["finalization_digest"]
    rebind(candidate[-1], signing_key_c)
    expect_error("journal-finalization-changed", "journal_finalization_changed", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["signature"]["signer_id"] = "body_01HSIM_OTHER000000000001"
    expect_error("journal-signature-detached", "journal_signature_unbound", candidate)

    candidate = deepcopy(entries)
    candidate[-1]["signature"]["signature_value"] = "00" * 64
    expect_error("journal-signature-forged", "journal_signature_invalid", candidate)

    candidate = deepcopy(entries)
    appended = deepcopy(candidate[-1])
    appended["sequence"] = len(candidate)
    appended["previous_journal_digest"] = candidate[-1]["journal_digest"]
    appended["status"] = "pending"
    appended["commit_marker_digest"] = None
    appended["updated_at"] = "2026-07-12T03:06:10Z"
    rebind(appended, signing_key_c)
    candidate.append(appended)
    expect_error("journal-entry-after-terminal", "journal_entry_after_terminal", candidate)

    expect_error(
        "journal-unknown-observed-state",
        "journal_observed_state_unknown",
        entries,
        observed="sha256:" + "66" * 32,
    )
    expect_error(
        "journal-untrusted-finalization",
        "journal_finalization_untrusted",
        entries,
        finalization="sha256:" + "77" * 32,
    )

    passed = all(case["passed"] for case in restart_cases) and all(
        case["detected"] for case in negative_cases
    )
    bundle = {
        "schema_version": "genesis.transaction.crash.simulation.v0.1",
        "instance_id": instance_id,
        "operation_id": recovery_id,
        "previous_registry_digest": previous_digest,
        "candidate_registry_digest": candidate_digest,
        "trusted_finalization_digest": finalization_digest,
        "journal_entries": entries,
        "restart_cases": restart_cases,
        "negative_cases": negative_cases,
        "single_writer_before": active_writer_count(previous_registry) == 1,
        "single_writer_after": active_writer_count(candidate_registry) == 1,
        "all_passed": passed,
    }
    args.artifacts_output.parent.mkdir(parents=True, exist_ok=True)
    args.artifacts_output.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "simulation": bundle["schema_version"],
                "instance_id": instance_id,
                "operation_id": recovery_id,
                "journal_entries": len(entries),
                "restart_cases": len(restart_cases),
                "negative_cases": len(negative_cases),
                "single_writer_before": bundle["single_writer_before"],
                "single_writer_after": bundle["single_writer_after"],
                "all_passed": passed,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    if not passed:
        return 1
    print(
        f"\n{len(restart_cases)} REINICIOS Y {len(negative_cases)} CASOS INVÁLIDOS: todos seguros",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

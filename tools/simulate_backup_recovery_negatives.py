#!/usr/bin/env python3
"""Casos que la misma evaluación positiva de backup/recovery debe rechazar."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

from validate_backup_recovery import (
    compute_backup_commit_digest,
    compute_backup_encryption_digest,
    compute_body_revocation_digest,
    compute_continuity_gap_digest,
    compute_recovery_authorization_digest,
    compute_recovery_record_digest,
    evaluate_recovery_transaction,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    valid = json.loads(args.artifacts.read_text(encoding="utf-8"))
    results: list[dict] = []

    def expect(case_id: str, expected: str, mutate) -> None:
        candidate = deepcopy(valid)
        mutate(candidate)
        actual = evaluate_recovery_transaction(candidate, evaluated_at="2026-07-12T03:05:00Z")
        results.append(
            {
                "case_id": case_id,
                "expected_error": expected,
                "actual_error": actual,
                "detected": actual == expected,
            }
        )

    expect(
        "backup-manifest-tampered",
        "backup_manifest_digest_mismatch",
        lambda item: item["backup_manifest"].__setitem__("last_sequence", 99),
    )

    def corrupt_ciphertext(item: dict) -> None:
        value = item["backup_ciphertext_hex"]
        item["backup_ciphertext_hex"] = ("00" if value[:2] != "00" else "ff") + value[2:]

    expect("backup-ciphertext-tampered", "backup_ciphertext_digest_mismatch", corrupt_ciphertext)

    def cross_instance_backup(item: dict) -> None:
        encryption = item["backup_encryption"]
        encryption["instance_id"] = "inst_01HSIM_OTHER000000000001"
        encryption["encryption_digest"] = compute_backup_encryption_digest(encryption)

    expect("backup-cross-instance", "recovery_instance_id_mismatch", cross_instance_backup)

    def detach_encryption(item: dict) -> None:
        encryption = item["backup_encryption"]
        encryption["manifest_digest"] = "sha256:" + "99" * 32
        encryption["encryption_digest"] = compute_backup_encryption_digest(encryption)

    expect("encryption-detached-from-manifest", "backup_encryption_manifest_mismatch", detach_encryption)

    def leave_backup_partial(item: dict) -> None:
        commit = item["backup_commit"]
        commit["state"] = "prepared"
        commit["commit_digest"] = compute_backup_commit_digest(commit)

    expect("backup-not-committed", "backup_not_committed", leave_backup_partial)

    expect(
        "backup-checkpoint-signature-forged",
        "backup_checkpoint_signature_invalid",
        lambda item: item["backup_checkpoint"]["signature"].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    expect(
        "backup-commit-signature-forged",
        "backup_commit_signature_invalid",
        lambda item: item["backup_commit"]["signature"].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    expect(
        "recovery-policy-tampered",
        "recovery_policy_digest_mismatch",
        lambda item: item["recovery_policy"].__setitem__("fallback_wait_seconds", 1),
    )

    def forge_policy_witness(item: dict) -> None:
        witness = item["recovery_policy"]["guardian_witness"]
        witness["signature_value"] = "00" * 64

    expect(
        "recovery-policy-witness-forged",
        "recovery_policy_guardian_witness_invalid",
        forge_policy_witness,
    )

    def expire_authorization(item: dict) -> None:
        authorization = item["recovery_authorization"]
        authorization["expires_at"] = "2026-07-12T03:04:00Z"
        authorization["authorization_digest"] = compute_recovery_authorization_digest(authorization)

    expect("recovery-authorization-expired", "recovery_authorization_expired", expire_authorization)

    def invert_authorization_window(item: dict) -> None:
        authorization = item["recovery_authorization"]
        authorization["not_before"] = "2026-07-12T03:31:00Z"
        authorization["expires_at"] = "2026-07-12T03:01:00Z"
        authorization["authorization_digest"] = compute_recovery_authorization_digest(authorization)

    expect(
        "recovery-authorization-invalid-window",
        "recovery_authorization_time_window_invalid",
        invert_authorization_window,
    )

    def change_authorized_destination(item: dict) -> None:
        authorization = item["recovery_authorization"]
        authorization["new_body_id"] = "body_01HSIM_UNAUTHORIZED000001"
        authorization["authorization_digest"] = compute_recovery_authorization_digest(authorization)

    expect("recovery-destination-not-authorized", "recovery_authorization_scope_mismatch", change_authorized_destination)

    def skip_fallback_wait(item: dict) -> None:
        authorization = item["recovery_authorization"]
        authorization["not_before"] = "2026-07-12T02:01:01Z"
        authorization["authorization_digest"] = compute_recovery_authorization_digest(authorization)

    expect(
        "recovery-fallback-wait-skipped",
        "recovery_fallback_wait_not_satisfied",
        skip_fallback_wait,
    )

    expect(
        "recovery-fallback-threshold-not-met",
        "recovery_fallback_threshold_not_met",
        lambda item: item["recovery_authorization"].__setitem__(
            "approvals", item["recovery_authorization"]["approvals"][:1]
        ),
    )

    def duplicate_approval(item: dict) -> None:
        approvals = item["recovery_authorization"]["approvals"]
        approvals[1] = deepcopy(approvals[0])

    expect(
        "recovery-duplicate-approval",
        "recovery_authorization_duplicate_approval",
        duplicate_approval,
    )

    expect(
        "recovery-approval-forged",
        "recovery_authorization_approval_invalid",
        lambda item: item["recovery_authorization"]["approvals"][0].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    expect(
        "recovery-destination-possession-forged",
        "recovery_destination_possession_signature_invalid",
        lambda item: item["destination_possession_signature"].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    expect(
        "recovery-record-signature-forged",
        "recovery_record_signature_invalid",
        lambda item: item["recovery_record"]["signature"].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    expect(
        "recovery-finalization-ack-forged",
        "recovery_finalization_acknowledgement_invalid",
        lambda item: item["recovery_finalization"]["destination_acknowledgement"].__setitem__(
            "signature_value", "00" * 64
        ),
    )

    def detach_policy(item: dict) -> None:
        authorization = item["recovery_authorization"]
        authorization["recovery_policy_digest"] = "sha256:" + "ab" * 32
        authorization["authorization_digest"] = compute_recovery_authorization_digest(authorization)

    expect(
        "recovery-authorization-detached-policy",
        "recovery_authorization_policy_mismatch",
        detach_policy,
    )

    expect(
        "recovery-record-cross-instance",
        "recovery_instance_id_mismatch",
        lambda item: item["recovery_record"].__setitem__(
            "instance_id", "inst_01HSIM_OTHER000000000001"
        ),
    )

    def hide_gap(item: dict) -> None:
        record = item["recovery_record"]
        record["continuity_status"] = "complete"
        record["continuity_gap_ref"] = None
        record["recovery_digest"] = compute_recovery_record_digest(record)
        item["continuity_gap"] = None

    expect("recovery-hides-memory-gap", "undeclared_memory_gap", hide_gap)

    def alter_gap_range(item: dict) -> None:
        gap = item["continuity_gap"]
        gap["first_missing_sequence"] = 3
        gap["gap_digest"] = compute_continuity_gap_digest(gap)

    expect("recovery-gap-range-invalid", "continuity_gap_range_invalid", alter_gap_range)

    def keep_previous_body(item: dict) -> None:
        revocation = item["previous_body_revocation"]
        revocation["body_id"] = "body_01HSIM_OTHER000000000001"
        revocation["revocation_digest"] = compute_body_revocation_digest(revocation)

    expect("previous-body-not-revoked", "previous_body_not_revoked", keep_previous_body)

    def create_second_writer(item: dict) -> None:
        registry = item["body_registry_after"]
        for body in registry["bodies"]:
            if body["body_id"] == item["recovery_record"]["previous_body_id"]:
                body["status"] = "active_writer"

    expect("recovery-creates-second-writer", "recovery_final_registry_authority_invalid", create_second_writer)

    expect(
        "recovery-final-registry-content-tampered",
        "recovery_final_registry_digest_mismatch",
        lambda item: item["body_registry_after"]["bodies"][-1].__setitem__(
            "platform_profile", "tampered-platform"
        ),
    )

    def skip_recovery_sequence(item: dict) -> None:
        item["recovery_event"]["sequence"] = 6

    expect("recovery-event-wrong-sequence", "recovery_event_continuity_invalid", skip_recovery_sequence)

    passed = all(result["detected"] for result in results)
    print(
        json.dumps(
            {
                "suite": "genesis.backup_recovery.negative.v0.1",
                "total": len(results),
                "all_detected": passed,
                "cases": results,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    for result in results:
        mark = "ok" if result["detected"] else "FAIL"
        print(
            f"{mark}: {result['case_id']} — esperado={result['expected_error']} actual={result['actual_error']}",
            file=sys.stderr,
        )
    if not passed:
        return 1
    print(f"\n{len(results)} CASOS NEGATIVOS BACKUP/RECOVERY: todos detectados", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

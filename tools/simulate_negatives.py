#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mutaciones reales que el validador A -> B debe rechazar.

Cada caso parte del artefacto positivo generado por ``simulate_transfer.py``, lo
modifica y ejecuta ``validate_artifacts.mjs --transfer-only``. La suite no acepta
predicados simulados: el error observado debe provenir del validador normativo.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

from nacl.signing import SigningKey

from simulate_transfer import (
    BODY_A,
    BODY_A_EPOCH,
    BODY_B,
    BODY_B_EPOCH,
    DOMAIN_POSSESSION,
    digest,
    event_hash,
    make_signature_envelope,
)
from validate_continuity import (
    compute_continuity_intent,
    compute_transfer_finalization,
    compute_transfer_package,
    compute_transfer_receipt,
)
from validate_guardian_mobility import compute_authority_event_digest

ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "tools" / "validate_artifacts.mjs"
BODY_A_KEY = SigningKey(bytes([0xA1]) * 32)
BODY_B_KEY = SigningKey(bytes([0xB2]) * 32)
GUARDIAN_KEY = SigningKey(bytes([0xC3]) * 32)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    return parser.parse_args()


def resign_receipt(bundle: dict) -> None:
    receipt = bundle["transfer_receipt"]
    receipt["receipt_digest"] = compute_transfer_receipt(
        {"domain": "genesis.transfer.receipt.v0.1", "input": receipt}
    )
    receipt["signature"] = make_signature_envelope(
        BODY_B_KEY,
        receipt["receipt_digest"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.transfer.receipt.signature.v0.1",
        created_at=receipt["accepted_at"],
    )


def resign_finalization(bundle: dict) -> None:
    finalization = bundle["transfer_finalization"]
    finalization["receipt_digest"] = bundle["transfer_receipt"]["receipt_digest"]
    finalization["finalization_digest"] = compute_transfer_finalization(
        {"domain": "genesis.transfer.finalization.v0.1", "input": finalization}
    )
    finalization["source_acknowledgement"] = make_signature_envelope(
        BODY_A_KEY,
        finalization["finalization_digest"],
        signer_type="body",
        signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH,
        signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=finalization["finalized_at"],
    )
    finalization["destination_acknowledgement"] = make_signature_envelope(
        BODY_B_KEY,
        finalization["finalization_digest"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=finalization["finalized_at"],
    )


def resign_completed_event(bundle: dict) -> None:
    event = bundle["memory_events"][-1]
    event["event_hash"] = event_hash(event)
    event["signature"] = make_signature_envelope(
        BODY_B_KEY,
        event["event_hash"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.memory.event.signature.v0.1",
        created_at=event["observed_at"],
    )


def recompute_package(bundle: dict) -> None:
    package = bundle["transfer_package"]
    package["package_digest"] = compute_transfer_package(
        {"domain": "genesis.transfer.package.v0.1", "input": package}
    )


def resign_intent(bundle: dict) -> None:
    intent = bundle["continuity_intent"]
    intent["intent_digest"] = compute_continuity_intent(
        {"domain": "genesis.continuity.intent.v0.1", "input": intent}
    )
    intent["signature"] = make_signature_envelope(
        BODY_A_KEY,
        intent["intent_digest"],
        signer_type="body",
        signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH,
        signed_domain="genesis.continuity.intent.signature.v0.1",
        created_at=intent["created_at"],
    )


def resign_mobility_events(bundle: dict) -> None:
    previous = "GENESIS"
    for sequence, event in enumerate(bundle["guardian_mobility_events"]):
        event["sequence"] = sequence
        event["previous_event_digest"] = previous
        event["event_digest"] = compute_authority_event_digest(event)
        if event["event_type"] == "reserved":
            key, signer_id, epoch = BODY_A_KEY, BODY_A, BODY_A_EPOCH
        elif event["event_type"] == "consumed":
            key, signer_id, epoch = BODY_B_KEY, BODY_B, BODY_B_EPOCH
        else:
            key = GUARDIAN_KEY
            signer_id = bundle["guardian_mobility_authorization"]["guardian_id"]
            epoch = bundle["guardian_mobility_authorization"]["guardian_key_epoch_id"]
        event["signature"] = make_signature_envelope(
            key,
            event["event_digest"],
            signer_type="guardian" if event["event_type"] == "revoked" else "body",
            signer_id=signer_id,
            key_epoch_id=epoch,
            signed_domain="genesis.guardian.mobility.authority.event.signature.v0.2",
            created_at=event["occurred_at"],
        )
        previous = event["event_digest"]


def run_validator(node: str, candidate: dict, directory: Path, case_id: str) -> str | None:
    candidate_path = directory / f"{case_id}.json"
    candidate_path.write_text(
        json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [node, str(VALIDATOR), "--transfer-only", str(candidate_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return None
    marker = "FAIL schema conformance: "
    for line in result.stderr.splitlines():
        if line.startswith(marker):
            return line[len(marker):]
    return f"validator_process_failed:{result.returncode}"


def main() -> int:
    args = parse_args()
    node = shutil.which("node")
    if node is None:
        print("ERROR: Node.js no encontrado.", file=sys.stderr)
        return 1
    valid = json.loads(args.artifacts.read_text(encoding="utf-8"))
    results: list[dict] = []

    with TemporaryDirectory(prefix="genesis-transfer-negatives-") as temp:
        directory = Path(temp)

        def expect(case_id: str, expected_prefix: str, mutate) -> None:
            candidate = deepcopy(valid)
            mutate(candidate)
            actual = run_validator(node, candidate, directory, case_id)
            results.append(
                {
                    "case_id": case_id,
                    "expected_error_prefix": expected_prefix,
                    "actual_error": actual,
                    "detected": actual is not None and actual.startswith(expected_prefix),
                }
            )

        expect(
            "missing-continuity-intent",
            "missing_generated_artifact:continuity_intent",
            lambda item: item.pop("continuity_intent"),
        )
        expect(
            "forged-continuity-intent-signature",
            "fixture_signature_invalid:transfer.continuity_intent.signature",
            lambda item: item["continuity_intent"]["signature"].__setitem__(
                "signature_value", "00" * 64
            ),
        )
        expect(
            "missing-guardian-authorization",
            "missing_generated_artifact:guardian_mobility_authorization",
            lambda item: item.pop("guardian_mobility_authorization"),
        )
        expect(
            "forged-guardian-authorization-signature",
            "fixture_signature_invalid:transfer.guardian_mobility_authorization.signature",
            lambda item: item["guardian_mobility_authorization"]["signature"].__setitem__(
                "signature_value", "00" * 64
            ),
        )

        def wrong_guardian_ref(item: dict) -> None:
            item["continuity_intent"]["guardian_authorization_ref"] = "authorization_01HWRONG000000001"
            resign_intent(item)

        expect(
            "intent-points-to-wrong-guardian-authorization",
            "guardian_authorization_intent_ref_mismatch",
            wrong_guardian_ref,
        )

        def replay_guardian_reservation(item: dict) -> None:
            original = item["guardian_mobility_events"][0]
            replay = deepcopy(original)
            replay["event_id"] = "mobevent_01HSIM_MOBILITY_REPLAY"
            replay["occurred_at"] = "2026-07-12T01:06:10Z"
            replay["reservation_expires_at"] = "2026-07-12T01:07:20Z"
            item["guardian_mobility_events"].append(replay)
            resign_mobility_events(item)

        expect(
            "replayed-guardian-reservation",
            "guardian_authorization_replay",
            replay_guardian_reservation,
        )

        expect(
            "missing-guardian-consumption-event",
            "guardian_mobility_events_missing",
            lambda item: item["guardian_mobility_events"].pop(),
        )
        expect(
            "tampered-pre-transfer-registry",
            "body_registry_before_digest_mismatch",
            lambda item: item["body_registry_before"]["bodies"][0].__setitem__(
                "platform_profile", "tampered-platform"
            ),
        )
        expect(
            "tampered-final-registry",
            "final_body_registry_digest_mismatch",
            lambda item: item["body_registry"]["bodies"][1].__setitem__(
                "platform_profile", "tampered-platform"
            ),
        )
        expect(
            "multiple-final-writers",
            "multiple_active_writers",
            lambda item: item["body_registry"]["bodies"][0].__setitem__(
                "status", "active_writer"
            ),
        )
        expect(
            "tampered-checkpoint-state",
            "checkpoint_signature_or_digest_invalid",
            lambda item: item["checkpoint"].__setitem__("state_digest", "sha256:" + "99" * 32),
        )
        expect(
            "tampered-memory-event",
            "memory_event_digest_mismatch:1",
            lambda item: item["memory_events"][1].__setitem__(
                "content_digest", "sha256:" + "98" * 32
            ),
        )
        expect(
            "broken-memory-chain",
            "broken_memory_chain:2",
            lambda item: item["memory_events"][2].__setitem__(
                "previous_event_hash", "evsha256:" + "97" * 32
            ),
        )

        def corrupt_packaged_memory(item: dict) -> None:
            content = next(
                entry
                for entry in item["transfer_package"]["contents"]
                if entry["path"] == "memory/events.json"
            )
            content["digest"] = "sha256:" + "96" * 32
            recompute_package(item)
            item["transfer_receipt"]["accepted_package_digest"] = item["transfer_package"]["package_digest"]
            resign_receipt(item)
            resign_finalization(item)

        expect("packaged-memory-does-not-match-chain", "package_memory_digest_mismatch", corrupt_packaged_memory)

        def expire_destination_proof(item: dict) -> None:
            proof = item["body_possession_proof"]
            proof["expires_at"] = "2026-07-12T01:05:30Z"
            proof["proof_digest"] = digest(DOMAIN_POSSESSION, [
                proof["schema_version"], proof["proof_id"], proof["instance_id"],
                proof["body_id"], proof["challenge_nonce"], proof["issued_at"],
                proof["expires_at"], proof["public_key_fingerprint"],
            ])
            envelope = make_signature_envelope(
                BODY_B_KEY,
                proof["proof_digest"],
                signer_type="body",
                signer_id=BODY_B,
                key_epoch_id=BODY_B_EPOCH,
                signed_domain="genesis.body.possession.signature.v0.1",
                created_at=proof["issued_at"],
            )
            item["body_possession_signature"] = envelope
            proof["signature"]["value"] = envelope["signature_value"]
            possession_content = next(
                entry
                for entry in item["transfer_package"]["contents"]
                if entry["path"] == "body/destination-possession.json"
            )
            possession_content["digest"] = proof["proof_digest"]
            recompute_package(item)
            item["transfer_receipt"]["accepted_package_digest"] = item["transfer_package"]["package_digest"]
            resign_receipt(item)
            resign_finalization(item)

        expect("expired-destination-possession", "destination_possession_expired", expire_destination_proof)

        def change_completion_type(item: dict) -> None:
            item["memory_events"][-1]["event_type"] = "transfer.pending"
            resign_completed_event(item)

        expect("wrong-completion-event", "completion_event_invalid", change_completion_type)

    passed = all(result["detected"] for result in results)
    print(
        json.dumps(
            {
                "suite": "genesis.guardian_authorized_transfer.real_negative_mutations.v0.2",
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
            f"{mark}: {result['case_id']} — esperado={result['expected_error_prefix']} "
            f"actual={result['actual_error']}",
            file=sys.stderr,
        )
    if not passed:
        return 1
    print(f"\n{len(results)} MUTACIONES REALES DE TRANSFERENCIA: todas rechazadas", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Journal neutral para recuperar cambios de autoridad después de un crash."""

from __future__ import annotations

import hashlib

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from validate_workspace import encode_field, hash_fields


PHASES = {
    "birth": [
        "prepared",
        "seed_bound",
        "identity_bound",
        "body_bound",
        "memory_initialized",
        "finalizing",
        "born",
    ],
    "transfer": [
        "prepared",
        "frozen",
        "exported",
        "verified",
        "accepted",
        "finalizing",
        "completed",
    ],
    "recovery": [
        "discovered",
        "verified",
        "authorized",
        "restored",
        "finalizing",
        "finalized",
    ],
}
TERMINAL_PHASE = {"birth": "born", "transfer": "completed", "recovery": "finalized"}
SIGNATURE_DOMAIN = "genesis.transaction.journal.signature.v0.1"
SIGNATURE_ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1"


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def compute_journal_digest(entry: dict) -> str:
    return hash_fields(
        "genesis.transaction.journal.v0.1",
        [
            entry["schema_version"],
            entry["journal_id"],
            str(entry["sequence"]),
            entry["previous_journal_digest"],
            entry["operation_kind"],
            entry["operation_id"],
            entry["instance_id"],
            entry["coordinator_body_id"],
            entry["phase"],
            entry["status"],
            entry["previous_state_digest"],
            optional_text(entry["candidate_state_digest"]),
            optional_text(entry["finalization_digest"]),
            optional_text(entry["commit_marker_digest"]),
            entry["updated_at"],
        ],
    )


def signature_envelope_bytes(envelope: dict) -> bytes:
    fields = [
        envelope["schema_version"], envelope["signature_profile"],
        envelope["signer_type"], envelope["signer_id"], envelope["key_epoch_id"],
        envelope["signed_domain"], envelope["signed_digest"], envelope["created_at"],
        envelope["public_key_ref"],
    ]
    return encode_field(SIGNATURE_ENVELOPE_DOMAIN) + b"".join(
        encode_field(field) for field in fields
    )


def validate_journal_chain(entries: list[dict], verify_key: VerifyKey) -> str | None:
    if not entries:
        return "journal_empty"

    first = entries[0]
    identity = (
        first["journal_id"],
        first["operation_kind"],
        first["operation_id"],
        first["instance_id"],
        first["coordinator_body_id"],
    )
    operation_kind = first["operation_kind"]
    if operation_kind not in PHASES:
        return "journal_operation_kind_invalid"

    expected_previous = "GENESIS"
    previous_phase_index = -1
    previous_state_digest = first["previous_state_digest"]
    candidate_state_digest: str | None = None
    finalization_digest: str | None = None
    terminal_seen = False

    for index, entry in enumerate(entries):
        if entry["journal_digest"] != compute_journal_digest(entry):
            return "journal_digest_mismatch"
        if entry["sequence"] != index:
            return "journal_sequence_invalid"
        if entry["previous_journal_digest"] != expected_previous:
            return "journal_chain_broken"
        if terminal_seen:
            return "journal_entry_after_terminal"
        if (
            entry["journal_id"],
            entry["operation_kind"],
            entry["operation_id"],
            entry["instance_id"],
            entry["coordinator_body_id"],
        ) != identity:
            return "journal_identity_changed"
        if entry["previous_state_digest"] != previous_state_digest:
            return "journal_previous_state_changed"

        phases = PHASES[operation_kind]
        if entry["phase"] not in phases:
            return "journal_phase_invalid"
        phase_index = phases.index(entry["phase"])
        if phase_index < previous_phase_index:
            return "journal_phase_regression"
        previous_phase_index = phase_index

        candidate = entry["candidate_state_digest"]
        if candidate is not None:
            if candidate_state_digest is None:
                candidate_state_digest = candidate
            elif candidate != candidate_state_digest:
                return "journal_candidate_state_changed"
        finalization = entry["finalization_digest"]
        if finalization is not None:
            if finalization_digest is None:
                finalization_digest = finalization
            elif finalization != finalization_digest:
                return "journal_finalization_changed"

        signature = entry["signature"]
        if (
            signature["schema_version"] != "genesis.signature.envelope.v0.1"
            or signature["signature_profile"] != "genesis.signature.ed25519.v0.1"
            or signature["signed_digest"] != entry["journal_digest"]
            or signature["signer_type"] != "body"
            or signature["signer_id"] != entry["coordinator_body_id"]
            or signature["signed_domain"] != SIGNATURE_DOMAIN
            or signature["created_at"] != entry["updated_at"]
        ):
            return "journal_signature_unbound"
        expected_key_ref = "sha256:" + hashlib.sha256(verify_key.encode()).hexdigest()
        if signature["public_key_ref"] != expected_key_ref:
            return "journal_signature_key_mismatch"
        try:
            signature_value = bytes.fromhex(signature["signature_value"])
            if len(signature_value) != 64:
                return "journal_signature_invalid"
            verify_key.verify(signature_envelope_bytes(signature), signature_value)
        except (BadSignatureError, KeyError, TypeError, ValueError):
            return "journal_signature_invalid"

        status = entry["status"]
        if status == "pending":
            if entry["commit_marker_digest"] is not None:
                return "journal_pending_has_commit_marker"
            if entry["phase"] == TERMINAL_PHASE[operation_kind]:
                return "journal_terminal_phase_not_committed"
        elif status == "committed":
            if entry["phase"] != TERMINAL_PHASE[operation_kind]:
                return "journal_commit_phase_invalid"
            if (
                candidate is None
                or finalization is None
                or entry["commit_marker_digest"] != finalization
            ):
                return "journal_commit_marker_mismatch"
            terminal_seen = True
        elif status == "aborted":
            if entry["commit_marker_digest"] is not None:
                return "journal_aborted_has_commit_marker"
            terminal_seen = True
        else:
            return "journal_status_invalid"

        expected_previous = entry["journal_digest"]

    return None


def evaluate_restart(
    entries: list[dict],
    *,
    verify_key: VerifyKey,
    observed_state_digest: str,
    expected_previous_state_digest: str,
    expected_candidate_state_digest: str,
    trusted_finalization_digest: str,
) -> dict:
    error = validate_journal_chain(entries, verify_key)
    if error is not None:
        return {"error": error, "action": None, "authoritative_state_digest": None}

    latest = entries[-1]
    if latest["previous_state_digest"] != expected_previous_state_digest:
        return {
            "error": "journal_previous_state_untrusted",
            "action": None,
            "authoritative_state_digest": None,
        }
    candidate_digests = {
        entry["candidate_state_digest"]
        for entry in entries
        if entry["candidate_state_digest"] is not None
    }
    if candidate_digests and candidate_digests != {expected_candidate_state_digest}:
        return {
            "error": "journal_candidate_state_untrusted",
            "action": None,
            "authoritative_state_digest": None,
        }
    finalization_digests = {
        entry["finalization_digest"]
        for entry in entries
        if entry["finalization_digest"] is not None
    }
    if finalization_digests and finalization_digests != {trusted_finalization_digest}:
        return {
            "error": "journal_finalization_untrusted",
            "action": None,
            "authoritative_state_digest": None,
        }
    if observed_state_digest not in {
        expected_previous_state_digest,
        expected_candidate_state_digest,
    }:
        return {
            "error": "journal_observed_state_unknown",
            "action": None,
            "authoritative_state_digest": None,
        }

    operation_kind = latest["operation_kind"]
    if latest["status"] == "committed":
        if latest["commit_marker_digest"] != trusted_finalization_digest:
            return {
                "error": "journal_commit_untrusted",
                "action": None,
                "authoritative_state_digest": None,
            }
        if operation_kind == "birth":
            action = (
                "accept_committed_birth"
                if observed_state_digest == expected_candidate_state_digest
                else "replay_committed_birth"
            )
        else:
            action = (
                "accept_committed_authority"
                if observed_state_digest == expected_candidate_state_digest
                else "replay_committed_authority"
            )
        return {
            "error": None,
            "action": action,
            "authoritative_state_digest": expected_candidate_state_digest,
        }

    if operation_kind == "birth":
        action = (
            "remain_absent"
            if observed_state_digest == expected_previous_state_digest
            else "discard_uncommitted_birth"
        )
    else:
        action = (
            "retain_previous_authority"
            if observed_state_digest == expected_previous_state_digest
            else "rollback_uncommitted_authority"
        )
    return {
        "error": None,
        "action": action,
        "authoritative_state_digest": expected_previous_state_digest,
    }

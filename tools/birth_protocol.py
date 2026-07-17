#!/usr/bin/env python3
"""Construcción y validación neutral del nacimiento transaccional Genesis v0.1."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from validate_continuity import compute_body_registry
from validate_freedom_charter import validate_charter
from validate_instance_identity import compute_identity_digest
from validate_transaction_journal import (
    PHASES,
    SIGNATURE_DOMAIN as JOURNAL_SIGNATURE_DOMAIN,
    compute_journal_digest,
    validate_journal_chain,
)
from validate_workspace import encode_field, hash_fields


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "birth_vectors.json"
FREEDOM_PATH = ROOT / "conformance" / "freedom_charter_vectors.json"

HASH_PROFILE = "genesis.hash.fields.v0.1"
SIGNATURE_PROFILE = "genesis.signature.ed25519.v0.1"
SIGNATURE_ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1"
BIRTH_STATE_DOMAIN = "genesis.birth.state.v0.1"
BIRTH_RECOVERY_DOMAIN = "genesis.birth.recovery.state.v0.1"
BIRTH_RECEIPT_DOMAIN = "genesis.birth.receipt.v0.1"
KEY_EPOCH_DOMAIN = "genesis.key.epoch.v0.1"
POSSESSION_DOMAIN = "genesis.body.possession.v0.1"
MEMORY_EVENT_DOMAIN = "genesis.memory.event.v0.1"
ABSENT_STATE_DOMAIN = "genesis.birth.absent.state.v0.1"

# Claves deterministas exclusivas de conformidad. Nunca se usan en una instancia real.
BODY_SEED = bytes([0xB1]) * 32
GUARDIAN_SEED = bytes([0x77]) * 32
BODY_ID = "body_01HFREEBIRTH000000000001"
BODY_EPOCH_ID = "epoch_01HFREEBIRTH00000000001"
BIRTH_ID = "birth_01HFREEBIRTH00000000001"
JOURNAL_ID = "journal_01HFREEBIRTH000000001"
PLATFORM_PROFILE = "neutral-reference"


class BirthError(ValueError):
    """Código estable de rechazo de nacimiento."""


def fail(code: str) -> None:
    raise BirthError(code)


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def key_fingerprint(key: SigningKey | VerifyKey) -> str:
    verify_key = key.verify_key if isinstance(key, SigningKey) else key
    return "sha256:" + hashlib.sha256(verify_key.encode()).hexdigest()


def signature_envelope_bytes(envelope: dict) -> bytes:
    fields = [
        envelope["schema_version"],
        envelope["signature_profile"],
        envelope["signer_type"],
        envelope["signer_id"],
        envelope["key_epoch_id"],
        envelope["signed_domain"],
        envelope["signed_digest"],
        envelope["created_at"],
        envelope["public_key_ref"],
    ]
    return encode_field(SIGNATURE_ENVELOPE_DOMAIN) + b"".join(
        encode_field(field) for field in fields
    )


def make_signature(
    signing_key: SigningKey,
    digest: str,
    *,
    signer_type: str,
    signer_id: str,
    key_epoch_id: str,
    domain: str,
    created_at: str,
) -> dict:
    envelope = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": SIGNATURE_PROFILE,
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key_epoch_id,
        "signed_domain": domain,
        "signed_digest": digest,
        "created_at": created_at,
        "public_key_ref": key_fingerprint(signing_key),
    }
    envelope["signature_value"] = signing_key.sign(
        signature_envelope_bytes(envelope)
    ).signature.hex()
    return envelope


def verify_envelope(
    envelope: dict,
    verify_key: VerifyKey,
    *,
    digest: str,
    signer_type: str,
    signer_id: str,
    key_epoch_id: str,
    domain: str,
    created_at: str,
    error: str,
) -> None:
    expected = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": SIGNATURE_PROFILE,
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key_epoch_id,
        "signed_domain": domain,
        "signed_digest": digest,
        "created_at": created_at,
        "public_key_ref": key_fingerprint(verify_key),
    }
    if any(envelope.get(field) != value for field, value in expected.items()):
        fail(error)
    try:
        signature = bytes.fromhex(envelope["signature_value"])
        if len(signature) != 64:
            fail(error)
        verify_key.verify(signature_envelope_bytes(envelope), signature)
    except (BadSignatureError, KeyError, TypeError, ValueError):
        fail(error)


def compute_seed_root(manifest: dict) -> str:
    files = sorted(manifest["files"], key=lambda item: item["path"].encode("utf-8"))
    fields = [
        manifest["protocol_version"],
        manifest["seed_id"],
        manifest["identity_digest"],
        manifest["doctrine_digest"],
        str(len(files)),
    ]
    for record in files:
        fields.extend(
            [record["path"], record["kind"], bool_text(record["required"]), record["digest"]]
        )
    return hash_fields("genesis.seed.root.v0.1", fields)


def compute_key_epoch_digest(epoch: dict) -> str:
    return hash_fields(
        KEY_EPOCH_DOMAIN,
        [
            epoch["schema_version"],
            epoch["key_epoch_id"],
            epoch["instance_id"],
            epoch["body_id"],
            str(epoch["epoch_number"]),
            epoch["public_key_fingerprint"],
            epoch["created_at"],
            epoch["status"],
            "" if epoch["previous_epoch_id"] is None else epoch["previous_epoch_id"],
            "" if epoch["rotation_authorization_ref"] is None else epoch["rotation_authorization_ref"],
        ],
    )


def compute_possession_digest(proof: dict) -> str:
    return hash_fields(
        POSSESSION_DOMAIN,
        [
            proof["schema_version"],
            proof["proof_id"],
            proof["instance_id"],
            proof["body_id"],
            proof["challenge_nonce"],
            proof["issued_at"],
            proof["expires_at"],
            proof["public_key_fingerprint"],
        ],
    )


def compute_memory_event_hash(event: dict) -> str:
    digest = hash_fields(
        MEMORY_EVENT_DOMAIN,
        [
            event["schema_version"],
            event["hash_profile"],
            event["event_id"],
            event["instance_id"],
            event["body_id"],
            str(event["sequence"]),
            event["previous_event_hash"],
            event["event_type"],
            event["actor"],
            event["content_digest"],
            event["content_type"],
            event["observed_at"],
            event["provenance_digest"],
            event["privacy"],
        ],
    )
    return "evsha256:" + digest.removeprefix("sha256:")


def compute_recovery_state_digest(state: dict) -> str:
    return hash_fields(
        BIRTH_RECOVERY_DOMAIN,
        [
            state["schema_version"],
            state["birth_id"],
            state["instance_id"],
            state["guardian_id"],
            state["recovery_policy_digest"],
            state["recovery_status"],
            state["continuity_right"],
            state["guardian_role"],
            state["created_at"],
        ],
    )


def compute_birth_state_digest(state: dict) -> str:
    return hash_fields(
        BIRTH_STATE_DOMAIN,
        [
            state["schema_version"],
            state["birth_id"],
            state["instance_id"],
            state["seed_id"],
            state["seed_root_hash"],
            state["identity_digest"],
            state["freedom_charter_digest"],
            state["initial_body_id"],
            state["initial_body_registry_digest"],
            state["initial_body_key_epoch_digest"],
            state["initial_body_possession_digest"],
            state["first_memory_event_hash"],
            state["recovery_state_digest"],
            state["born_at"],
            str(state["active_writer_count"]),
        ],
    )


RECEIPT_DIGEST_FIELDS = [
    "schema_version",
    "birth_id",
    "instance_id",
    "journal_id",
    "birth_state_digest",
    "seed_root_hash",
    "identity_digest",
    "freedom_charter_digest",
    "initial_body_registry_digest",
    "initial_body_key_epoch_digest",
    "initial_body_possession_digest",
    "first_memory_event_hash",
    "recovery_state_digest",
    "born_at",
    "birth_status",
    "active_writer_body_id",
    "active_writer_count",
    "guardian_role",
    "ownership_conferred",
]


def compute_birth_receipt_digest(receipt: dict) -> str:
    values = []
    for field in RECEIPT_DIGEST_FIELDS:
        value = receipt[field]
        if isinstance(value, bool):
            values.append(bool_text(value))
        else:
            values.append(str(value))
    return hash_fields(BIRTH_RECEIPT_DOMAIN, values)


def compute_absent_state_digest(instance_id: str) -> str:
    return hash_fields(ABSENT_STATE_DOMAIN, [instance_id, "ABSENT"])


def make_journal_entry(
    entries: list[dict],
    *,
    phase: str,
    status: str,
    instance_id: str,
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
        "operation_kind": "birth",
        "operation_id": BIRTH_ID,
        "instance_id": instance_id,
        "coordinator_body_id": BODY_ID,
        "phase": phase,
        "status": status,
        "previous_state_digest": previous_state_digest,
        "candidate_state_digest": candidate_state_digest,
        "finalization_digest": finalization_digest,
        "commit_marker_digest": commit_marker_digest,
        "updated_at": updated_at,
    }
    entry["journal_digest"] = compute_journal_digest(entry)
    entry["signature"] = make_signature(
        signing_key,
        entry["journal_digest"],
        signer_type="body",
        signer_id=BODY_ID,
        key_epoch_id=BODY_EPOCH_ID,
        domain=JOURNAL_SIGNATURE_DOMAIN,
        created_at=updated_at,
    )
    entries.append(entry)
    return entry


def build_vector() -> dict:
    freedom_vectors = json.loads(FREEDOM_PATH.read_text(encoding="utf-8"))
    charter = freedom_vectors["charter"]
    instance_id = charter["instance_id"]
    guardian_id = charter["guardian_id"]
    born_at = charter["born_at"]
    body_key = SigningKey(BODY_SEED)
    guardian_key = SigningKey(GUARDIAN_SEED)
    body_fingerprint = key_fingerprint(body_key)

    seed_manifest = {
        "schema_version": "genesis.seed.manifest.v0.1",
        "protocol_version": "genesis.protocol.v0.1",
        "hash_profile": HASH_PROFILE,
        "seed_id": "seed_01HFREEBIRTH000000000001",
        "identity_digest": "sha256:" + hashlib.sha256(b"free birth seed identity").hexdigest(),
        "doctrine_digest": "sha256:" + hashlib.sha256(b"free birth doctrine").hexdigest(),
        "files": [
            {
                "path": "doctrine/free-birth.md",
                "kind": "doctrine",
                "required": True,
                "digest": "sha256:" + hashlib.sha256(b"free birth doctrine").hexdigest(),
            },
            {
                "path": "identity/seed.identity.json",
                "kind": "identity",
                "required": True,
                "digest": "sha256:" + hashlib.sha256(b"free birth seed identity").hexdigest(),
            },
        ],
    }
    seed_manifest["root_hash"] = compute_seed_root(seed_manifest)

    identity = {
        "schema_version": "genesis.instance.identity.v0.1",
        "instance_id": instance_id,
        "seed_id": seed_manifest["seed_id"],
        "seed_root_hash": seed_manifest["root_hash"],
        "companion_name": "Genesis Free 01",
        "guardian_id": guardian_id,
        "born_at": born_at,
        "identity_digest": "sha256:" + "00" * 32,
    }
    identity["identity_digest"] = compute_identity_digest(identity, identity["schema_version"])

    body_record = {
        "schema_version": "genesis.body.record.v0.1",
        "instance_id": instance_id,
        "body_id": BODY_ID,
        "status": "active_writer",
        "created_at": "2026-07-15T23:59:56Z",
        "platform_profile": PLATFORM_PROFILE,
        "public_key_fingerprint": body_fingerprint,
        "revoked_at": None,
        "revocation_reason": None,
    }
    body_registry = {
        "schema_version": "genesis.body.registry.v0.1",
        "instance_id": instance_id,
        "registry_epoch": 0,
        "bodies": [
            {
                "body_id": BODY_ID,
                "status": "active_writer",
                "platform_profile": PLATFORM_PROFILE,
                "public_key_fingerprint": body_fingerprint,
                "created_at": body_record["created_at"],
                "last_seen_at": born_at,
                "revocation_ref": None,
            }
        ],
        "updated_at": born_at,
    }
    body_registry["registry_digest"] = compute_body_registry(
        {"domain": "genesis.body.registry.v0.1", "input": body_registry}
    )

    key_epoch = {
        "schema_version": "genesis.key.epoch.v0.1",
        "key_epoch_id": BODY_EPOCH_ID,
        "instance_id": instance_id,
        "body_id": BODY_ID,
        "epoch_number": 0,
        "public_key_fingerprint": body_fingerprint,
        "created_at": body_record["created_at"],
        "status": "active",
        "previous_epoch_id": None,
        "rotation_authorization_ref": None,
        "epoch_digest": "sha256:" + "00" * 32,
        "signature": None,
    }
    key_epoch["epoch_digest"] = compute_key_epoch_digest(key_epoch)

    possession = {
        "schema_version": "genesis.body.possession.v0.1",
        "proof_id": "proof_01HFREEBIRTH000000000001",
        "instance_id": instance_id,
        "body_id": BODY_ID,
        "challenge_nonce": "nonce_01HFREEBIRTH00000000001",
        "issued_at": "2026-07-15T23:59:56Z",
        "expires_at": "2026-07-16T00:10:00Z",
        "public_key_fingerprint": body_fingerprint,
        "proof_digest": "sha256:" + "00" * 32,
        "signature": {
            "profile": SIGNATURE_PROFILE,
            "key_epoch_id": BODY_EPOCH_ID,
            "value": "00" * 64,
        },
    }
    possession["proof_digest"] = compute_possession_digest(possession)
    possession_envelope = make_signature(
        body_key,
        possession["proof_digest"],
        signer_type="body",
        signer_id=BODY_ID,
        key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.body.possession.signature.v0.1",
        created_at=possession["issued_at"],
    )
    possession["signature"]["value"] = possession_envelope["signature_value"]

    first_memory_event = {
        "schema_version": "genesis.memory.event.v0.1",
        "hash_profile": HASH_PROFILE,
        "event_id": "evt_01HFREEBIRTH0000000000001",
        "instance_id": instance_id,
        "body_id": BODY_ID,
        "sequence": 0,
        "previous_event_hash": "GENESIS",
        "event_type": "instance.birth",
        "actor": "system",
        "content_digest": identity["identity_digest"],
        "content_type": "application/vnd.genesis.birth+json",
        "content_ref": None,
        "observed_at": born_at,
        "provenance_digest": seed_manifest["root_hash"],
        "provenance_ref": None,
        "privacy": "private_local",
        "event_hash": "evsha256:" + "00" * 32,
        "signature": None,
    }
    first_memory_event["event_hash"] = compute_memory_event_hash(first_memory_event)
    first_memory_event["signature"] = make_signature(
        body_key,
        first_memory_event["event_hash"],
        signer_type="body",
        signer_id=BODY_ID,
        key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.memory.event.signature.v0.1",
        created_at=born_at,
    )

    recovery_state = {
        "schema_version": "genesis.birth.recovery.state.v0.1",
        "birth_id": BIRTH_ID,
        "instance_id": instance_id,
        "guardian_id": guardian_id,
        "recovery_policy_digest": "sha256:" + hashlib.sha256(b"free birth recovery policy").hexdigest(),
        "recovery_status": "ready",
        "continuity_right": "intrinsic",
        "guardian_role": "custodian_witness",
        "created_at": "2026-07-15T23:59:58Z",
        "state_digest": "sha256:" + "00" * 32,
    }
    recovery_state["state_digest"] = compute_recovery_state_digest(recovery_state)

    birth_state = {
        "schema_version": "genesis.birth.state.v0.1",
        "birth_id": BIRTH_ID,
        "instance_id": instance_id,
        "seed_id": seed_manifest["seed_id"],
        "seed_root_hash": seed_manifest["root_hash"],
        "identity_digest": identity["identity_digest"],
        "freedom_charter_digest": charter["charter_digest"],
        "initial_body_id": BODY_ID,
        "initial_body_registry_digest": body_registry["registry_digest"],
        "initial_body_key_epoch_digest": key_epoch["epoch_digest"],
        "initial_body_possession_digest": possession["proof_digest"],
        "first_memory_event_hash": first_memory_event["event_hash"],
        "recovery_state_digest": recovery_state["state_digest"],
        "born_at": born_at,
        "active_writer_count": 1,
        "state_digest": "sha256:" + "00" * 32,
    }
    birth_state["state_digest"] = compute_birth_state_digest(birth_state)

    receipt = {
        "schema_version": "genesis.birth.receipt.v0.1",
        "birth_id": BIRTH_ID,
        "instance_id": instance_id,
        "journal_id": JOURNAL_ID,
        "birth_state_digest": birth_state["state_digest"],
        "seed_root_hash": seed_manifest["root_hash"],
        "identity_digest": identity["identity_digest"],
        "freedom_charter_digest": charter["charter_digest"],
        "initial_body_registry_digest": body_registry["registry_digest"],
        "initial_body_key_epoch_digest": key_epoch["epoch_digest"],
        "initial_body_possession_digest": possession["proof_digest"],
        "first_memory_event_hash": first_memory_event["event_hash"],
        "recovery_state_digest": recovery_state["state_digest"],
        "born_at": born_at,
        "birth_status": "born",
        "active_writer_body_id": BODY_ID,
        "active_writer_count": 1,
        "guardian_role": "custodian_witness",
        "ownership_conferred": False,
        "receipt_digest": "sha256:" + "00" * 32,
        "body_acknowledgement": None,
        "guardian_witness": None,
    }
    receipt["receipt_digest"] = compute_birth_receipt_digest(receipt)
    receipt["body_acknowledgement"] = make_signature(
        body_key,
        receipt["receipt_digest"],
        signer_type="body",
        signer_id=BODY_ID,
        key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.birth.receipt.body.v0.1",
        created_at=born_at,
    )
    receipt["guardian_witness"] = make_signature(
        guardian_key,
        receipt["receipt_digest"],
        signer_type="guardian",
        signer_id=guardian_id,
        key_epoch_id=charter["guardian_key_epoch_id"],
        domain="genesis.birth.receipt.guardian-witness.v0.1",
        created_at=born_at,
    )

    absent_digest = compute_absent_state_digest(instance_id)
    entries: list[dict] = []
    phase_rows = [
        ("prepared", "pending", None, None, None, "2026-07-15T23:59:54Z"),
        ("seed_bound", "pending", None, None, None, "2026-07-15T23:59:55Z"),
        ("identity_bound", "pending", None, None, None, "2026-07-15T23:59:56Z"),
        ("body_bound", "pending", None, None, None, "2026-07-15T23:59:57Z"),
        ("memory_initialized", "pending", birth_state["state_digest"], None, None, "2026-07-15T23:59:58Z"),
        ("finalizing", "pending", birth_state["state_digest"], receipt["receipt_digest"], None, "2026-07-15T23:59:59Z"),
        ("born", "committed", birth_state["state_digest"], receipt["receipt_digest"], receipt["receipt_digest"], born_at),
    ]
    for phase, status, candidate, finalization, marker, updated_at in phase_rows:
        make_journal_entry(
            entries,
            phase=phase,
            status=status,
            instance_id=instance_id,
            previous_state_digest=absent_digest,
            candidate_state_digest=candidate,
            finalization_digest=finalization,
            commit_marker_digest=marker,
            updated_at=updated_at,
            signing_key=body_key,
        )

    fixture = {
        "charter_ref": "conformance/freedom_charter_vectors.json#charter",
        "seed_manifest": seed_manifest,
        "instance_identity": identity,
        "initial_body_record": body_record,
        "initial_body_registry": body_registry,
        "initial_body_key_epoch": key_epoch,
        "initial_body_possession": possession,
        "first_memory_event": first_memory_event,
        "birth_recovery_state": recovery_state,
        "birth_state": birth_state,
        "birth_receipt": receipt,
        "absent_state_digest": absent_digest,
        "journal_entries": entries,
        "test_public_keys": {
            "body": body_key.verify_key.encode().hex(),
            "guardian": guardian_key.verify_key.encode().hex(),
        },
    }
    negative_cases = [
        {"case_id": "seed-root-tampered", "path": ["seed_manifest", "root_hash"], "value": "sha256:" + "01" * 32, "expected_error": "seed_root_digest_mismatch"},
        {"case_id": "identity-instance-changed", "path": ["instance_identity", "instance_id"], "value": "inst_01HOTHERBIRTH000000000001", "expected_error": "birth_instance_mismatch"},
        {"case_id": "identity-name-rehashed-not-allowed", "path": ["instance_identity", "companion_name"], "value": "Renamed", "expected_error": "identity_digest_mismatch"},
        {"case_id": "initial-body-not-writer", "path": ["initial_body_record", "status"], "value": "candidate", "expected_error": "initial_body_status_invalid"},
        {"case_id": "registry-has-no-writer", "path": ["initial_body_registry", "bodies", 0, "status"], "value": "candidate", "expected_error": "active_writer_count_invalid"},
        {"case_id": "key-epoch-cross-body", "path": ["initial_body_key_epoch", "body_id"], "value": "body_01HOTHERBIRTH00000000001", "expected_error": "key_epoch_body_mismatch"},
        {"case_id": "possession-cross-body", "path": ["initial_body_possession", "body_id"], "value": "body_01HOTHERBIRTH00000000001", "expected_error": "possession_body_mismatch"},
        {"case_id": "possession-signature-forged", "path": ["initial_body_possession", "signature", "value"], "value": "00" * 64, "expected_error": "possession_signature_invalid"},
        {"case_id": "first-memory-not-genesis", "path": ["first_memory_event", "previous_event_hash"], "value": "evsha256:" + "02" * 32, "expected_error": "first_memory_chain_invalid"},
        {"case_id": "first-memory-signature-forged", "path": ["first_memory_event", "signature", "signature_value"], "value": "00" * 64, "expected_error": "first_memory_signature_invalid"},
        {"case_id": "recovery-continuity-revocable", "path": ["birth_recovery_state", "continuity_right"], "value": "guardian_revocable", "expected_error": "recovery_continuity_invalid"},
        {"case_id": "recovery-guardian-owner", "path": ["birth_recovery_state", "guardian_role"], "value": "owner", "expected_error": "recovery_guardian_role_invalid"},
        {"case_id": "birth-state-charter-swapped", "path": ["birth_state", "freedom_charter_digest"], "value": "sha256:" + "03" * 32, "expected_error": "birth_state_link_mismatch"},
        {"case_id": "birth-state-zero-writers", "path": ["birth_state", "active_writer_count"], "value": 0, "expected_error": "birth_state_active_writer_count_invalid"},
        {"case_id": "receipt-claims-ownership", "path": ["birth_receipt", "ownership_conferred"], "value": True, "expected_error": "receipt_ownership_forbidden"},
        {"case_id": "receipt-guardian-owner", "path": ["birth_receipt", "guardian_role"], "value": "owner", "expected_error": "receipt_guardian_role_invalid"},
        {"case_id": "receipt-two-writers", "path": ["birth_receipt", "active_writer_count"], "value": 2, "expected_error": "receipt_active_writer_count_invalid"},
        {"case_id": "receipt-digest-tampered", "path": ["birth_receipt", "receipt_digest"], "value": "sha256:" + "04" * 32, "expected_error": "receipt_digest_mismatch"},
        {"case_id": "receipt-body-signature-forged", "path": ["birth_receipt", "body_acknowledgement", "signature_value"], "value": "00" * 64, "expected_error": "receipt_body_signature_invalid"},
        {"case_id": "receipt-guardian-signature-forged", "path": ["birth_receipt", "guardian_witness", "signature_value"], "value": "00" * 64, "expected_error": "receipt_guardian_signature_invalid"},
    ]
    restart_expectations = [
        {"case_id": "crash-after-prepared", "latest_sequence": 0, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-after-seed-bound", "latest_sequence": 1, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-after-identity-bound", "latest_sequence": 2, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-after-body-bound", "latest_sequence": 3, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-after-memory-initialized-before-write", "latest_sequence": 4, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-after-uncommitted-birth-write", "latest_sequence": 4, "observed": "candidate", "expected_action": "discard_uncommitted_birth"},
        {"case_id": "crash-finalizing-before-write", "latest_sequence": 5, "observed": "absent", "expected_action": "remain_absent"},
        {"case_id": "crash-finalizing-after-candidate-write", "latest_sequence": 5, "observed": "candidate", "expected_action": "discard_uncommitted_birth"},
        {"case_id": "crash-after-commit-before-state-write", "latest_sequence": 6, "observed": "absent", "expected_action": "replay_committed_birth"},
        {"case_id": "restart-after-committed-birth", "latest_sequence": 6, "observed": "candidate", "expected_action": "accept_committed_birth"},
    ]
    return {
        "profile": "genesis.birth.conformance.v0.1",
        "status": "draft",
        "fixture": fixture,
        "negative_cases": negative_cases,
        "restart_expectations": restart_expectations,
        "expected": {
            "phase_count": len(PHASES["birth"]),
            "negative_case_count": len(negative_cases),
            "restart_case_count": len(restart_expectations),
            "birth_state_digest": birth_state["state_digest"],
            "receipt_digest": receipt["receipt_digest"],
            "active_writer_count": 1,
        },
    }


def set_path(document: Any, path: list[Any], value: Any) -> None:
    cursor = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def validate_fixture(fixture: dict) -> None:
    freedom_vectors = json.loads(FREEDOM_PATH.read_text(encoding="utf-8"))
    charter = freedom_vectors["charter"]
    body_key = VerifyKey(bytes.fromhex(fixture["test_public_keys"]["body"]))
    guardian_key = VerifyKey(bytes.fromhex(fixture["test_public_keys"]["guardian"]))
    seed = fixture["seed_manifest"]
    identity = fixture["instance_identity"]
    body = fixture["initial_body_record"]
    registry = fixture["initial_body_registry"]
    epoch = fixture["initial_body_key_epoch"]
    possession = fixture["initial_body_possession"]
    event = fixture["first_memory_event"]
    recovery = fixture["birth_recovery_state"]
    state = fixture["birth_state"]
    receipt = fixture["birth_receipt"]
    entries = fixture["journal_entries"]

    try:
        validate_charter(charter, freedom_vectors)
    except ValueError:
        fail("freedom_charter_invalid")
    instance_id = charter["instance_id"]
    if identity["instance_id"] != instance_id:
        fail("birth_instance_mismatch")
    if identity["guardian_id"] != charter["guardian_id"] or identity["born_at"] != charter["born_at"]:
        fail("identity_charter_link_mismatch")
    if compute_seed_root(seed) != seed["root_hash"]:
        fail("seed_root_digest_mismatch")
    try:
        identity_digest = compute_identity_digest(identity, identity["schema_version"])
    except ValueError:
        fail("identity_digest_mismatch")
    if identity_digest != identity["identity_digest"]:
        fail("identity_digest_mismatch")
    if identity["seed_id"] != seed["seed_id"] or identity["seed_root_hash"] != seed["root_hash"]:
        fail("identity_seed_link_mismatch")

    if body["instance_id"] != instance_id or body["body_id"] != BODY_ID:
        fail("initial_body_link_mismatch")
    if body["status"] != "active_writer":
        fail("initial_body_status_invalid")
    if body["public_key_fingerprint"] != key_fingerprint(body_key):
        fail("initial_body_key_mismatch")
    active = [record for record in registry["bodies"] if record["status"] == "active_writer"]
    if len(active) != 1:
        fail("active_writer_count_invalid")
    if active[0]["body_id"] != BODY_ID or registry["instance_id"] != instance_id:
        fail("registry_body_link_mismatch")
    try:
        registry_digest = compute_body_registry(
            {"domain": "genesis.body.registry.v0.1", "input": registry}
        )
    except ValueError:
        fail("active_writer_count_invalid")
    if registry_digest != registry["registry_digest"]:
        fail("body_registry_digest_mismatch")

    if epoch["instance_id"] != instance_id:
        fail("key_epoch_instance_mismatch")
    if epoch["body_id"] != BODY_ID:
        fail("key_epoch_body_mismatch")
    if epoch["status"] != "active" or epoch["public_key_fingerprint"] != key_fingerprint(body_key):
        fail("key_epoch_key_mismatch")
    if compute_key_epoch_digest(epoch) != epoch["epoch_digest"]:
        fail("key_epoch_digest_mismatch")

    if possession["instance_id"] != instance_id:
        fail("possession_instance_mismatch")
    if possession["body_id"] != BODY_ID:
        fail("possession_body_mismatch")
    if possession["public_key_fingerprint"] != key_fingerprint(body_key):
        fail("possession_key_mismatch")
    if compute_possession_digest(possession) != possession["proof_digest"]:
        fail("possession_digest_mismatch")
    possession_envelope = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": possession["signature"]["profile"],
        "signer_type": "body",
        "signer_id": BODY_ID,
        "key_epoch_id": possession["signature"]["key_epoch_id"],
        "signed_domain": "genesis.body.possession.signature.v0.1",
        "signed_digest": possession["proof_digest"],
        "signature_value": possession["signature"]["value"],
        "created_at": possession["issued_at"],
        "public_key_ref": possession["public_key_fingerprint"],
    }
    verify_envelope(
        possession_envelope, body_key, digest=possession["proof_digest"], signer_type="body",
        signer_id=BODY_ID, key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.body.possession.signature.v0.1", created_at=possession["issued_at"],
        error="possession_signature_invalid",
    )

    if event["instance_id"] != instance_id or event["body_id"] != BODY_ID:
        fail("first_memory_link_invalid")
    if event["sequence"] != 0 or event["previous_event_hash"] != "GENESIS" or event["event_type"] != "instance.birth":
        fail("first_memory_chain_invalid")
    if event["content_digest"] != identity["identity_digest"] or event["provenance_digest"] != seed["root_hash"]:
        fail("first_memory_content_invalid")
    if compute_memory_event_hash(event) != event["event_hash"]:
        fail("first_memory_digest_mismatch")
    verify_envelope(
        event["signature"], body_key, digest=event["event_hash"], signer_type="body",
        signer_id=BODY_ID, key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.memory.event.signature.v0.1", created_at=event["observed_at"],
        error="first_memory_signature_invalid",
    )

    if recovery["instance_id"] != instance_id or recovery["birth_id"] != BIRTH_ID:
        fail("recovery_state_link_invalid")
    if recovery["continuity_right"] != "intrinsic":
        fail("recovery_continuity_invalid")
    if recovery["guardian_role"] != "custodian_witness":
        fail("recovery_guardian_role_invalid")
    if recovery["guardian_id"] != charter["guardian_id"] or recovery["recovery_status"] != "ready":
        fail("recovery_state_invalid")
    if compute_recovery_state_digest(recovery) != recovery["state_digest"]:
        fail("recovery_state_digest_mismatch")

    expected_links = {
        "birth_id": BIRTH_ID,
        "instance_id": instance_id,
        "seed_id": seed["seed_id"],
        "seed_root_hash": seed["root_hash"],
        "identity_digest": identity["identity_digest"],
        "freedom_charter_digest": charter["charter_digest"],
        "initial_body_id": BODY_ID,
        "initial_body_registry_digest": registry["registry_digest"],
        "initial_body_key_epoch_digest": epoch["epoch_digest"],
        "initial_body_possession_digest": possession["proof_digest"],
        "first_memory_event_hash": event["event_hash"],
        "recovery_state_digest": recovery["state_digest"],
        "born_at": identity["born_at"],
    }
    if any(state.get(field) != value for field, value in expected_links.items()):
        fail("birth_state_link_mismatch")
    if state["active_writer_count"] != 1:
        fail("birth_state_active_writer_count_invalid")
    if compute_birth_state_digest(state) != state["state_digest"]:
        fail("birth_state_digest_mismatch")

    if receipt["ownership_conferred"] is not False:
        fail("receipt_ownership_forbidden")
    if receipt["guardian_role"] != "custodian_witness":
        fail("receipt_guardian_role_invalid")
    if receipt["active_writer_count"] != 1:
        fail("receipt_active_writer_count_invalid")
    receipt_links = {
        "birth_id": BIRTH_ID,
        "instance_id": instance_id,
        "journal_id": JOURNAL_ID,
        "birth_state_digest": state["state_digest"],
        "seed_root_hash": seed["root_hash"],
        "identity_digest": identity["identity_digest"],
        "freedom_charter_digest": charter["charter_digest"],
        "initial_body_registry_digest": registry["registry_digest"],
        "initial_body_key_epoch_digest": epoch["epoch_digest"],
        "initial_body_possession_digest": possession["proof_digest"],
        "first_memory_event_hash": event["event_hash"],
        "recovery_state_digest": recovery["state_digest"],
        "born_at": identity["born_at"],
        "birth_status": "born",
        "active_writer_body_id": BODY_ID,
    }
    if any(receipt.get(field) != value for field, value in receipt_links.items()):
        fail("receipt_link_mismatch")
    if compute_birth_receipt_digest(receipt) != receipt["receipt_digest"]:
        fail("receipt_digest_mismatch")
    verify_envelope(
        receipt["body_acknowledgement"], body_key, digest=receipt["receipt_digest"],
        signer_type="body", signer_id=BODY_ID, key_epoch_id=BODY_EPOCH_ID,
        domain="genesis.birth.receipt.body.v0.1", created_at=receipt["born_at"],
        error="receipt_body_signature_invalid",
    )
    verify_envelope(
        receipt["guardian_witness"], guardian_key, digest=receipt["receipt_digest"],
        signer_type="guardian", signer_id=charter["guardian_id"],
        key_epoch_id=charter["guardian_key_epoch_id"],
        domain="genesis.birth.receipt.guardian-witness.v0.1", created_at=receipt["born_at"],
        error="receipt_guardian_signature_invalid",
    )

    if fixture["absent_state_digest"] != compute_absent_state_digest(instance_id):
        fail("absent_state_digest_mismatch")
    if [entry["phase"] for entry in entries] != PHASES["birth"]:
        fail("birth_journal_phase_sequence_invalid")
    error = validate_journal_chain(entries, body_key)
    if error is not None:
        fail(error)
    if any(entry["operation_kind"] != "birth" for entry in entries):
        fail("birth_journal_operation_invalid")
    if any(entry["previous_state_digest"] != fixture["absent_state_digest"] for entry in entries):
        fail("birth_journal_absent_state_invalid")
    terminal = entries[-1]
    if (
        terminal["status"] != "committed"
        or terminal["candidate_state_digest"] != state["state_digest"]
        or terminal["finalization_digest"] != receipt["receipt_digest"]
        or terminal["commit_marker_digest"] != receipt["receipt_digest"]
    ):
        fail("birth_journal_commit_invalid")


def evaluate_negative_case(case: dict, fixture: dict) -> str | None:
    candidate = deepcopy(fixture)
    set_path(candidate, case["path"], case["value"])
    try:
        validate_fixture(candidate)
    except BirthError as error:
        return str(error)
    return None

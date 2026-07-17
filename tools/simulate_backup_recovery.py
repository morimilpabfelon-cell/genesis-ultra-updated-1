#!/usr/bin/env python3
"""Simula backup comprometido atómicamente y recovery con una brecha declarada."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from nacl import pwhash
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

from simulate_transfer import (
    BODY_A,
    BODY_B,
    BODY_A_EPOCH,
    BODY_B_EPOCH,
    HASH_PROFILE,
    INSTANCE_ID,
    SEED_ROOT,
    SIGNATURE_PROFILE,
    compute_checkpoint_hash,
    key_fingerprint,
    make_event,
    make_signature_envelope,
    verify_signature,
)
from validate_backup_recovery import (
    compute_backup_commit_digest,
    compute_backup_encryption_digest,
    compute_backup_manifest_digest,
    compute_body_possession_digest,
    compute_body_revocation_digest,
    compute_continuity_gap_digest,
    compute_recovery_authorization_digest,
    compute_recovery_finalization_digest,
    compute_recovery_record_digest,
    evaluate_recovery_transaction,
)
from validate_authority import compute_device_registration_digest
from validate_continuity import compute_body_registry
from validate_workspace import encode_field


BODY_C = "body_01HSIM_C000000000000001"
BODY_C_EPOCH = "epoch_01HSIM_C00000000000001"
BACKUP_ID = "backup_01HSIM000000000000001"
RECOVERY_ID = "recovery_01HSIM0000000000001"
RECOVERY_AUTH_ID = "rauth_01HSIM00000000000001"
GUARDIAN_ID = "guardian_01HSIM_EIDON000000001"
GUARDIAN_KEY_EPOCH = "guardian_epoch_01HSIM000000001"


def make_device_registration(
    *,
    registration_id: str,
    body_id: str,
    platform_profile: str,
    public_key_fingerprint: str,
    registered_at: str,
    guardian_key: SigningKey,
) -> dict:
    """Registra el Body de recuperación; no concede permiso de movimiento."""
    registration = {
        "schema_version": "genesis.guardian.device.registration.v0.1",
        "registration_id": registration_id,
        "guardian_id": GUARDIAN_ID,
        "guardian_key_epoch_id": GUARDIAN_KEY_EPOCH,
        "instance_id": INSTANCE_ID,
        "authority_epoch": 1,
        "body_id": body_id,
        "platform_profile": platform_profile,
        "public_key_fingerprint": public_key_fingerprint,
        "registered_at": registered_at,
    }
    registration["registration_digest"] = compute_device_registration_digest(registration)
    registration["signature"] = make_signature_envelope(
        guardian_key,
        registration["registration_digest"],
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
        signed_domain="genesis.guardian.device.registration.signature.v0.1",
        created_at=registered_at,
    )
    verify_signature(registration["signature"], guardian_key.verify_key)
    return registration


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_registry_after_recovery(
    signing_key_a: SigningKey,
    signing_key_b: SigningKey,
    signing_key_c: SigningKey,
    updated_at: str,
) -> dict:
    registry = {
        "schema_version": "genesis.body.registry.v0.1",
        "instance_id": INSTANCE_ID,
        "registry_epoch": 3,
        "bodies": [
            {
                "body_id": BODY_A,
                "status": "revoked",
                "platform_profile": "android-kotlin",
                "public_key_fingerprint": key_fingerprint(signing_key_a),
                "created_at": "2026-07-12T00:00:00Z",
                "last_seen_at": "2026-07-12T01:06:00Z",
                "revocation_ref": "revoke_01HSIM_A0000000000001",
            },
            {
                "body_id": BODY_B,
                "status": "lost",
                "platform_profile": "apple-swift",
                "public_key_fingerprint": key_fingerprint(signing_key_b),
                "created_at": "2026-07-12T00:30:00Z",
                "last_seen_at": "2026-07-12T02:10:00Z",
                "revocation_ref": "revoke_01HSIM_B0000000000001",
            },
            {
                "body_id": BODY_C,
                "status": "active_writer",
                "platform_profile": "windows-dotnet",
                "public_key_fingerprint": key_fingerprint(signing_key_c),
                "created_at": "2026-07-12T03:00:00Z",
                "last_seen_at": updated_at,
                "revocation_ref": None,
            },
        ],
        "updated_at": updated_at,
    }
    registry["registry_digest"] = compute_body_registry(
        {"domain": "genesis.body.registry.v0.1", "input": registry}
    )
    return registry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-artifacts", type=Path, required=True)
    parser.add_argument("--artifacts-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = json.loads(args.source_artifacts.read_text(encoding="utf-8"))
    signing_key_a = SigningKey(bytes([0xA1]) * 32)
    signing_key_b = SigningKey(bytes([0xB2]) * 32)
    guardian_key = SigningKey(bytes([0xC3]) * 32)
    signing_key_c = SigningKey(bytes([0xD4]) * 32)

    memory_events = source["memory_events"]
    tip = memory_events[-1]
    assert tip["body_id"] == BODY_B and tip["sequence"] == 3
    registry_at_backup = source["body_registry"]
    state_bytes = canonical_json(memory_events)

    checkpoint = {
        "schema_version": "genesis.checkpoint.v0.1",
        "hash_profile": HASH_PROFILE,
        "checkpoint_id": "checkpoint_01HSIM_BACKUP000001",
        "instance_id": INSTANCE_ID,
        "created_by_body_id": BODY_B,
        "sequence": tip["sequence"],
        "last_event_hash": tip["event_hash"],
        "seed_root_hash": SEED_ROOT,
        "body_registry_digest": registry_at_backup["registry_digest"],
        "state_digest": sha256_bytes(state_bytes),
        "created_at": "2026-07-12T02:00:00Z",
    }
    checkpoint["checkpoint_hash"] = compute_checkpoint_hash(checkpoint)
    checkpoint["signature"] = make_signature_envelope(
        signing_key_b,
        checkpoint["checkpoint_hash"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.checkpoint.signature.v0.1",
        created_at=checkpoint["created_at"],
    )
    verify_signature(checkpoint["signature"], signing_key_b.verify_key)

    archive = {
        "seed_root_hash": SEED_ROOT,
        "memory_events": memory_events,
        "checkpoint": checkpoint,
        "body_registry": registry_at_backup,
    }
    plaintext = canonical_json(archive)
    manifest = {
        "schema_version": "genesis.backup.manifest.v0.1",
        "backup_id": BACKUP_ID,
        "instance_id": INSTANCE_ID,
        "seed_root_hash": SEED_ROOT,
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "last_event_hash": tip["event_hash"],
        "last_sequence": tip["sequence"],
        "body_registry_digest": registry_at_backup["registry_digest"],
        "created_at": "2026-07-12T02:01:00Z",
        "created_by_body_id": BODY_B,
        "encryption_profile": "genesis.backup.xchacha20poly1305.v0.1",
        "key_recovery_profile": "guardian-recovery-secret-v0.1",
        "contents": [
            {"kind": "seed", "path": "seed/root.txt", "digest": SEED_ROOT, "encrypted": True},
            {"kind": "memory", "path": "memory/events.json", "digest": sha256_bytes(state_bytes), "encrypted": True},
            {"kind": "checkpoint", "path": "continuity/checkpoint.json", "digest": checkpoint["checkpoint_hash"], "encrypted": True},
            {"kind": "body_registry", "path": "continuity/body-registry.json", "digest": registry_at_backup["registry_digest"], "encrypted": True},
        ],
    }
    manifest["package_digest"] = compute_backup_manifest_digest(manifest)

    salt = bytes.fromhex("44" * 16)
    nonce = bytes.fromhex("55" * 24)
    password = b"genesis-backup-recovery-simulation"
    kdf_parameters = {"opslimit": 1, "memlimit": 8192, "key_length": 32}
    key = pwhash.argon2id.kdf(
        kdf_parameters["key_length"],
        password,
        salt,
        opslimit=kdf_parameters["opslimit"],
        memlimit=kdf_parameters["memlimit"],
    )
    aad = encode_field("genesis.backup.aad.v0.1") + encode_field(manifest["package_digest"])
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    assert crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key) == plaintext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    try:
        crypto_aead_xchacha20poly1305_ietf_decrypt(bytes(tampered), aad, nonce, key)
        raise AssertionError("ciphertext alterado aceptado")
    except CryptoError:
        pass

    encryption = {
        "schema_version": "genesis.backup.encryption.v0.1",
        "backup_id": BACKUP_ID,
        "instance_id": INSTANCE_ID,
        "manifest_digest": manifest["package_digest"],
        "encryption_profile": "genesis.backup.xchacha20poly1305.v0.1",
        "kdf_profile": "genesis.kdf.argon2id.v0.1",
        "kdf_parameters": kdf_parameters,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "associated_data_digest": sha256_bytes(aad),
        "ciphertext_digest": sha256_bytes(ciphertext),
        "wrapped_key": None,
        "created_at": "2026-07-12T02:02:00Z",
    }
    encryption["encryption_digest"] = compute_backup_encryption_digest(encryption)

    backup_commit = {
        "schema_version": "genesis.backup.commit.v0.1",
        "backup_id": BACKUP_ID,
        "instance_id": INSTANCE_ID,
        "created_by_body_id": BODY_B,
        "manifest_digest": manifest["package_digest"],
        "encryption_digest": encryption["encryption_digest"],
        "ciphertext_digest": encryption["ciphertext_digest"],
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "last_event_hash": tip["event_hash"],
        "last_sequence": tip["sequence"],
        "state": "committed",
        "committed_at": "2026-07-12T02:03:00Z",
    }
    backup_commit["commit_digest"] = compute_backup_commit_digest(backup_commit)
    backup_commit["signature"] = make_signature_envelope(
        signing_key_b,
        backup_commit["commit_digest"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.backup.commit.signature.v0.1",
        created_at=backup_commit["committed_at"],
    )
    verify_signature(backup_commit["signature"], signing_key_b.verify_key)

    destination_registration = make_device_registration(
        registration_id="device_reg_01HSIM_C00000000001",
        body_id=BODY_C,
        platform_profile="windows-dotnet",
        public_key_fingerprint=key_fingerprint(signing_key_c),
        registered_at="2026-07-12T03:00:00Z",
        guardian_key=guardian_key,
    )
    recovery_authorization = {
        "schema_version": "genesis.recovery.authorization.v0.1",
        "authorization_id": RECOVERY_AUTH_ID,
        "recovery_id": RECOVERY_ID,
        "guardian_id": GUARDIAN_ID,
        "guardian_key_epoch_id": GUARDIAN_KEY_EPOCH,
        "instance_id": INSTANCE_ID,
        "authority_epoch": 1,
        "source_backup_id": BACKUP_ID,
        "source_backup_commit_digest": backup_commit["commit_digest"],
        "previous_body_id": BODY_B,
        "new_body_id": BODY_C,
        "reason": "lost",
        "issued_at": "2026-07-12T03:01:00Z",
        "not_before": "2026-07-12T03:01:00Z",
        "expires_at": "2026-07-12T03:31:00Z",
    }
    recovery_authorization["authorization_digest"] = compute_recovery_authorization_digest(
        recovery_authorization
    )
    recovery_authorization["signature"] = make_signature_envelope(
        guardian_key,
        recovery_authorization["authorization_digest"],
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
        signed_domain="genesis.recovery.authorization.signature.v0.1",
        created_at=recovery_authorization["issued_at"],
    )
    verify_signature(recovery_authorization["signature"], guardian_key.verify_key)

    possession_input = {
        "schema_version": "genesis.body.possession.v0.1",
        "proof_id": "proof_01HSIM_C00000000000001",
        "instance_id": INSTANCE_ID,
        "body_id": BODY_C,
        "challenge_nonce": "nonce_01HSIM_C00000000000001",
        "issued_at": "2026-07-12T03:02:00Z",
        "expires_at": "2026-07-12T03:12:00Z",
        "public_key_fingerprint": key_fingerprint(signing_key_c),
    }
    possession_input["proof_digest"] = compute_body_possession_digest(possession_input)
    destination_possession_signature = make_signature_envelope(
        signing_key_c,
        possession_input["proof_digest"],
        signer_type="body",
        signer_id=BODY_C,
        key_epoch_id=BODY_C_EPOCH,
        signed_domain="genesis.body.possession.signature.v0.1",
        created_at=possession_input["issued_at"],
    )
    verify_signature(destination_possession_signature, signing_key_c.verify_key)
    destination_possession = {
        **possession_input,
        "signature": {
            "profile": SIGNATURE_PROFILE,
            "key_epoch_id": BODY_C_EPOCH,
            "value": destination_possession_signature["signature_value"],
        },
    }

    continuity_gap = {
        "schema_version": "genesis.continuity.gap.v0.1",
        "gap_id": "gap_01HSIM00000000000000001",
        "instance_id": INSTANCE_ID,
        "detected_at": "2026-07-12T03:03:00Z",
        "first_missing_sequence": 4,
        "last_missing_sequence": 4,
        "reason": "device_lost",
        "last_trusted_event_hash": tip["event_hash"],
        "recovery_event_ref": RECOVERY_ID,
        "notes_digest": sha256_bytes(b"event 4 known to exist but unavailable"),
    }
    continuity_gap["gap_digest"] = compute_continuity_gap_digest(continuity_gap)

    previous_body_revocation = {
        "schema_version": "genesis.body.revocation.v0.1",
        "instance_id": INSTANCE_ID,
        "body_id": BODY_B,
        "revoked_at": "2026-07-12T03:04:00Z",
        "reason": "lost",
        "last_trusted_event_hash": tip["event_hash"],
        "guardian_authorization_ref": RECOVERY_AUTH_ID,
    }
    previous_body_revocation["revocation_digest"] = compute_body_revocation_digest(
        previous_body_revocation
    )

    recovery_record = {
        "schema_version": "genesis.recovery.record.v0.1",
        "recovery_id": RECOVERY_ID,
        "instance_id": INSTANCE_ID,
        "source_backup_id": BACKUP_ID,
        "source_backup_commit_digest": backup_commit["commit_digest"],
        "new_body_id": BODY_C,
        "previous_body_id": BODY_B,
        "restored_checkpoint_hash": checkpoint["checkpoint_hash"],
        "restored_last_event_hash": tip["event_hash"],
        "restored_last_sequence": 3,
        "last_known_sequence": 4,
        "continuity_status": "known_gap",
        "continuity_gap_ref": continuity_gap["gap_id"],
        "guardian_authorization_ref": RECOVERY_AUTH_ID,
        "previous_body_revocation_ref": previous_body_revocation["revocation_digest"],
        "destination_registration_ref": destination_registration["registration_digest"],
        "destination_possession_ref": destination_possession["proof_digest"],
        "performed_at": "2026-07-12T03:05:00Z",
    }
    recovery_record["recovery_digest"] = compute_recovery_record_digest(recovery_record)
    recovery_record["signature"] = make_signature_envelope(
        signing_key_c,
        recovery_record["recovery_digest"],
        signer_type="body",
        signer_id=BODY_C,
        key_epoch_id=BODY_C_EPOCH,
        signed_domain="genesis.recovery.record.signature.v0.1",
        created_at=recovery_record["performed_at"],
    )
    verify_signature(recovery_record["signature"], signing_key_c.verify_key)

    recovery_event = make_event(
        5,
        BODY_C,
        tip["event_hash"],
        "recovery.restored",
        signing_key_c,
        BODY_C_EPOCH,
    )
    registry_after = make_registry_after_recovery(
        signing_key_a,
        signing_key_b,
        signing_key_c,
        "2026-07-12T03:06:00Z",
    )
    recovery_finalization = {
        "schema_version": "genesis.recovery.finalization.v0.1",
        "recovery_id": RECOVERY_ID,
        "instance_id": INSTANCE_ID,
        "backup_commit_digest": backup_commit["commit_digest"],
        "recovery_record_digest": recovery_record["recovery_digest"],
        "continuity_gap_digest": continuity_gap["gap_digest"],
        "previous_body_revocation_digest": previous_body_revocation["revocation_digest"],
        "destination_registration_digest": destination_registration["registration_digest"],
        "destination_possession_digest": destination_possession["proof_digest"],
        "final_body_registry_digest": registry_after["registry_digest"],
        "previous_body_status": "lost",
        "destination_body_status": "active_writer",
        "guardian_authorization_ref": RECOVERY_AUTH_ID,
        "recovery_event_hash": recovery_event["event_hash"],
        "finalized_at": "2026-07-12T03:06:00Z",
    }
    recovery_finalization["finalization_digest"] = compute_recovery_finalization_digest(
        recovery_finalization
    )
    recovery_finalization["guardian_acknowledgement"] = make_signature_envelope(
        guardian_key,
        recovery_finalization["finalization_digest"],
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
        signed_domain="genesis.recovery.finalization.signature.v0.1",
        created_at=recovery_finalization["finalized_at"],
    )
    recovery_finalization["destination_acknowledgement"] = make_signature_envelope(
        signing_key_c,
        recovery_finalization["finalization_digest"],
        signer_type="body",
        signer_id=BODY_C,
        key_epoch_id=BODY_C_EPOCH,
        signed_domain="genesis.recovery.finalization.signature.v0.1",
        created_at=recovery_finalization["finalized_at"],
    )
    verify_signature(recovery_finalization["guardian_acknowledgement"], guardian_key.verify_key)
    verify_signature(recovery_finalization["destination_acknowledgement"], signing_key_c.verify_key)

    bundle = {
        "backup_checkpoint": checkpoint,
        "backup_manifest": manifest,
        "backup_encryption": encryption,
        "backup_ciphertext_hex": ciphertext.hex(),
        "backup_commit": backup_commit,
        "recovery_authorization": recovery_authorization,
        "destination_registration": destination_registration,
        "destination_possession": destination_possession,
        "destination_possession_signature": destination_possession_signature,
        "continuity_gap": continuity_gap,
        "previous_body_revocation": previous_body_revocation,
        "recovery_record": recovery_record,
        "recovery_event": recovery_event,
        "body_registry_after": registry_after,
        "recovery_finalization": recovery_finalization,
    }
    error = evaluate_recovery_transaction(bundle, evaluated_at="2026-07-12T03:05:00Z")
    assert error is None, error

    args.artifacts_output.parent.mkdir(parents=True, exist_ok=True)
    args.artifacts_output.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "simulation": "genesis.backup_recovery.v0.1",
                "status": "complete_with_known_gap",
                "backup_id": BACKUP_ID,
                "backup_commit_digest": backup_commit["commit_digest"],
                "recovery_id": RECOVERY_ID,
                "recovery_finalization_digest": recovery_finalization["finalization_digest"],
                "restored_sequence": 3,
                "last_known_sequence": 4,
                "first_recovery_sequence": 5,
                "previous_body_status": "lost",
                "destination_body_status": "active_writer",
                "ciphertext_tamper_rejected": True,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    print("\nBACKUP -> PÉRDIDA -> RECOVERY COMPLETO", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

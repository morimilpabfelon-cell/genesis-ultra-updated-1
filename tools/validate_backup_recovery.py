#!/usr/bin/env python3
"""Digests y enlaces compartidos para backup y recovery transaccionales."""

from __future__ import annotations

from datetime import datetime
import hashlib

from validate_authority import compute_device_registration_digest
from validate_workspace import bool_text, encode_field, hash_fields, safe_relative_path


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compute_backup_manifest_digest(manifest: dict) -> str:
    contents = manifest["contents"]
    paths = [item["path"] for item in contents]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate_backup_path")
    if any(not safe_relative_path(path) for path in paths):
        raise ValueError("invalid_relative_path")
    fields = [
        manifest["schema_version"],
        manifest["backup_id"],
        manifest["instance_id"],
        manifest["seed_root_hash"],
        manifest["checkpoint_hash"],
        manifest["last_event_hash"],
        str(manifest["last_sequence"]),
        manifest["body_registry_digest"],
        manifest["created_at"],
        manifest["created_by_body_id"],
        manifest["encryption_profile"],
        optional_text(manifest.get("key_recovery_profile")),
        str(len(contents)),
    ]
    for item in sorted(contents, key=lambda value: value["path"].encode("utf-8")):
        fields.extend(
            [item["kind"], item["path"], item["digest"], bool_text(item["encrypted"])]
        )
    return hash_fields("genesis.backup.manifest.v0.1", fields)


def compute_backup_encryption_digest(encryption: dict) -> str:
    parameters = encryption["kdf_parameters"]
    return hash_fields(
        "genesis.backup.encryption.v0.1",
        [
            encryption["schema_version"],
            encryption["backup_id"],
            encryption["instance_id"],
            encryption["manifest_digest"],
            encryption["encryption_profile"],
            encryption["kdf_profile"],
            str(parameters["opslimit"]),
            str(parameters["memlimit"]),
            str(parameters["key_length"]),
            encryption["salt"],
            encryption["nonce"],
            encryption["associated_data_digest"],
            encryption["ciphertext_digest"],
            optional_text(encryption["wrapped_key"]),
            encryption["created_at"],
        ],
    )


def compute_backup_commit_digest(commit: dict) -> str:
    return hash_fields(
        "genesis.backup.commit.v0.1",
        [
            commit["schema_version"],
            commit["backup_id"],
            commit["instance_id"],
            commit["created_by_body_id"],
            commit["manifest_digest"],
            commit["encryption_digest"],
            commit["ciphertext_digest"],
            commit["checkpoint_hash"],
            commit["last_event_hash"],
            str(commit["last_sequence"]),
            commit["state"],
            commit["committed_at"],
        ],
    )


def compute_recovery_authorization_digest(authorization: dict) -> str:
    return hash_fields(
        "genesis.recovery.authorization.v0.1",
        [
            authorization["schema_version"],
            authorization["authorization_id"],
            authorization["recovery_id"],
            authorization["guardian_id"],
            authorization["guardian_key_epoch_id"],
            authorization["instance_id"],
            str(authorization["authority_epoch"]),
            authorization["source_backup_id"],
            authorization["source_backup_commit_digest"],
            authorization["previous_body_id"],
            authorization["new_body_id"],
            authorization["reason"],
            authorization["issued_at"],
            authorization["not_before"],
            authorization["expires_at"],
        ],
    )


def compute_continuity_gap_digest(gap: dict) -> str:
    return hash_fields(
        "genesis.continuity.gap.v0.1",
        [
            gap["schema_version"],
            gap["gap_id"],
            gap["instance_id"],
            gap["detected_at"],
            str(gap["first_missing_sequence"]),
            str(gap["last_missing_sequence"]),
            gap["reason"],
            gap["last_trusted_event_hash"],
            gap["recovery_event_ref"],
            optional_text(gap.get("notes_digest")),
        ],
    )


def compute_body_revocation_digest(revocation: dict) -> str:
    return hash_fields(
        "genesis.body.revocation.v0.1",
        [
            revocation["schema_version"],
            revocation["instance_id"],
            revocation["body_id"],
            revocation["revoked_at"],
            revocation["reason"],
            revocation["last_trusted_event_hash"],
            revocation["guardian_authorization_ref"],
        ],
    )


def compute_body_possession_digest(proof: dict) -> str:
    return hash_fields(
        "genesis.body.possession.v0.1",
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


def compute_recovery_record_digest(record: dict) -> str:
    return hash_fields(
        "genesis.recovery.record.v0.1",
        [
            record["schema_version"],
            record["recovery_id"],
            record["instance_id"],
            record["source_backup_id"],
            record["source_backup_commit_digest"],
            record["new_body_id"],
            optional_text(record["previous_body_id"]),
            record["restored_checkpoint_hash"],
            record["restored_last_event_hash"],
            str(record["restored_last_sequence"]),
            str(record["last_known_sequence"]),
            record["continuity_status"],
            optional_text(record["continuity_gap_ref"]),
            record["guardian_authorization_ref"],
            record["previous_body_revocation_ref"],
            record["destination_registration_ref"],
            record["destination_possession_ref"],
            record["performed_at"],
        ],
    )


def compute_recovery_finalization_digest(finalization: dict) -> str:
    return hash_fields(
        "genesis.recovery.finalization.v0.1",
        [
            finalization["schema_version"],
            finalization["recovery_id"],
            finalization["instance_id"],
            finalization["backup_commit_digest"],
            finalization["recovery_record_digest"],
            optional_text(finalization["continuity_gap_digest"]),
            finalization["previous_body_revocation_digest"],
            finalization["destination_registration_digest"],
            finalization["destination_possession_digest"],
            finalization["final_body_registry_digest"],
            finalization["previous_body_status"],
            finalization["destination_body_status"],
            finalization["guardian_authorization_ref"],
            finalization["recovery_event_hash"],
            finalization["finalized_at"],
        ],
    )


def evaluate_recovery_transaction(bundle: dict, *, evaluated_at: str) -> str | None:
    manifest = bundle["backup_manifest"]
    encryption = bundle["backup_encryption"]
    commit = bundle["backup_commit"]
    authorization = bundle["recovery_authorization"]
    registration = bundle["destination_registration"]
    possession = bundle["destination_possession"]
    gap = bundle.get("continuity_gap")
    revocation = bundle["previous_body_revocation"]
    record = bundle["recovery_record"]
    finalization = bundle["recovery_finalization"]
    registry = bundle["body_registry_after"]
    recovery_event = bundle["recovery_event"]

    instance_id = manifest["instance_id"]
    instance_artifacts = [
        bundle["backup_checkpoint"],
        encryption,
        commit,
        authorization,
        registration,
        possession,
        revocation,
        record,
        finalization,
        registry,
        recovery_event,
    ]
    if gap is not None:
        instance_artifacts.append(gap)
    if any(artifact["instance_id"] != instance_id for artifact in instance_artifacts):
        return "recovery_instance_id_mismatch"
    if (
        encryption["backup_id"] != manifest["backup_id"]
        or commit["backup_id"] != manifest["backup_id"]
        or commit["created_by_body_id"] != manifest["created_by_body_id"]
    ):
        return "backup_identity_links_invalid"

    if manifest["package_digest"] != compute_backup_manifest_digest(manifest):
        return "backup_manifest_digest_mismatch"
    if encryption["encryption_digest"] != compute_backup_encryption_digest(encryption):
        return "backup_encryption_digest_mismatch"
    if encryption["manifest_digest"] != manifest["package_digest"]:
        return "backup_encryption_manifest_mismatch"
    try:
        ciphertext = bytes.fromhex(bundle["backup_ciphertext_hex"])
    except (KeyError, ValueError):
        return "backup_ciphertext_encoding_invalid"
    if "sha256:" + hashlib.sha256(ciphertext).hexdigest() != encryption["ciphertext_digest"]:
        return "backup_ciphertext_digest_mismatch"
    aad = encode_field("genesis.backup.aad.v0.1") + encode_field(manifest["package_digest"])
    if "sha256:" + hashlib.sha256(aad).hexdigest() != encryption["associated_data_digest"]:
        return "backup_associated_data_digest_mismatch"
    if commit["commit_digest"] != compute_backup_commit_digest(commit):
        return "backup_commit_digest_mismatch"
    if commit["state"] != "committed":
        return "backup_not_committed"
    if (
        commit["manifest_digest"] != manifest["package_digest"]
        or commit["encryption_digest"] != encryption["encryption_digest"]
        or commit["ciphertext_digest"] != encryption["ciphertext_digest"]
        or commit["checkpoint_hash"] != manifest["checkpoint_hash"]
        or commit["last_event_hash"] != manifest["last_event_hash"]
        or commit["last_sequence"] != manifest["last_sequence"]
    ):
        return "backup_commit_links_invalid"
    checkpoint = bundle["backup_checkpoint"]
    if (
        checkpoint["checkpoint_hash"] != manifest["checkpoint_hash"]
        or checkpoint["last_event_hash"] != manifest["last_event_hash"]
        or checkpoint["sequence"] != manifest["last_sequence"]
        or checkpoint["seed_root_hash"] != manifest["seed_root_hash"]
        or checkpoint["body_registry_digest"] != manifest["body_registry_digest"]
        or checkpoint["created_by_body_id"] != manifest["created_by_body_id"]
    ):
        return "backup_checkpoint_links_invalid"

    if authorization["authorization_digest"] != compute_recovery_authorization_digest(authorization):
        return "recovery_authorization_digest_mismatch"
    if not (
        parse_utc(authorization["issued_at"])
        <= parse_utc(authorization["not_before"])
        < parse_utc(authorization["expires_at"])
    ):
        return "recovery_authorization_time_window_invalid"
    evaluated = parse_utc(evaluated_at)
    if evaluated < parse_utc(authorization["not_before"]):
        return "recovery_authorization_not_yet_valid"
    if evaluated >= parse_utc(authorization["expires_at"]):
        return "recovery_authorization_expired"
    if (
        authorization["source_backup_id"] != commit["backup_id"]
        or authorization["source_backup_commit_digest"] != commit["commit_digest"]
        or authorization["recovery_id"] != record["recovery_id"]
        or authorization["previous_body_id"] != record["previous_body_id"]
        or authorization["new_body_id"] != record["new_body_id"]
    ):
        return "recovery_authorization_scope_mismatch"

    if registration["registration_digest"] != compute_device_registration_digest(registration):
        return "recovery_destination_registration_invalid"
    if possession["proof_digest"] != compute_body_possession_digest(possession):
        return "recovery_destination_possession_invalid"
    if (
        registration["body_id"] != record["new_body_id"]
        or possession["body_id"] != record["new_body_id"]
        or registration["public_key_fingerprint"] != possession["public_key_fingerprint"]
    ):
        return "recovery_destination_identity_mismatch"
    if (
        registration["guardian_id"] != authorization["guardian_id"]
        or registration["guardian_key_epoch_id"] != authorization["guardian_key_epoch_id"]
        or registration["authority_epoch"] != authorization["authority_epoch"]
    ):
        return "recovery_guardian_scope_mismatch"

    if revocation["revocation_digest"] != compute_body_revocation_digest(revocation):
        return "previous_body_revocation_digest_mismatch"
    if (
        revocation["body_id"] != record["previous_body_id"]
        or revocation["guardian_authorization_ref"] != authorization["authorization_id"]
    ):
        return "previous_body_not_revoked"

    if record["recovery_digest"] != compute_recovery_record_digest(record):
        return "recovery_record_digest_mismatch"
    if (
        record["source_backup_id"] != manifest["backup_id"]
        or record["source_backup_commit_digest"] != commit["commit_digest"]
        or record["restored_checkpoint_hash"] != manifest["checkpoint_hash"]
        or record["restored_last_event_hash"] != manifest["last_event_hash"]
        or record["restored_last_sequence"] != manifest["last_sequence"]
        or record["guardian_authorization_ref"] != authorization["authorization_id"]
    ):
        return "recovery_record_links_invalid"

    if record["last_known_sequence"] < record["restored_last_sequence"]:
        return "recovery_last_known_sequence_invalid"
    has_gap = record["last_known_sequence"] > record["restored_last_sequence"]
    if has_gap:
        if record["continuity_status"] != "known_gap" or gap is None:
            return "undeclared_memory_gap"
        if gap["gap_digest"] != compute_continuity_gap_digest(gap):
            return "continuity_gap_digest_mismatch"
        if (
            gap["first_missing_sequence"] != record["restored_last_sequence"] + 1
            or gap["last_missing_sequence"] != record["last_known_sequence"]
            or gap["last_trusted_event_hash"] != record["restored_last_event_hash"]
            or record["continuity_gap_ref"] != gap["gap_id"]
        ):
            return "continuity_gap_range_invalid"
    elif record["continuity_status"] != "complete" or gap is not None:
        return "unexpected_continuity_gap"

    if finalization["finalization_digest"] != compute_recovery_finalization_digest(finalization):
        return "recovery_finalization_digest_mismatch"
    expected_gap_digest = None if gap is None else gap["gap_digest"]
    if (
        finalization["backup_commit_digest"] != commit["commit_digest"]
        or finalization["recovery_record_digest"] != record["recovery_digest"]
        or finalization["continuity_gap_digest"] != expected_gap_digest
        or finalization["previous_body_revocation_digest"] != revocation["revocation_digest"]
        or finalization["destination_registration_digest"] != registration["registration_digest"]
        or finalization["destination_possession_digest"] != possession["proof_digest"]
        or finalization["guardian_authorization_ref"] != authorization["authorization_id"]
        or finalization["recovery_event_hash"] != recovery_event["event_hash"]
    ):
        return "recovery_finalization_links_invalid"

    active = [body for body in registry["bodies"] if body["status"] == "active_writer"]
    previous = next((body for body in registry["bodies"] if body["body_id"] == record["previous_body_id"]), None)
    if len(active) != 1 or active[0]["body_id"] != record["new_body_id"]:
        return "recovery_final_registry_authority_invalid"
    if previous is None or previous["status"] not in {"lost", "revoked"}:
        return "recovery_previous_body_still_authoritative"
    if previous["status"] != finalization["previous_body_status"]:
        return "recovery_finalization_status_mismatch"
    if finalization["final_body_registry_digest"] != registry["registry_digest"]:
        return "recovery_final_registry_digest_mismatch"
    if (
        recovery_event["body_id"] != record["new_body_id"]
        or recovery_event["sequence"] != record["last_known_sequence"] + 1
        or recovery_event["previous_event_hash"] != record["restored_last_event_hash"]
    ):
        return "recovery_event_continuity_invalid"

    return None

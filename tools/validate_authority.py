#!/usr/bin/env python3
"""Reglas auxiliares para autoridad del guardián y movilidad.

La norma vive en ``spec/``. Este módulo concentra una sola implementación de las
reglas que usan tanto la simulación positiva como las pruebas negativas.
"""

from __future__ import annotations

from datetime import datetime

from validate_workspace import hash_fields

AUTHORIZATION_DOMAIN = "genesis.guardian.authorization.v0.1"
DEVICE_REGISTRATION_DOMAIN = "genesis.guardian.device.registration.v0.1"
AUTHORITY_EVENT_DOMAIN = "genesis.guardian.authority.event.v0.1"
AUTHORIZATION_USE_DOMAIN = "genesis.guardian.authorization.use.v0.1"


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def compute_device_registration_digest(registration: dict) -> str:
    return hash_fields(
        DEVICE_REGISTRATION_DOMAIN,
        [
            registration["schema_version"],
            registration["registration_id"],
            registration["guardian_id"],
            registration["guardian_key_epoch_id"],
            registration["instance_id"],
            str(registration["authority_epoch"]),
            registration["body_id"],
            registration["platform_profile"],
            registration["public_key_fingerprint"],
            registration["registered_at"],
        ],
    )


def compute_authorization_digest(authorization: dict) -> str:
    destinations = sorted(
        authorization["destination_body_ids"],
        key=lambda value: value.encode("utf-8"),
    )
    fields = [
        authorization["schema_version"],
        authorization["authorization_id"],
        authorization["guardian_id"],
        authorization["guardian_key_epoch_id"],
        authorization["instance_id"],
        str(authorization["authority_epoch"]),
        authorization["permission"],
        authorization["mode"],
        optional_text(authorization["source_body_id"]),
        authorization["destination_scope"],
        str(len(destinations)),
        *destinations,
        authorization["issued_at"],
        authorization["not_before"],
        optional_text(authorization["expires_at"]),
        optional_text(authorization["use_limit"]),
    ]
    return hash_fields(AUTHORIZATION_DOMAIN, fields)


def compute_authorization_use_digest(
    authorization_id: str,
    transfer_id: str,
    source_body_id: str,
    destination_body_id: str,
) -> str:
    return hash_fields(
        AUTHORIZATION_USE_DOMAIN,
        [authorization_id, transfer_id, source_body_id, destination_body_id],
    )


def compute_authority_event_hash(event: dict) -> str:
    return hash_fields(
        AUTHORITY_EVENT_DOMAIN,
        [
            event["schema_version"],
            event["ledger_id"],
            event["event_id"],
            str(event["sequence"]),
            event["previous_event_hash"],
            event["guardian_id"],
            event["instance_id"],
            str(event["authority_epoch"]),
            event["event_type"],
            optional_text(event["authorization_ref"]),
            optional_text(event["body_id"]),
            optional_text(event["transfer_id"]),
            event["subject_digest"],
            event["recorded_at"],
        ],
    )


def validate_authority_ledger(events: list[dict]) -> str | None:
    if not events:
        return "authority_ledger_empty"

    ledger_id = events[0]["ledger_id"]
    guardian_id = events[0]["guardian_id"]
    instance_id = events[0]["instance_id"]
    previous = "GENESIS"
    previous_epoch = -1

    for expected_sequence, event in enumerate(events):
        if event["sequence"] != expected_sequence:
            return "authority_ledger_sequence_invalid"
        if event["previous_event_hash"] != previous:
            return "authority_ledger_chain_broken"
        if event["event_hash"] != compute_authority_event_hash(event):
            return "authority_event_hash_mismatch"
        if event["ledger_id"] != ledger_id:
            return "authority_ledger_id_mismatch"
        if event["guardian_id"] != guardian_id:
            return "authority_guardian_mismatch"
        if event["instance_id"] != instance_id:
            return "authority_instance_mismatch"
        if event["authority_epoch"] < previous_epoch:
            return "authority_epoch_regression"
        if previous_epoch >= 0 and event["authority_epoch"] > previous_epoch:
            if (
                event["event_type"] != "authority.epoch.rotated"
                or event["authority_epoch"] != previous_epoch + 1
            ):
                return "authority_epoch_change_without_rotation"
        previous = event["event_hash"]
        previous_epoch = event["authority_epoch"]
    return None


def evaluate_mobility_authorization(
    authorization: dict | None,
    ledger_events: list[dict],
    device_registrations: list[dict],
    *,
    instance_id: str,
    source_body_id: str,
    destination_body_id: str,
    transfer_id: str,
    evaluated_at: str,
) -> str | None:
    """Devuelve ``None`` si la transferencia está autorizada; si no, un código estable."""

    if authorization is None:
        return "authorization_missing"

    ledger_error = validate_authority_ledger(ledger_events)
    if ledger_error:
        return ledger_error

    if authorization["authorization_digest"] != compute_authorization_digest(authorization):
        return "authorization_digest_mismatch"
    if authorization["instance_id"] != instance_id:
        return "authorization_instance_mismatch"
    if authorization["permission"] != "mobility.transfer":
        return "authorization_action_denied"
    if authorization["guardian_id"] != ledger_events[0]["guardian_id"]:
        return "authorization_guardian_mismatch"

    evaluated = parse_utc(evaluated_at)
    if evaluated < parse_utc(authorization["not_before"]):
        return "authorization_not_yet_valid"
    if authorization["expires_at"] is not None:
        if evaluated >= parse_utc(authorization["expires_at"]):
            return "authorization_expired"

    relevant_events = ledger_events
    active_authority_epoch = max(event["authority_epoch"] for event in relevant_events)
    if authorization["authority_epoch"] != active_authority_epoch:
        return "authorization_epoch_inactive"
    granted = any(
        event["event_type"] == "authorization.granted"
        and event["authorization_ref"] == authorization["authorization_id"]
        and event["subject_digest"] == authorization["authorization_digest"]
        and event["authority_epoch"] == active_authority_epoch
        for event in relevant_events
    )
    if not granted:
        return "authorization_not_granted"

    revoked = any(
        event["event_type"] == "authorization.revoked"
        and event["authorization_ref"] == authorization["authorization_id"]
        for event in relevant_events
    )
    if revoked:
        return "authorization_revoked"

    registration = next(
        (
            item
            for item in device_registrations
            if item["body_id"] == destination_body_id
            and item["instance_id"] == instance_id
            and item["guardian_id"] == authorization["guardian_id"]
            and item["authority_epoch"] == active_authority_epoch
        ),
        None,
    )
    if registration is None:
        return "destination_not_registered"
    if registration["registration_digest"] != compute_device_registration_digest(registration):
        return "device_registration_digest_mismatch"

    registration_recorded = any(
        event["event_type"] == "device.registered"
        and event["body_id"] == destination_body_id
        and event["subject_digest"] == registration["registration_digest"]
        and event["authority_epoch"] == active_authority_epoch
        for event in relevant_events
    )
    if not registration_recorded:
        return "device_registration_not_recorded"

    device_revoked = any(
        event["event_type"] == "device.revoked"
        and event["body_id"] == destination_body_id
        for event in relevant_events
    )
    if device_revoked:
        return "destination_device_revoked"

    if authorization["source_body_id"] is not None:
        if authorization["source_body_id"] != source_body_id:
            return "authorization_source_mismatch"

    if authorization["destination_scope"] == "specific_bodies":
        if destination_body_id not in authorization["destination_body_ids"]:
            return "authorization_destination_denied"
    elif authorization["destination_scope"] != "registered_guardian_devices":
        return "authorization_scope_invalid"

    consumed = [
        event
        for event in relevant_events
        if event["event_type"] == "authorization.consumed"
        and event["authorization_ref"] == authorization["authorization_id"]
    ]
    if any(event["transfer_id"] == transfer_id for event in consumed):
        return "transfer_id_already_consumed"
    if authorization["mode"] == "one_time":
        if len(consumed) >= authorization["use_limit"]:
            return "authorization_use_limit_reached"
    elif authorization["mode"] != "standing":
        return "authorization_mode_invalid"

    return None

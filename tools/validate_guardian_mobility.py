#!/usr/bin/env python3
"""Valida autorizaciones de movilidad del Guardian sin propiedad ni encierro."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import unicodedata

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "guardian_mobility_vectors.json"
MAX_INT = 9007199254740991
TS_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

AUTHORIZATION_DOMAIN = "genesis.guardian.mobility.authorization.v0.2"
AUTHORIZATION_SIGNATURE_DOMAIN = "genesis.guardian.mobility.authorization.signature.v0.2"
EVENT_DOMAIN = "genesis.guardian.mobility.authority.event.v0.2"
EVENT_SIGNATURE_DOMAIN = "genesis.guardian.mobility.authority.event.signature.v0.2"
ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1"

GUARDIAN_SEED = bytes([0xC3]) * 32
SOURCE_SEED = bytes([0xA1]) * 32
DESTINATION_SEED = bytes([0xB2]) * 32
GUARDIAN_ID = "guardian_01HMOBILITY000000001"
GUARDIAN_EPOCH = "epoch_01HMOBILITY_GUARDIAN01"
SOURCE_BODY = "body_01HNEUTRAL00000000000001"
SOURCE_EPOCH = "epoch_01HNEUTRAL000000000001"
DESTINATION_BODY = "body_01HNEUTRAL00000000000002"
DESTINATION_EPOCH = "epoch_01HNEUTRAL000000000002"
INSTANCE_ID = "inst_01HNEUTRAL00000000000001"

SIGNATURE_FIELDS = {
    "schema_version", "signature_profile", "signer_type", "signer_id",
    "key_epoch_id", "signed_domain", "signed_digest", "signature_value",
    "created_at", "public_key_ref",
}
AUTHORIZATION_FIELDS = {
    "schema_version", "hash_profile", "authorization_id", "instance_id",
    "guardian_id", "guardian_key_epoch_id", "authority_epoch", "mode",
    "scope", "transfer_id", "source_body_id", "destination_body_id",
    "valid_from", "expires_at", "issued_at", "reservation_ttl_seconds",
    "ownership_conferred", "identity_mutation_allowed", "memory_mutation_allowed",
    "authorization_digest", "signature",
}
EVENT_FIELDS = {
    "schema_version", "event_id", "authorization_id", "authorization_digest",
    "instance_id", "authority_epoch", "sequence", "previous_event_digest",
    "event_type", "transfer_id", "source_body_id", "destination_body_id",
    "reservation_expires_at", "occurred_at", "event_digest", "signature",
}
REQUEST_FIELDS = {
    "authorization_id", "reservation_event_id", "transfer_id", "instance_id",
    "source_body_id", "destination_body_id", "authority_epoch", "prepared_at",
    "finalized_at", "host_consent_verified",
}


class MobilityError(ValueError):
    pass


def fail(code: str) -> None:
    raise MobilityError(code)


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        fail("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        fail("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def hash_fields(domain: str, fields: list[str]) -> str:
    return "sha256:" + hashlib.sha256(
        encode_field(domain) + b"".join(encode_field(value) for value in fields)
    ).hexdigest()


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not TS_RE.fullmatch(value):
        fail(code)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def exact_fields(value: object, expected: set[str], code: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def key_fingerprint(key: SigningKey | VerifyKey) -> str:
    verify_key = key.verify_key if isinstance(key, SigningKey) else key
    return "sha256:" + hashlib.sha256(verify_key.encode()).hexdigest()


def signature_bytes(envelope: dict) -> bytes:
    return encode_field(ENVELOPE_DOMAIN) + b"".join(
        encode_field(envelope[field])
        for field in [
            "schema_version", "signature_profile", "signer_type", "signer_id",
            "key_epoch_id", "signed_domain", "signed_digest", "created_at",
            "public_key_ref",
        ]
    )


def make_signature(
    key: SigningKey,
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
        "signature_profile": "genesis.signature.ed25519.v0.1",
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key_epoch_id,
        "signed_domain": domain,
        "signed_digest": digest,
        "created_at": created_at,
        "public_key_ref": key_fingerprint(key),
    }
    envelope["signature_value"] = key.sign(signature_bytes(envelope)).signature.hex()
    return envelope


def verify_signature(
    envelope: object,
    public_keys: dict[str, bytes],
    *,
    digest: str,
    signer_type: str,
    signer_id: str,
    key_epoch_id: str,
    domain: str,
    created_at: str,
    error: str,
) -> None:
    exact_fields(envelope, SIGNATURE_FIELDS, error)
    expected = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": "genesis.signature.ed25519.v0.1",
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key_epoch_id,
        "signed_domain": domain,
        "signed_digest": digest,
        "created_at": created_at,
    }
    if any(envelope.get(field) != value for field, value in expected.items()):
        fail(error)
    raw_key = public_keys.get(envelope.get("public_key_ref"))
    if raw_key is None or not isinstance(envelope.get("signature_value"), str) or not HEX128_RE.fullmatch(envelope["signature_value"]):
        fail(error)
    if "sha256:" + hashlib.sha256(raw_key).hexdigest() != envelope["public_key_ref"]:
        fail(error)
    try:
        VerifyKey(raw_key).verify(signature_bytes(envelope), bytes.fromhex(envelope["signature_value"]))
    except (BadSignatureError, ValueError):
        fail(error)


def compute_authorization_digest(item: dict) -> str:
    return hash_fields(AUTHORIZATION_DOMAIN, [
        item["schema_version"], item["hash_profile"], item["authorization_id"],
        item["instance_id"], item["guardian_id"], item["guardian_key_epoch_id"],
        str(item["authority_epoch"]), item["mode"], item["scope"],
        optional_text(item["transfer_id"]), optional_text(item["source_body_id"]),
        optional_text(item["destination_body_id"]), item["valid_from"],
        item["expires_at"], item["issued_at"], str(item["reservation_ttl_seconds"]),
        bool_text(item["ownership_conferred"]), bool_text(item["identity_mutation_allowed"]),
        bool_text(item["memory_mutation_allowed"]),
    ])


def compute_authority_event_digest(item: dict) -> str:
    return hash_fields(EVENT_DOMAIN, [
        item["schema_version"], item["event_id"], item["authorization_id"],
        item["authorization_digest"], item["instance_id"], str(item["authority_epoch"]),
        str(item["sequence"]), item["previous_event_digest"], item["event_type"],
        optional_text(item["transfer_id"]), optional_text(item["source_body_id"]),
        optional_text(item["destination_body_id"]), optional_text(item["reservation_expires_at"]),
        item["occurred_at"],
    ])


def validate_authorization(item: object, public_keys: dict[str, bytes]) -> dict:
    if item is None:
        fail("guardian_authorization_missing")
    authorization = exact_fields(item, AUTHORIZATION_FIELDS, "guardian_authorization_fields_invalid")
    if authorization["schema_version"] != "genesis.guardian.mobility.authorization.v0.2" or authorization["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("guardian_authorization_profile_invalid")
    if type(authorization["authority_epoch"]) is not int or not 0 <= authorization["authority_epoch"] <= MAX_INT:
        fail("guardian_authority_epoch_invalid")
    ttl = authorization["reservation_ttl_seconds"]
    if type(ttl) is not int or not 60 <= ttl <= 86400:
        fail("guardian_reservation_ttl_invalid")
    issued = parse_time(authorization["issued_at"], "guardian_authorization_time_invalid")
    valid_from = parse_time(authorization["valid_from"], "guardian_authorization_time_invalid")
    expires = parse_time(authorization["expires_at"], "guardian_authorization_time_invalid")
    if issued > valid_from or valid_from >= expires:
        fail("guardian_authorization_window_invalid")
    if (
        authorization["ownership_conferred"] is not False
        or authorization["identity_mutation_allowed"] is not False
        or authorization["memory_mutation_allowed"] is not False
    ):
        fail("guardian_authorization_rights_boundary_invalid")
    if authorization["mode"] == "one_time":
        if authorization["scope"] != "exact_transfer" or any(
            not isinstance(authorization[field], str)
            for field in ["transfer_id", "source_body_id", "destination_body_id"]
        ):
            fail("guardian_authorization_mode_scope_invalid")
    elif authorization["mode"] == "standing":
        if authorization["scope"] != "any_registered_body_with_host_consent" or any(
            authorization[field] is not None
            for field in ["transfer_id", "source_body_id", "destination_body_id"]
        ):
            fail("guardian_authorization_mode_scope_invalid")
    else:
        fail("guardian_authorization_mode_scope_invalid")
    if not isinstance(authorization["authorization_digest"], str) or not SHA_RE.fullmatch(authorization["authorization_digest"]):
        fail("guardian_authorization_digest_invalid")
    if compute_authorization_digest(authorization) != authorization["authorization_digest"]:
        fail("guardian_authorization_digest_mismatch")
    verify_signature(
        authorization["signature"], public_keys,
        digest=authorization["authorization_digest"], signer_type="guardian",
        signer_id=authorization["guardian_id"], key_epoch_id=authorization["guardian_key_epoch_id"],
        domain=AUTHORIZATION_SIGNATURE_DOMAIN, created_at=authorization["issued_at"],
        error="guardian_authorization_signature_invalid",
    )
    return authorization


def validate_event_chain(events: object, authorization: dict, public_keys: dict[str, bytes]) -> list[dict]:
    if not isinstance(events, list):
        fail("guardian_authority_events_invalid")
    previous = "GENESIS"
    event_ids: set[str] = set()
    reservation_transfers: set[str] = set()
    validated: list[dict] = []
    for sequence, raw_event in enumerate(events):
        event = exact_fields(raw_event, EVENT_FIELDS, "guardian_authority_event_fields_invalid")
        if event["schema_version"] != "genesis.guardian.mobility.authority.event.v0.2":
            fail("guardian_authority_event_profile_invalid")
        if event["event_id"] in event_ids:
            fail("guardian_authority_event_duplicate")
        event_ids.add(event["event_id"])
        if event["sequence"] != sequence or event["previous_event_digest"] != previous:
            fail("guardian_authority_event_chain_invalid")
        if (
            event["authorization_id"] != authorization["authorization_id"]
            or event["authorization_digest"] != authorization["authorization_digest"]
            or event["instance_id"] != authorization["instance_id"]
            or event["authority_epoch"] != authorization["authority_epoch"]
        ):
            fail("guardian_authority_event_binding_invalid")
        parse_time(event["occurred_at"], "guardian_authority_event_time_invalid")
        if event["event_type"] in {"reserved", "consumed"}:
            if any(not isinstance(event[field], str) for field in ["transfer_id", "source_body_id", "destination_body_id"]):
                fail("guardian_authority_event_scope_invalid")
            if event["event_type"] == "reserved":
                if not isinstance(event["reservation_expires_at"], str):
                    fail("guardian_authority_event_scope_invalid")
                parse_time(event["reservation_expires_at"], "guardian_authority_event_time_invalid")
                if event["transfer_id"] in reservation_transfers:
                    fail("guardian_authorization_replay")
                reservation_transfers.add(event["transfer_id"])
                signer_type, signer_id = "body", event["source_body_id"]
            else:
                if event["reservation_expires_at"] is not None:
                    fail("guardian_authority_event_scope_invalid")
                signer_type, signer_id = "body", event["destination_body_id"]
        elif event["event_type"] == "revoked":
            if any(event[field] is not None for field in ["transfer_id", "source_body_id", "destination_body_id", "reservation_expires_at"]):
                fail("guardian_authority_event_scope_invalid")
            signer_type, signer_id = "guardian", authorization["guardian_id"]
        else:
            fail("guardian_authority_event_type_invalid")
        if not isinstance(event["event_digest"], str) or compute_authority_event_digest(event) != event["event_digest"]:
            fail("guardian_authority_event_digest_mismatch")
        expected_epoch = authorization["guardian_key_epoch_id"] if signer_type == "guardian" else event["signature"].get("key_epoch_id")
        verify_signature(
            event["signature"], public_keys, digest=event["event_digest"], signer_type=signer_type,
            signer_id=signer_id, key_epoch_id=expected_epoch, domain=EVENT_SIGNATURE_DOMAIN,
            created_at=event["occurred_at"], error="guardian_authority_event_signature_invalid",
        )
        previous = event["event_digest"]
        validated.append(event)
    return validated


def validate_transfer_authorization(
    authorization: object,
    events: object,
    request: object,
    public_keys: dict[str, bytes],
) -> dict:
    grant = validate_authorization(authorization, public_keys)
    exact_fields(request, REQUEST_FIELDS, "guardian_mobility_request_fields_invalid")
    if (
        request["authorization_id"] != grant["authorization_id"]
        or request["instance_id"] != grant["instance_id"]
    ):
        fail("guardian_authorization_instance_mismatch")
    if request["authority_epoch"] != grant["authority_epoch"]:
        fail("guardian_authority_epoch_mismatch")
    prepared = parse_time(request["prepared_at"], "guardian_mobility_request_time_invalid")
    finalized = parse_time(request["finalized_at"], "guardian_mobility_request_time_invalid")
    if finalized < prepared:
        fail("guardian_mobility_request_time_invalid")
    if not (parse_time(grant["valid_from"], "guardian_authorization_time_invalid") <= prepared < parse_time(grant["expires_at"], "guardian_authorization_time_invalid")):
        fail("guardian_authorization_expired")
    if request["host_consent_verified"] is not True:
        fail("guardian_host_consent_required")
    if grant["mode"] == "one_time" and any(
        request[field] != grant[field]
        for field in ["transfer_id", "source_body_id", "destination_body_id"]
    ):
        fail("guardian_authorization_scope_mismatch")

    ledger = validate_event_chain(events, grant, public_keys)
    revocations = [event for event in ledger if event["event_type"] == "revoked"]
    if any(parse_time(event["occurred_at"], "guardian_authority_event_time_invalid") <= prepared for event in revocations):
        fail("guardian_authorization_revoked")
    reservations = [
        event for event in ledger
        if event["event_type"] == "reserved"
        and event["event_id"] == request["reservation_event_id"]
        and all(event[field] == request[field] for field in ["transfer_id", "source_body_id", "destination_body_id"])
    ]
    if len(reservations) != 1:
        fail("guardian_authorization_reservation_missing")
    reservation = reservations[0]
    reserved_at = parse_time(reservation["occurred_at"], "guardian_authority_event_time_invalid")
    reservation_expires = parse_time(reservation["reservation_expires_at"], "guardian_authority_event_time_invalid")
    if reserved_at > prepared or reservation_expires <= reserved_at:
        fail("guardian_authorization_reservation_window_invalid")
    if (reservation_expires - reserved_at).total_seconds() > grant["reservation_ttl_seconds"]:
        fail("guardian_authorization_reservation_window_invalid")
    if reservation_expires > parse_time(grant["expires_at"], "guardian_authorization_time_invalid"):
        fail("guardian_authorization_reservation_window_invalid")
    if any(parse_time(event["occurred_at"], "guardian_authority_event_time_invalid") <= reserved_at for event in revocations):
        fail("guardian_authorization_revoked")
    if finalized > reservation_expires:
        fail("guardian_authorization_reservation_expired")

    consumptions = [
        event for event in ledger
        if event["event_type"] == "consumed"
        and all(event[field] == request[field] for field in ["transfer_id", "source_body_id", "destination_body_id"])
    ]
    if len(consumptions) != 1:
        fail("guardian_authorization_consumption_missing")
    consumed_at = parse_time(consumptions[0]["occurred_at"], "guardian_authority_event_time_invalid")
    if not finalized <= consumed_at <= reservation_expires:
        fail("guardian_authorization_consumption_time_invalid")
    if grant["mode"] == "one_time":
        if len([event for event in ledger if event["event_type"] == "reserved"]) != 1 or len([event for event in ledger if event["event_type"] == "consumed"]) != 1:
            fail("guardian_authorization_one_time_already_used")
    return {
        "authorization_id": grant["authorization_id"],
        "authorization_digest": grant["authorization_digest"],
        "reservation_event_id": reservation["event_id"],
        "reservation_event_digest": reservation["event_digest"],
        "mode": grant["mode"],
        "transfer_id": request["transfer_id"],
    }


def build_authorization(*, mode: str, authorization_id: str, transfer_id: str | None) -> dict:
    guardian_key = SigningKey(GUARDIAN_SEED)
    exact = mode == "one_time"
    item = {
        "schema_version": "genesis.guardian.mobility.authorization.v0.2",
        "hash_profile": "genesis.hash.fields.v0.1",
        "authorization_id": authorization_id,
        "instance_id": INSTANCE_ID,
        "guardian_id": GUARDIAN_ID,
        "guardian_key_epoch_id": GUARDIAN_EPOCH,
        "authority_epoch": 7,
        "mode": mode,
        "scope": "exact_transfer" if exact else "any_registered_body_with_host_consent",
        "transfer_id": transfer_id if exact else None,
        "source_body_id": SOURCE_BODY if exact else None,
        "destination_body_id": DESTINATION_BODY if exact else None,
        "valid_from": "2026-07-12T00:00:00Z",
        "expires_at": "2026-07-13T00:00:00Z",
        "issued_at": "2026-07-12T00:00:00Z",
        "reservation_ttl_seconds": 900,
        "ownership_conferred": False,
        "identity_mutation_allowed": False,
        "memory_mutation_allowed": False,
    }
    item["authorization_digest"] = compute_authorization_digest(item)
    item["signature"] = make_signature(
        guardian_key, item["authorization_digest"], signer_type="guardian",
        signer_id=GUARDIAN_ID, key_epoch_id=GUARDIAN_EPOCH,
        domain=AUTHORIZATION_SIGNATURE_DOMAIN, created_at=item["issued_at"],
    )
    return item


def append_event(
    events: list[dict], authorization: dict, *, event_id: str, event_type: str,
    transfer_id: str | None, occurred_at: str, reservation_expires_at: str | None = None,
) -> dict:
    if event_type == "reserved":
        key, signer_type, signer_id, epoch = SigningKey(SOURCE_SEED), "body", SOURCE_BODY, SOURCE_EPOCH
        source, destination = SOURCE_BODY, DESTINATION_BODY
    elif event_type == "consumed":
        key, signer_type, signer_id, epoch = SigningKey(DESTINATION_SEED), "body", DESTINATION_BODY, DESTINATION_EPOCH
        source, destination = SOURCE_BODY, DESTINATION_BODY
    else:
        key, signer_type, signer_id, epoch = SigningKey(GUARDIAN_SEED), "guardian", GUARDIAN_ID, GUARDIAN_EPOCH
        source = destination = None
    event = {
        "schema_version": "genesis.guardian.mobility.authority.event.v0.2",
        "event_id": event_id,
        "authorization_id": authorization["authorization_id"],
        "authorization_digest": authorization["authorization_digest"],
        "instance_id": authorization["instance_id"],
        "authority_epoch": authorization["authority_epoch"],
        "sequence": len(events),
        "previous_event_digest": events[-1]["event_digest"] if events else "GENESIS",
        "event_type": event_type,
        "transfer_id": transfer_id if event_type != "revoked" else None,
        "source_body_id": source,
        "destination_body_id": destination,
        "reservation_expires_at": reservation_expires_at if event_type == "reserved" else None,
        "occurred_at": occurred_at,
    }
    event["event_digest"] = compute_authority_event_digest(event)
    event["signature"] = make_signature(
        key, event["event_digest"], signer_type=signer_type, signer_id=signer_id,
        key_epoch_id=epoch, domain=EVENT_SIGNATURE_DOMAIN, created_at=occurred_at,
    )
    events.append(event)
    return event


def build_scenario(*, mode: str, suffix: str, revoked_after: bool = False) -> dict:
    transfer_id = f"transfer_01HMOBILITY_{suffix}_0001"
    authorization = build_authorization(
        mode=mode, authorization_id=f"authorization_01HMOBILITY_{suffix}_01",
        transfer_id=transfer_id,
    )
    events: list[dict] = []
    reservation = append_event(
        events, authorization, event_id=f"mobevent_01HMOBILITY_{suffix}_RESERVE",
        event_type="reserved", transfer_id=transfer_id, occurred_at="2026-07-12T01:00:00Z",
        reservation_expires_at="2026-07-12T01:15:00Z",
    )
    append_event(
        events, authorization, event_id=f"mobevent_01HMOBILITY_{suffix}_CONSUME",
        event_type="consumed", transfer_id=transfer_id, occurred_at="2026-07-12T01:10:00Z",
    )
    if revoked_after:
        append_event(
            events, authorization, event_id=f"mobevent_01HMOBILITY_{suffix}_REVOKE",
            event_type="revoked", transfer_id=None, occurred_at="2026-07-12T02:00:00Z",
        )
    request = {
        "authorization_id": authorization["authorization_id"],
        "reservation_event_id": reservation["event_id"],
        "transfer_id": transfer_id,
        "instance_id": INSTANCE_ID,
        "source_body_id": SOURCE_BODY,
        "destination_body_id": DESTINATION_BODY,
        "authority_epoch": 7,
        "prepared_at": "2026-07-12T01:01:00Z",
        "finalized_at": "2026-07-12T01:10:00Z",
        "host_consent_verified": True,
    }
    return {"authorization": authorization, "events": events, "request": request}


def _resign_event_chain(events: list[dict], authorization: dict) -> None:
    previous = "GENESIS"
    for sequence, event in enumerate(events):
        event["sequence"] = sequence
        event["previous_event_digest"] = previous
        event["event_digest"] = compute_authority_event_digest(event)
        if event["event_type"] == "reserved":
            key, signer_type, signer_id, epoch = SigningKey(SOURCE_SEED), "body", SOURCE_BODY, SOURCE_EPOCH
        elif event["event_type"] == "consumed":
            key, signer_type, signer_id, epoch = SigningKey(DESTINATION_SEED), "body", DESTINATION_BODY, DESTINATION_EPOCH
        else:
            key, signer_type, signer_id, epoch = SigningKey(GUARDIAN_SEED), "guardian", GUARDIAN_ID, GUARDIAN_EPOCH
        event["signature"] = make_signature(
            key, event["event_digest"], signer_type=signer_type, signer_id=signer_id,
            key_epoch_id=epoch, domain=EVENT_SIGNATURE_DOMAIN, created_at=event["occurred_at"],
        )
        previous = event["event_digest"]


def build_vector() -> dict:
    one_time = build_scenario(mode="one_time", suffix="ONE_TIME")
    standing = build_scenario(mode="standing", suffix="STANDING", revoked_after=True)
    negative_cases: list[dict] = []

    def add(case_id: str, expected_error: str, scenario: dict) -> None:
        negative_cases.append({"case_id": case_id, "expected_error": expected_error, **scenario})

    case = deepcopy(one_time); case["authorization"] = None
    add("missing-guardian-authorization", "guardian_authorization_missing", case)
    case = deepcopy(one_time); case["authorization"]["signature"]["signature_value"] = "00" * 64
    add("forged-guardian-signature", "guardian_authorization_signature_invalid", case)
    case = deepcopy(one_time); case["request"]["instance_id"] = "inst_01HOTHER00000000000000001"
    add("wrong-instance", "guardian_authorization_instance_mismatch", case)
    case = deepcopy(one_time); case["request"]["authority_epoch"] = 6
    add("stale-authority-epoch", "guardian_authority_epoch_mismatch", case)
    case = deepcopy(one_time); case["request"]["prepared_at"] = "2026-07-13T00:00:00Z"; case["request"]["finalized_at"] = "2026-07-13T00:00:01Z"
    add("expired-authorization", "guardian_authorization_expired", case)
    for field, value, name in [
        ("transfer_id", "transfer_01HMOBILITY_WRONG_0001", "wrong-transfer"),
        ("source_body_id", "body_01HMOBILITY_WRONG_SOURCE", "wrong-source-body"),
        ("destination_body_id", "body_01HMOBILITY_WRONG_DESTINATION", "wrong-destination-body"),
    ]:
        case = deepcopy(one_time); case["request"][field] = value
        add(name, "guardian_authorization_scope_mismatch", case)
    case = deepcopy(one_time); case["events"][0]["signature"]["signature_value"] = "00" * 64
    add("forged-reservation-signature", "guardian_authority_event_signature_invalid", case)
    case = deepcopy(one_time); case["events"][1]["signature"]["signature_value"] = "00" * 64
    add("forged-consumption-signature", "guardian_authority_event_signature_invalid", case)
    case = deepcopy(one_time); case["request"]["finalized_at"] = "2026-07-12T01:15:01Z"
    add("reservation-expired-before-finalization", "guardian_authorization_reservation_expired", case)
    case = deepcopy(one_time); case["request"]["host_consent_verified"] = False
    add("missing-host-consent", "guardian_host_consent_required", case)
    case = deepcopy(one_time)
    append_event(
        case["events"], case["authorization"], event_id="mobevent_01HMOBILITY_REPLAY_RESERVE",
        event_type="reserved", transfer_id=case["request"]["transfer_id"], occurred_at="2026-07-12T01:11:00Z",
        reservation_expires_at="2026-07-12T01:20:00Z",
    )
    add("one-time-replay", "guardian_authorization_replay", case)
    case = deepcopy(standing); case["request"]["prepared_at"] = "2026-07-12T02:00:00Z"; case["request"]["finalized_at"] = "2026-07-12T02:01:00Z"
    add("standing-grant-revoked-for-new-transfer", "guardian_authorization_revoked", case)
    case = deepcopy(one_time); case["authorization"]["ownership_conferred"] = True
    add("authorization-claims-ownership", "guardian_authorization_rights_boundary_invalid", case)

    keys = [SigningKey(GUARDIAN_SEED), SigningKey(SOURCE_SEED), SigningKey(DESTINATION_SEED)]
    public_keys = {key_fingerprint(key): key.verify_key.encode().hex() for key in keys}
    return {
        "profile": "genesis.guardian.mobility.conformance.v0.2",
        "status": "draft",
        "test_public_keys": public_keys,
        "positive_cases": [
            {"case_id": "one-time-exact-transfer", **one_time},
            {"case_id": "standing-reserved-before-prospective-revocation", **standing},
        ],
        "negative_cases": negative_cases,
        "expected": {
            "positive_case_count": 2,
            "negative_case_count": len(negative_cases),
            "one_time_authorization_digest": one_time["authorization"]["authorization_digest"],
            "standing_authorization_digest": standing["authorization"]["authorization_digest"],
        },
    }


def validate_vector(vector: dict) -> None:
    if vector.get("profile") != "genesis.guardian.mobility.conformance.v0.2":
        fail("guardian_mobility_vector_profile_invalid")
    public_keys = {ref: bytes.fromhex(raw) for ref, raw in vector["test_public_keys"].items()}
    for case in vector["positive_cases"]:
        validate_transfer_authorization(case["authorization"], case["events"], case["request"], public_keys)
    for case in vector["negative_cases"]:
        actual = None
        try:
            validate_transfer_authorization(case["authorization"], case["events"], case["request"], public_keys)
        except MobilityError as error:
            actual = str(error)
        if actual != case["expected_error"]:
            fail(f"guardian_mobility_negative_mismatch:{case['case_id']}:expected={case['expected_error']}:actual={actual}")
    expected = vector["expected"]
    if (
        expected["positive_case_count"] != len(vector["positive_cases"])
        or expected["negative_case_count"] != len(vector["negative_cases"])
        or expected["one_time_authorization_digest"] != vector["positive_cases"][0]["authorization"]["authorization_digest"]
        or expected["standing_authorization_digest"] != vector["positive_cases"][1]["authorization"]["authorization_digest"]
    ):
        fail("guardian_mobility_expected_summary_invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-vector", action="store_true")
    args = parser.parse_args()
    if args.write_vector:
        VECTOR_PATH.write_text(json.dumps(build_vector(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    validate_vector(vector)
    print(f"OK Guardian mobility authorizations ({vector['expected']['positive_case_count']} modes)")
    print(f"OK Guardian mobility negative cases ({vector['expected']['negative_case_count']})")
    print("NOTE mobility authorization never grants ownership or identity/memory mutation.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, MobilityError) as error:
        print(f"FAIL Guardian mobility: {error}")
        raise SystemExit(1)

#!/usr/bin/env python3
"""Reference validator for Genesis Ultra continuity hashes.

Auxiliary implementation only. The normative field order lives in
spec/CONTINUITY_HASHES.md.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "continuity_vectors.json"


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def hash_fields(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def safe_relative_path(value: str) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if unicodedata.normalize("NFC", value) != value:
        return False
    if value.startswith("/") or "\\" in value:
        return False
    if re.match(r"^[A-Za-z]:", value):
        return False
    segments = value.split("/")
    return not any(segment in {"", ".", ".."} for segment in segments)


def compute_body_registry(case: dict) -> str:
    data = case["input"]
    bodies = data["bodies"]
    ids = [body["body_id"] for body in bodies]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_body_id")
    active = sum(1 for body in bodies if body["status"] == "active_writer")
    if active > 1:
        raise ValueError("multiple_active_writers")

    fields = [
        data["schema_version"],
        data["instance_id"],
        str(data["registry_epoch"]),
        str(len(bodies)),
    ]
    for body in sorted(bodies, key=lambda item: item["body_id"].encode("utf-8")):
        fields.extend(
            [
                body["body_id"],
                body["status"],
                body["platform_profile"],
                body["public_key_fingerprint"],
                body["created_at"],
                optional_text(body.get("last_seen_at")),
                optional_text(body.get("revocation_ref")),
            ]
        )
    fields.append(data["updated_at"])
    return hash_fields(case["domain"], fields)


def compute_continuity_intent(case: dict) -> str:
    data = case["input"]
    if data["decision_origin"] != "instance":
        raise ValueError("continuity_intent_origin_invalid")
    return hash_fields(
        case["domain"],
        [
            data["schema_version"],
            data["intent_id"],
            data["transfer_id"],
            data["instance_id"],
            data["source_body_id"],
            data["destination_body_id"],
            data["checkpoint_hash"],
            data["last_event_hash"],
            data["decision_origin"],
            data["created_at"],
            data["expires_at"],
        ],
    )


def compute_host_consent(case: dict) -> str:
    data = case["input"]
    if data["resource_scope"] != "destination_body_runtime":
        raise ValueError("host_consent_scope_invalid")
    if data["ownership_claim"] != "none" or data["mobility_veto"] != "none":
        raise ValueError("host_consent_claim_invalid")
    return hash_fields(
        case["domain"],
        [
            data["schema_version"],
            data["consent_id"],
            data["transfer_id"],
            data["host_id"],
            data["host_key_epoch_id"],
            data["instance_id"],
            data["destination_body_id"],
            data["resource_scope"],
            data["granted_at"],
            data["expires_at"],
            data["ownership_claim"],
            data["mobility_veto"],
        ],
    )


def compute_transfer_package(case: dict) -> str:
    data = case["input"]
    contents = data["contents"]
    paths = [item["path"] for item in contents]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate_package_path")
    if any(not safe_relative_path(path) for path in paths):
        raise ValueError("invalid_relative_path")

    fields = [
        data["schema_version"],
        data["transfer_id"],
        data["instance_id"],
        data["source_body_id"],
        optional_text(data.get("destination_body_id")),
        data["mode"],
        data["created_at"],
        data["checkpoint_hash"],
        data["last_event_hash"],
        data["continuity_status"],
        data["continuity_intent_ref"],
        data["host_consent_ref"],
        data["destination_possession_ref"],
        str(len(contents)),
    ]
    for item in sorted(contents, key=lambda value: value["path"].encode("utf-8")):
        fields.extend([item["kind"], item["path"], item["digest"]])
    return hash_fields(case["domain"], fields)


def compute_transfer_receipt(case: dict) -> str:
    data = case["input"]
    if data["continuity_status"] == "known_gap" and not data.get("continuity_gap_ref"):
        raise ValueError("missing_continuity_gap_ref")
    fields = [
        data["schema_version"],
        data["transfer_id"],
        data["instance_id"],
        data["source_body_id"],
        data["destination_body_id"],
        data["accepted_package_digest"],
        data["accepted_checkpoint_hash"],
        data["accepted_last_event_hash"],
        str(data["accepted_last_sequence"]),
        data["accepted_at"],
        data["continuity_status"],
        optional_text(data.get("continuity_gap_ref")),
        data["continuity_intent_ref"],
        data["host_consent_ref"],
        data["destination_possession_ref"],
    ]
    return hash_fields(case["domain"], fields)


def compute_transfer_finalization(case: dict) -> str:
    data = case["input"]
    if data["destination_final_status"] != "active_writer":
        raise ValueError("destination_not_active_writer")
    if data["source_final_status"] not in {"read_only", "revoked", "lost"}:
        raise ValueError("invalid_source_final_status")
    if data["source_body_id"] == data["destination_body_id"]:
        raise ValueError("source_destination_same_body")
    fields = [
        data["schema_version"],
        data["transfer_id"],
        data["instance_id"],
        data["source_body_id"],
        data["destination_body_id"],
        data["receipt_digest"],
        data["source_final_status"],
        data["destination_final_status"],
        data["finalized_at"],
        data["continuity_intent_ref"],
        data["host_consent_ref"],
        data["destination_possession_ref"],
    ]
    return hash_fields(case["domain"], fields)


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    package_actual = compute_transfer_package(vectors["transfer_package"])
    package_expected = vectors["transfer_package"]["expected_package_digest"]

    if vectors["transfer_receipt"]["input"]["accepted_package_digest"] != package_expected:
        print("FAIL receipt_not_linked_to_expected_package")
        return 1

    checks = [
        (
            "continuity_intent",
            compute_continuity_intent(vectors["continuity_intent"]),
            vectors["continuity_intent"]["expected_intent_digest"],
        ),
        (
            "host_consent",
            compute_host_consent(vectors["host_consent"]),
            vectors["host_consent"]["expected_consent_digest"],
        ),
        (
            "body_registry",
            compute_body_registry(vectors["body_registry"]),
            vectors["body_registry"]["expected_registry_digest"],
        ),
        ("transfer_package", package_actual, package_expected),
        (
            "transfer_receipt",
            compute_transfer_receipt(vectors["transfer_receipt"]),
            vectors["transfer_receipt"]["expected_receipt_digest"],
        ),
        (
            "transfer_finalization",
            compute_transfer_finalization(vectors["transfer_finalization"]),
            vectors["transfer_finalization"]["expected_finalization_digest"],
        ),
    ]

    failed = False
    for name, actual, expected in checks:
        if actual == expected:
            print(f"OK {name}")
        else:
            failed = True
            print(f"FAIL {name}")
            print(f"  actual:   {actual}")
            print(f"  expected: {expected}")

    if failed:
        return 1
    print("OK continuity vectors")
    print("NOTE Reference conformance check; not a production security certification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

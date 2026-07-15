#!/usr/bin/env python3
"""Valida la identidad de nacimiento y su nombre canónico inmutable."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "instance_identity_vectors.json"

IDENTITY_FIELDS = {
    "schema_version",
    "instance_id",
    "seed_id",
    "seed_root_hash",
    "companion_name",
    "guardian_id",
    "born_at",
    "identity_digest",
}
DIGEST_FIELDS = [
    "schema_version",
    "instance_id",
    "seed_id",
    "seed_root_hash",
    "companion_name",
    "guardian_id",
    "born_at",
]
CONTINUITY_ERRORS = [
    ("instance_id", "instance_id_mismatch"),
    ("seed_id", "seed_id_mismatch"),
    ("seed_root_hash", "seed_root_hash_mismatch"),
    ("companion_name", "canonical_name_mismatch"),
    ("guardian_id", "guardian_id_mismatch"),
    ("born_at", "birth_timestamp_mismatch"),
]


class ConformanceError(ValueError):
    """Error estable compartido por los vectores de conformidad."""


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ConformanceError("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def hash_fields(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(value) for value in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def validate_text(identity: dict) -> None:
    for value in identity.values():
        if isinstance(value, str) and unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("text_not_nfc")


def validate_identity_fields(identity: dict) -> None:
    validate_text(identity)
    fields = set(identity)
    if fields - IDENTITY_FIELDS:
        raise ConformanceError("identity_additional_field")
    if IDENTITY_FIELDS - fields:
        raise ConformanceError("identity_missing_field")


def compute_identity_digest(identity: dict, domain: str) -> str:
    validate_identity_fields(identity)
    return hash_fields(domain, [identity[field] for field in DIGEST_FIELDS])


def validate_birth_identity(identity: dict, domain: str) -> None:
    if identity.get("schema_version") != domain:
        raise ConformanceError("identity_schema_version_invalid")
    if compute_identity_digest(identity, domain) != identity["identity_digest"]:
        raise ConformanceError("identity_digest_mismatch")


def validate_continuity(trusted_birth: dict, candidate: dict, domain: str) -> None:
    validate_birth_identity(trusted_birth, domain)
    validate_identity_fields(candidate)
    for field, error_code in CONTINUITY_ERRORS:
        if candidate[field] != trusted_birth[field]:
            raise ConformanceError(error_code)
    if compute_identity_digest(candidate, domain) != candidate["identity_digest"]:
        raise ConformanceError("identity_digest_mismatch")
    if candidate["identity_digest"] != trusted_birth["identity_digest"]:
        raise ConformanceError("identity_digest_mismatch")


def evaluate_rejection(test_case: dict, trusted_birth: dict, domain: str) -> str | None:
    candidate = deepcopy(trusted_birth)
    mutation = test_case["mutation"]
    try:
        if "additional_field" in mutation:
            candidate[mutation["additional_field"]] = mutation["value"]
        else:
            candidate[mutation["field"]] = mutation["value"]
            if mutation.get("recompute_digest"):
                candidate["identity_digest"] = compute_identity_digest(candidate, domain)
        validate_continuity(trusted_birth, candidate, domain)
    except ConformanceError as error:
        return str(error)
    return None


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []
    domain = vectors["domain"]
    trusted_birth = vectors["birth_identity"]

    if vectors["profile"] != "genesis.instance.identity.v0.1":
        failures.append("identity_profile_invalid")
    if domain != "genesis.instance.identity.v0.1":
        failures.append("identity_domain_invalid")

    try:
        validate_birth_identity(trusted_birth, domain)
    except ConformanceError as error:
        failures.append(f"birth:{error}")

    expected_profiles = {"android-kotlin", "apple-swift", "windows-dotnet"}
    actual_profiles = {case["platform_profile"] for case in vectors["continuity_cases"]}
    if actual_profiles != expected_profiles:
        failures.append("identity_fixture_platform_set_invalid")
    for case in vectors["continuity_cases"]:
        try:
            validate_continuity(trusted_birth, case["identity"], domain)
        except ConformanceError as error:
            failures.append(f"{case['case_id']}:{error}")

    for test_case in vectors["must_reject"]:
        actual_error = evaluate_rejection(test_case, trusted_birth, domain)
        if actual_error != test_case["expected_error"]:
            failures.append(
                f"{test_case['case_id']}:expected={test_case['expected_error']}:actual={actual_error}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1

    print("OK canonical birth name and identity digest")
    print(
        "OK identical identity across Android, Apple, and Windows declarations "
        f"({len(vectors['continuity_cases'])})"
    )
    print(f"OK immutable identity rejection cases ({len(vectors['must_reject'])})")
    print("NOTE Draft fixtures do not certify platform secure storage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

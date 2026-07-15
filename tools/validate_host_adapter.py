#!/usr/bin/env python3
"""Valida el contrato neutral entre Genesis Core y adaptadores de cuerpo."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "host_adapter_vectors.json"

MANIFEST_FIELDS = {
    "schema_version",
    "adapter_id",
    "adapter_version",
    "platform_profile",
    "protocol_versions",
    "verification_state",
    "capabilities",
    "portability",
}
PORTABLE_IDENTITY_FIELDS = {
    "seed_id",
    "seed_root_hash",
    "instance_id",
    "memory",
    "checkpoint",
    "guardian_id",
}
ANCHOR_FIELDS = [
    "protocol_version",
    "seed_root_hash",
    "instance_id",
    "checkpoint_hash",
    "last_event_hash",
    "last_sequence",
    "continuity_status",
    "authority_ledger_head",
]
PORTABILITY_RULES = {
    "neutral_export": (True, "neutral_export_required"),
    "neutral_import": (True, "neutral_import_required"),
    "platform_account_required": (False, "platform_account_required"),
    "private_body_keys_exported": (False, "private_body_key_export_forbidden"),
    "engine_bound_to_identity": (False, "engine_identity_binding_forbidden"),
    "source_deactivation_required": (True, "source_deactivation_required"),
}


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


def validate_capabilities(capabilities: list[str], required: list[str]) -> None:
    if len(capabilities) != len(set(capabilities)):
        raise ConformanceError("duplicate_host_capability")
    if capabilities != sorted(capabilities, key=lambda value: value.encode("utf-8")):
        raise ConformanceError("unsorted_host_capabilities")
    missing = set(required) - set(capabilities)
    if missing:
        raise ConformanceError("missing_required_capability")
    if set(capabilities) - set(required):
        raise ConformanceError("unsupported_host_capability")


def validate_portability(portability: dict) -> None:
    missing = set(PORTABILITY_RULES) - set(portability)
    if missing:
        raise ConformanceError("missing_portability_rule")
    if set(portability) - set(PORTABILITY_RULES):
        raise ConformanceError("unexpected_portability_rule")
    for field, (expected, error_code) in PORTABILITY_RULES.items():
        if portability[field] is not expected:
            raise ConformanceError(error_code)


def validate_manifest(manifest: dict, required: list[str]) -> None:
    additional = set(manifest) - MANIFEST_FIELDS
    if additional & PORTABLE_IDENTITY_FIELDS:
        raise ConformanceError("host_manifest_contains_portable_identity")
    if additional:
        raise ConformanceError("unexpected_host_manifest_field")
    if MANIFEST_FIELDS - set(manifest):
        raise ConformanceError("missing_host_manifest_field")
    if manifest["schema_version"] != "genesis.host.capability.manifest.v0.1":
        raise ConformanceError("host_manifest_schema_version_invalid")
    if "genesis.protocol.v0.1" not in manifest["protocol_versions"]:
        raise ConformanceError("protocol_version_not_supported")
    if manifest["verification_state"] not in {
        "declaration_only",
        "simulated",
        "storage_verified",
    }:
        raise ConformanceError("host_verification_state_invalid")
    validate_capabilities(manifest["capabilities"], required)
    validate_portability(manifest["portability"])


def validate_anchor(anchor: dict, forbidden_fields: set[str]) -> None:
    if set(anchor) & forbidden_fields:
        raise ConformanceError("platform_binding_in_portable_anchor")
    if set(anchor) != set(ANCHOR_FIELDS):
        raise ConformanceError("portable_anchor_fields_invalid")


def compute_anchor(vector: dict, forbidden_fields: set[str]) -> str:
    anchor = vector["input"]
    validate_anchor(anchor, forbidden_fields)
    fields = [
        anchor["protocol_version"],
        anchor["seed_root_hash"],
        anchor["instance_id"],
        anchor["checkpoint_hash"],
        anchor["last_event_hash"],
        str(anchor["last_sequence"]),
        anchor["continuity_status"],
        anchor["authority_ledger_head"],
    ]
    return hash_fields(vector["domain"], fields)


def evaluate_rejection(test_case: dict, vectors: dict) -> str | None:
    category = test_case["category"]
    mutation = test_case["input"]
    manifest = deepcopy(vectors["adapters"][0]["manifest"])

    try:
        if category == "required_capabilities":
            capabilities = list(manifest["capabilities"])
            if "remove" in mutation:
                capabilities.remove(mutation["remove"])
            if "duplicate" in mutation:
                capabilities.append(mutation["duplicate"])
            if mutation.get("reverse"):
                capabilities.reverse()
            validate_capabilities(capabilities, vectors["required_capabilities"])
        elif category == "host_manifest_fields":
            for field in mutation["additional_fields"]:
                manifest[field] = "forbidden"
            validate_manifest(manifest, vectors["required_capabilities"])
        elif category == "portability":
            manifest["portability"][mutation["field"]] = mutation["value"]
            validate_manifest(manifest, vectors["required_capabilities"])
        elif category == "portable_anchor_fields":
            anchor = deepcopy(vectors["portable_anchor"]["input"])
            for field in mutation["additional_fields"]:
                anchor[field] = "forbidden"
            validate_anchor(anchor, set(vectors["forbidden_portable_fields"]))
        else:
            raise ConformanceError(f"unknown_host_rejection_category:{category}")
    except ConformanceError as error:
        return str(error)
    return None


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []
    if vectors["profile"] != "genesis.host.adapter.v0.1":
        failures.append("host_adapter_profile_invalid")

    required = vectors["required_capabilities"]
    forbidden = vectors["forbidden_portable_fields"]
    try:
        validate_capabilities(required, required)
        if forbidden != sorted(forbidden, key=lambda value: value.encode("utf-8")):
            raise ConformanceError("unsorted_forbidden_portable_fields")
        if len(forbidden) != len(set(forbidden)):
            raise ConformanceError("duplicate_forbidden_portable_field")
    except ConformanceError as error:
        failures.append(str(error))

    expected_profiles = {"android-kotlin", "apple-swift", "windows-dotnet"}
    actual_profiles = {
        adapter["manifest"].get("platform_profile") for adapter in vectors["adapters"]
    }
    if actual_profiles != expected_profiles:
        failures.append("host_fixture_platform_set_invalid")

    expected_anchor = vectors["portable_anchor"]["expected_digest"]
    for adapter in vectors["adapters"]:
        try:
            validate_manifest(adapter["manifest"], required)
            if adapter["manifest"]["verification_state"] != "declaration_only":
                raise ConformanceError("fixture_must_not_claim_storage_verification")
            actual_anchor = compute_anchor(vectors["portable_anchor"], set(forbidden))
            if actual_anchor != expected_anchor:
                raise ConformanceError("portable_anchor_digest_mismatch")
        except ConformanceError as error:
            failures.append(f"{adapter['case_id']}:{error}")

    for test_case in vectors["must_reject"]:
        actual_error = evaluate_rejection(test_case, vectors)
        if actual_error != test_case["expected_error"]:
            failures.append(
                f"{test_case['case_id']}:expected={test_case['expected_error']}:actual={actual_error}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1

    print("OK portable anchor is identical across Android, Apple, and Windows declarations")
    print(f"OK host capability manifests ({len(vectors['adapters'])})")
    print(f"OK anti-lock-in rejection cases ({len(vectors['must_reject'])})")
    print("NOTE Declaration fixtures are not real platform storage certification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

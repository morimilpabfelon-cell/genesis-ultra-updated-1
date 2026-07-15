#!/usr/bin/env python3
"""Valida adaptadores neutrales de Vista, Propiocepción e Interocepción."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unicodedata

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("FAIL PyNaCl requerido para validar adaptadores de sentidos")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "sense_adapter_vectors.json"

MANIFEST_FIELDS = {
    "schema_version", "adapter_id", "adapter_version", "platform_profile", "sense",
    "source_kinds", "verification_state", "permission_model", "capabilities", "boundary",
}
RESULT_FIELDS = {
    "schema_version", "hash_profile", "capture_id", "adapter_id", "adapter_version",
    "sense", "source_kind", "status", "captured_at", "payload_digest",
    "payload_media_type", "privacy", "permission_state", "diagnostic_code", "result_digest",
}
RESULT_DIGEST_FIELDS = [
    "schema_version", "hash_profile", "capture_id", "adapter_id", "adapter_version",
    "sense", "source_kind", "status", "captured_at", "payload_digest",
    "payload_media_type", "privacy", "permission_state", "diagnostic_code",
]
OBSERVATION_FIELDS = {
    "schema_version", "hash_profile", "observation_id", "instance_id", "body_id",
    "observation_sequence", "sense", "source_kind", "captured_at", "payload_digest",
    "payload_media_type", "evidence_digest", "privacy", "observation_digest", "signature",
}
OBSERVATION_DIGEST_FIELDS = [
    "schema_version", "hash_profile", "observation_id", "instance_id", "body_id",
    "observation_sequence", "sense", "source_kind", "captured_at", "payload_digest",
    "payload_media_type", "evidence_digest", "privacy",
]
BOUNDARY_RULES = {
    "emits_raw_payload": "adapter_raw_payload_forbidden",
    "exports_platform_handles": "adapter_platform_handle_export_forbidden",
    "writes_memory": "adapter_memory_write_forbidden",
    "executes_actions": "adapter_action_forbidden",
    "mutates_identity": "adapter_identity_mutation_forbidden",
}
SENSES = {"vision", "proprioception", "interoception"}
SOURCE_KINDS = {"local_sensor", "user_input", "runtime_state", "network_evidence", "clock"}


class ConformanceError(ValueError):
    """Error estable de conformidad."""


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ConformanceError("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


def hash_fields(domain: str, fields: list[str]) -> str:
    payload = encode_field(domain) + b"".join(encode_field(value) for value in fields)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_nfc(value: object) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("text_not_nfc")
    elif isinstance(value, dict):
        for key, child in value.items():
            validate_nfc(key)
            validate_nfc(child)
    elif isinstance(value, list):
        for child in value:
            validate_nfc(child)


def compute_result_digest(result: dict, domain: str) -> str:
    validate_nfc(result)
    if set(result) != RESULT_FIELDS:
        raise ConformanceError("capture_result_fields_invalid")
    return hash_fields(domain, [optional_text(result[field]) for field in RESULT_DIGEST_FIELDS])


def compute_observation_digest(observation: dict, domain: str) -> str:
    validate_nfc(observation)
    if set(observation) != OBSERVATION_FIELDS:
        raise ConformanceError("observation_fields_invalid")
    values = [
        str(observation[field]) if field == "observation_sequence" else observation[field]
        for field in OBSERVATION_DIGEST_FIELDS
    ]
    return hash_fields(domain, values)


def signature_bytes(domain: str, digest: str) -> bytes:
    return encode_field(domain) + encode_field(digest)


def sign_envelope(envelope: dict, digest: str, domain: str, signing_key: SigningKey) -> None:
    envelope["signed_domain"] = domain
    envelope["signed_digest"] = digest
    envelope["signature_value"] = signing_key.sign(signature_bytes(domain, digest)).signature.hex()


def validate_signature(
    envelope: dict,
    *,
    digest: str,
    domain: str,
    body_id: str,
    public_key: bytes,
    fingerprint: str,
) -> None:
    if envelope.get("signature_profile") != "genesis.signature.ed25519.v0.1":
        raise ConformanceError("observation_signature_profile_invalid")
    if envelope.get("signer_type") != "body" or envelope.get("signer_id") != body_id:
        raise ConformanceError("observation_signer_mismatch")
    if envelope.get("signed_domain") != domain:
        raise ConformanceError("observation_signature_domain_mismatch")
    if envelope.get("signed_digest") != digest:
        raise ConformanceError("observation_signature_digest_mismatch")
    if envelope.get("public_key_ref") != fingerprint:
        raise ConformanceError("observation_signature_key_mismatch")
    try:
        signature = bytes.fromhex(envelope["signature_value"])
        VerifyKey(public_key).verify(signature_bytes(domain, digest), signature)
    except (BadSignatureError, ValueError, KeyError):
        raise ConformanceError("observation_signature_invalid") from None


def validate_capabilities(capabilities: list[str], required: list[str]) -> None:
    if len(capabilities) != len(set(capabilities)):
        raise ConformanceError("duplicate_adapter_capability")
    if capabilities != sorted(capabilities, key=lambda value: value.encode("utf-8")):
        raise ConformanceError("unsorted_adapter_capabilities")
    if set(required) - set(capabilities):
        raise ConformanceError("missing_adapter_capability")
    if set(capabilities) - set(required):
        raise ConformanceError("unsupported_adapter_capability")


def validate_manifest(manifest: dict, vectors: dict) -> None:
    validate_nfc(manifest)
    additional = set(manifest) - MANIFEST_FIELDS
    if additional & set(vectors["forbidden_adapter_identity_fields"]):
        raise ConformanceError("adapter_manifest_contains_identity")
    if additional & set(vectors["forbidden_adapter_memory_fields"]):
        raise ConformanceError("adapter_manifest_contains_memory")
    if additional or MANIFEST_FIELDS - set(manifest):
        raise ConformanceError("adapter_manifest_fields_invalid")
    if manifest["schema_version"] != "genesis.sense.adapter.manifest.v0.1":
        raise ConformanceError("adapter_manifest_schema_version_invalid")
    if manifest["sense"] not in SENSES:
        raise ConformanceError("adapter_sense_invalid")
    sources = manifest["source_kinds"]
    if len(sources) != len(set(sources)):
        raise ConformanceError("duplicate_adapter_source")
    if sources != sorted(sources, key=lambda value: value.encode("utf-8")):
        raise ConformanceError("unsorted_adapter_sources")
    if not sources or any(source not in SOURCE_KINDS for source in sources):
        raise ConformanceError("adapter_source_invalid")
    validate_capabilities(manifest["capabilities"], vectors["required_capabilities"])
    if set(manifest["boundary"]) != set(BOUNDARY_RULES):
        raise ConformanceError("adapter_boundary_fields_invalid")
    for field, error_code in BOUNDARY_RULES.items():
        if manifest["boundary"][field] is not False:
            raise ConformanceError(error_code)
    if (
        manifest["platform_profile"] == "reference-neutral"
        and manifest["verification_state"] == "platform_verified"
    ):
        raise ConformanceError("reference_adapter_cannot_claim_platform_verification")
    if manifest["verification_state"] not in {
        "declaration_only", "simulated", "platform_verified"
    }:
        raise ConformanceError("adapter_verification_state_invalid")
    if manifest["permission_model"] not in {"os_runtime", "local_runtime", "not_required"}:
        raise ConformanceError("adapter_permission_model_invalid")


def validate_result(result: dict, manifest: dict, vectors: dict) -> None:
    validate_nfc(result)
    additional = set(result) - RESULT_FIELDS
    if "raw_payload" in additional:
        raise ConformanceError("capture_result_raw_payload_forbidden")
    if additional & set(vectors["forbidden_adapter_identity_fields"]):
        raise ConformanceError("capture_result_contains_identity")
    if additional & set(vectors["forbidden_adapter_memory_fields"]):
        raise ConformanceError("capture_result_contains_memory")
    if additional & set(vectors["forbidden_capture_result_fields"]):
        raise ConformanceError("capture_result_platform_binding")
    if additional or RESULT_FIELDS - set(result):
        raise ConformanceError("capture_result_fields_invalid")
    if result["schema_version"] != vectors["domains"]["capture_result"]:
        raise ConformanceError("capture_result_schema_version_invalid")
    if result["hash_profile"] != "genesis.hash.fields.v0.1":
        raise ConformanceError("capture_result_hash_profile_invalid")
    if result["adapter_id"] != manifest["adapter_id"]:
        raise ConformanceError("capture_result_adapter_mismatch")
    if result["adapter_version"] != manifest["adapter_version"]:
        raise ConformanceError("capture_result_adapter_version_mismatch")
    if result["sense"] != manifest["sense"]:
        raise ConformanceError("capture_result_sense_mismatch")
    if result["source_kind"] not in manifest["source_kinds"]:
        raise ConformanceError("capture_result_source_not_declared")
    if result["status"] not in {"captured", "denied", "unavailable", "failed"}:
        raise ConformanceError("capture_result_status_invalid")
    if result["status"] == "captured":
        if result["permission_state"] not in {"granted", "not_required"}:
            raise ConformanceError("captured_result_permission_invalid")
        if (
            result["captured_at"] is None
            or result["payload_digest"] is None
            or result["payload_media_type"] is None
        ):
            raise ConformanceError("captured_result_payload_required")
    else:
        if any(
            result[field] is not None
            for field in ("captured_at", "payload_digest", "payload_media_type")
        ):
            raise ConformanceError("noncaptured_result_payload_forbidden")
        if result["status"] == "denied" and result["permission_state"] != "denied":
            raise ConformanceError("denied_result_permission_mismatch")
        if result["status"] == "unavailable" and result["permission_state"] != "unavailable":
            raise ConformanceError("unavailable_result_permission_mismatch")
    actual = compute_result_digest(result, vectors["domains"]["capture_result"])
    if actual != result["result_digest"]:
        raise ConformanceError("capture_result_digest_mismatch")


def validate_observation(
    observation: dict | None,
    result: dict,
    vectors: dict,
    public_key: bytes,
) -> None:
    if result["status"] != "captured":
        if observation is not None:
            raise ConformanceError("noncaptured_result_must_not_emit_observation")
        return
    if observation is None:
        raise ConformanceError("captured_result_observation_required")
    validate_nfc(observation)
    if set(observation) != OBSERVATION_FIELDS:
        raise ConformanceError("observation_fields_invalid")
    if observation["schema_version"] != vectors["domains"]["observation"]:
        raise ConformanceError("observation_schema_version_invalid")
    if observation["hash_profile"] != "genesis.hash.fields.v0.1":
        raise ConformanceError("observation_hash_profile_invalid")
    links = (
        ("sense", "observation_sense_mismatch"),
        ("source_kind", "observation_source_mismatch"),
        ("captured_at", "observation_captured_at_mismatch"),
        ("payload_digest", "observation_payload_digest_mismatch"),
        ("payload_media_type", "observation_media_type_mismatch"),
        ("privacy", "observation_privacy_mismatch"),
    )
    for field, error_code in links:
        if observation[field] != result[field]:
            raise ConformanceError(error_code)
    if observation["evidence_digest"] != result["result_digest"]:
        raise ConformanceError("observation_evidence_digest_mismatch")
    actual = compute_observation_digest(observation, vectors["domains"]["observation"])
    if actual != observation["observation_digest"]:
        raise ConformanceError("observation_digest_mismatch")
    validate_signature(
        observation["signature"],
        digest=actual,
        domain=vectors["domains"]["observation_signature"],
        body_id=observation["body_id"],
        public_key=public_key,
        fingerprint=vectors["test_signing_key"]["public_key_fingerprint"],
    )


def set_path(target: dict, path: list[str], value: object) -> None:
    cursor = target
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = value


def evaluate_rejection(
    test_case: dict,
    vectors: dict,
    signing_key: SigningKey,
    public_key: bytes,
) -> str | None:
    fixture = deepcopy(vectors["adapters"][0])
    manifest = fixture["manifest"]
    result = fixture["capture_result"]
    observation = fixture["observation"]
    try:
        if test_case["target"] == "manifest":
            target = manifest
        elif test_case["target"] == "capture_result":
            target = result
        elif test_case["target"] == "observation":
            target = observation
        elif test_case["target"] == "noncaptured_emission":
            no_observation = deepcopy(
                vectors["no_observation_cases"][test_case["no_observation_index"]]
            )
            result = no_observation["capture_result"]
            observation = fixture["observation"]
            target = result
        else:
            raise ConformanceError("unknown_adapter_rejection_target")
        for mutation in test_case["mutations"]:
            set_path(target, mutation["path"], mutation["value"])
        if test_case["recompute_result_digest"]:
            result["result_digest"] = compute_result_digest(
                result, vectors["domains"]["capture_result"]
            )
        if test_case["recompute_observation_digest"]:
            observation["observation_digest"] = compute_observation_digest(
                observation, vectors["domains"]["observation"]
            )
        if test_case["resign"]:
            sign_envelope(
                observation["signature"],
                observation["observation_digest"],
                vectors["domains"]["observation_signature"],
                signing_key,
            )
        validate_manifest(manifest, vectors)
        validate_result(result, manifest, vectors)
        validate_observation(observation, result, vectors, public_key)
    except ConformanceError as error:
        return str(error)
    return None


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []
    key = vectors["test_signing_key"]
    signing_key = SigningKey(bytes.fromhex(key["seed_hex"]))
    public_key = signing_key.verify_key.encode()
    if vectors["profile"] != "genesis.sense.adapters.v0.1":
        failures.append("sense_adapter_profile_invalid")
    if public_key.hex() != key["public_key_hex"]:
        failures.append("sense_adapter_test_public_key_mismatch")
    fingerprint = "sha256:" + hashlib.sha256(public_key).hexdigest()
    if fingerprint != key["public_key_fingerprint"]:
        failures.append("sense_adapter_test_key_fingerprint_mismatch")
    if "TEST ONLY" not in key["warning"]:
        failures.append("sense_adapter_test_key_warning_missing")
    try:
        validate_capabilities(vectors["required_capabilities"], vectors["required_capabilities"])
        for field in (
            "forbidden_adapter_identity_fields",
            "forbidden_adapter_memory_fields",
            "forbidden_capture_result_fields",
        ):
            values = vectors[field]
            if values != sorted(values, key=lambda value: value.encode("utf-8")):
                raise ConformanceError("unsorted_" + field)
            if len(values) != len(set(values)):
                raise ConformanceError("duplicate_" + field)
    except ConformanceError as error:
        failures.append(str(error))

    expected_senses = ["vision", "proprioception", "interoception"]
    if [fixture["manifest"]["sense"] for fixture in vectors["adapters"]] != expected_senses:
        failures.append("sense_adapter_fixture_set_invalid")
    for fixture in vectors["adapters"]:
        try:
            validate_manifest(fixture["manifest"], vectors)
            if fixture["manifest"]["verification_state"] != "simulated":
                raise ConformanceError("reference_fixture_must_be_simulated")
            validate_result(fixture["capture_result"], fixture["manifest"], vectors)
            validate_observation(
                fixture["observation"], fixture["capture_result"], vectors, public_key
            )
        except ConformanceError as error:
            failures.append(f"{fixture['case_id']}:{error}")

    by_case_id = {fixture["case_id"]: fixture for fixture in vectors["adapters"]}
    for fixture in vectors["no_observation_cases"]:
        try:
            manifest = by_case_id[fixture["adapter_ref"]]["manifest"]
            validate_result(fixture["capture_result"], manifest, vectors)
            validate_observation(
                fixture["observation"], fixture["capture_result"], vectors, public_key
            )
        except (ConformanceError, KeyError) as error:
            failures.append(f"{fixture['case_id']}:{error}")

    for test_case in vectors["must_reject"]:
        actual = evaluate_rejection(test_case, vectors, signing_key, public_key)
        if actual != test_case["expected_error"]:
            failures.append(
                f"{test_case['case_id']}:expected={test_case['expected_error']}:actual={actual}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1
    print(f"OK neutral sense adapter manifests ({len(vectors['adapters'])})")
    print(f"OK captured result -> signed observation links ({len(vectors['adapters'])})")
    print(f"OK fail-closed no-observation cases ({len(vectors['no_observation_cases'])})")
    print(f"OK sense adapter boundary rejection cases ({len(vectors['must_reject'])})")
    print("NOTE Reference adapters are simulated, not platform-verified sensors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

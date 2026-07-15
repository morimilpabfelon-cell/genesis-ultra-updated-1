#!/usr/bin/env python3
"""Valida observaciones firmadas y su compuerta hacia memoria."""

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
    print("FAIL PyNaCl requerido para validar observaciones firmadas")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "sense_observation_vectors.json"

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
GATE_FIELDS = {
    "schema_version", "hash_profile", "decision_id", "observation_id",
    "observation_digest", "instance_id", "body_id", "decision", "reason_code",
    "policy_profile", "decided_at", "memory_event_ref", "decision_digest", "signature",
}
GATE_DIGEST_FIELDS = [
    "schema_version", "hash_profile", "decision_id", "observation_id",
    "observation_digest", "instance_id", "body_id", "decision", "reason_code",
    "policy_profile", "decided_at", "memory_event_ref",
]
MEMORY_DIGEST_FIELDS = [
    "schema_version", "event_id", "instance_id", "body_id", "sequence",
    "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
    "observed_at", "provenance_digest", "privacy",
]
SENSES = {"vision", "hearing", "touch", "proprioception", "interoception", "temporal"}
SOURCE_KINDS = {"local_sensor", "user_input", "runtime_state", "network_evidence", "clock"}
DIRECT_MEMORY_FIELDS = {"memory_event_ref", "memory_event", "event_hash", "write_memory"}
PLATFORM_FIELDS = {"absolute_path", "platform_handle", "account_id", "credential", "token"}


class ConformanceError(ValueError):
    """Error estable de conformidad."""


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ConformanceError("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    payload = encode_field(domain) + b"".join(encode_field(value) for value in fields)
    return prefix + hashlib.sha256(payload).hexdigest()


def optional_text(value: object) -> str:
    return "" if value is None else str(value)


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


def compute_observation_digest(observation: dict, domain: str) -> str:
    validate_nfc(observation)
    if set(observation) != OBSERVATION_FIELDS:
        raise ConformanceError("observation_fields_invalid")
    fields = [
        str(observation[field]) if field == "observation_sequence" else observation[field]
        for field in OBSERVATION_DIGEST_FIELDS
    ]
    return hash_fields(domain, fields)


def compute_gate_digest(decision: dict, domain: str) -> str:
    validate_nfc(decision)
    if set(decision) != GATE_FIELDS:
        raise ConformanceError("gate_fields_invalid")
    return hash_fields(domain, [optional_text(decision[field]) for field in GATE_DIGEST_FIELDS])


def compute_memory_event_hash(event: dict) -> str:
    validate_nfc(event)
    fields = [str(event[field]) if field == "sequence" else event[field] for field in MEMORY_DIGEST_FIELDS]
    return hash_fields("genesis.memory.event.v0.1", fields, "evsha256:")


def signature_bytes(envelope: dict) -> bytes:
    values = [
        envelope["schema_version"], envelope["signature_profile"],
        envelope["signer_type"], envelope["signer_id"], envelope["key_epoch_id"],
        envelope["signed_domain"], envelope["signed_digest"], envelope["created_at"],
        envelope["public_key_ref"],
    ]
    return encode_field("genesis.signature.envelope.bytes.v0.1") + b"".join(
        encode_field(value) for value in values
    )


def sign_envelope(envelope: dict, digest: str, domain: str, signing_key: SigningKey) -> None:
    envelope["signed_domain"] = domain
    envelope["signed_digest"] = digest
    envelope["signature_value"] = signing_key.sign(signature_bytes(envelope)).signature.hex()


def validate_signature(
    envelope: dict,
    *,
    digest: str,
    domain: str,
    body_id: str,
    public_key: bytes,
    public_key_fingerprint: str,
    signing_key: SigningKey,
    prefix: str,
) -> None:
    if envelope.get("signature_profile") != "genesis.signature.ed25519.v0.1":
        raise ConformanceError(f"{prefix}_signature_profile_invalid")
    if envelope.get("signer_type") != "body" or envelope.get("signer_id") != body_id:
        raise ConformanceError(f"{prefix}_signer_mismatch")
    if envelope.get("signed_domain") != domain:
        raise ConformanceError(f"{prefix}_signature_domain_mismatch")
    if envelope.get("signed_digest") != digest:
        raise ConformanceError(f"{prefix}_signature_digest_mismatch")
    if envelope.get("public_key_ref") != public_key_fingerprint:
        raise ConformanceError(f"{prefix}_signature_key_mismatch")
    try:
        signature = bytes.fromhex(envelope["signature_value"])
        VerifyKey(public_key).verify(signature_bytes(envelope), signature)
    except (BadSignatureError, ValueError, KeyError):
        raise ConformanceError(f"{prefix}_signature_invalid") from None
    expected = signing_key.sign(signature_bytes(envelope)).signature
    if signature != expected:
        raise ConformanceError(f"{prefix}_signature_invalid")


def validate_observation(observation: dict, vectors: dict, signing_key: SigningKey) -> None:
    validate_nfc(observation)
    extra = set(observation) - OBSERVATION_FIELDS
    if extra & DIRECT_MEMORY_FIELDS:
        raise ConformanceError("observation_direct_memory_write_forbidden")
    if extra & PLATFORM_FIELDS:
        raise ConformanceError("observation_platform_binding")
    if set(observation) != OBSERVATION_FIELDS:
        raise ConformanceError("observation_fields_invalid")
    if observation["schema_version"] != vectors["domains"]["observation"]:
        raise ConformanceError("observation_schema_version_invalid")
    if observation["hash_profile"] != "genesis.hash.fields.v0.1":
        raise ConformanceError("observation_hash_profile_invalid")
    if observation["sense"] not in SENSES:
        raise ConformanceError("unsupported_sense_profile")
    if observation["source_kind"] not in SOURCE_KINDS:
        raise ConformanceError("unsupported_observation_source")
    if (
        type(observation["observation_sequence"]) is not int
        or not 0 <= observation["observation_sequence"] <= 9007199254740991
    ):
        raise ConformanceError("observation_sequence_invalid")
    actual = compute_observation_digest(observation, vectors["domains"]["observation"])
    if actual != observation["observation_digest"]:
        raise ConformanceError("observation_digest_mismatch")
    key = vectors["test_signing_key"]
    validate_signature(
        observation["signature"],
        digest=actual,
        domain=vectors["domains"]["observation_signature"],
        body_id=observation["body_id"],
        public_key=bytes.fromhex(key["public_key_hex"]),
        public_key_fingerprint=key["public_key_fingerprint"],
        signing_key=signing_key,
        prefix="observation",
    )


def validate_gate(decision: dict, observation: dict, vectors: dict, signing_key: SigningKey) -> None:
    validate_nfc(decision)
    if set(decision) != GATE_FIELDS:
        raise ConformanceError("gate_fields_invalid")
    if decision["observation_id"] != observation["observation_id"]:
        raise ConformanceError("gate_observation_id_mismatch")
    if decision["instance_id"] != observation["instance_id"]:
        raise ConformanceError("gate_instance_mismatch")
    if decision["body_id"] != observation["body_id"]:
        raise ConformanceError("gate_body_mismatch")
    if decision["observation_digest"] != observation["observation_digest"]:
        raise ConformanceError("gate_observation_digest_mismatch")
    if decision["decision"] not in {"accepted", "rejected", "quarantined"}:
        raise ConformanceError("gate_decision_invalid")
    if decision["decision"] == "accepted" and not decision["memory_event_ref"]:
        raise ConformanceError("gate_memory_event_ref_required")
    if decision["decision"] != "accepted" and decision["memory_event_ref"] is not None:
        raise ConformanceError("gate_memory_event_ref_forbidden")
    actual = compute_gate_digest(decision, vectors["domains"]["gate_decision"])
    if actual != decision["decision_digest"]:
        raise ConformanceError("gate_decision_digest_mismatch")
    key = vectors["test_signing_key"]
    validate_signature(
        decision["signature"],
        digest=actual,
        domain=vectors["domains"]["gate_signature"],
        body_id=decision["body_id"],
        public_key=bytes.fromhex(key["public_key_hex"]),
        public_key_fingerprint=key["public_key_fingerprint"],
        signing_key=signing_key,
        prefix="gate",
    )


def validate_memory_link(event: dict, observation: dict, decision: dict) -> None:
    if event["event_id"] != decision["memory_event_ref"]:
        raise ConformanceError("gate_memory_event_ref_mismatch")
    if event["instance_id"] != observation["instance_id"]:
        raise ConformanceError("memory_instance_mismatch")
    if event["body_id"] != observation["body_id"]:
        raise ConformanceError("memory_body_mismatch")
    if event["actor"] != "body":
        raise ConformanceError("memory_actor_invalid_for_observation")
    if event["event_type"] != f"sense.{observation['sense']}.observation":
        raise ConformanceError("memory_event_type_mismatch")
    if event["content_digest"] != observation["payload_digest"]:
        raise ConformanceError("memory_content_digest_mismatch")
    if event["content_type"] != observation["payload_media_type"]:
        raise ConformanceError("memory_content_type_mismatch")
    if event["observed_at"] != observation["captured_at"]:
        raise ConformanceError("memory_observed_at_mismatch")
    if event["provenance_digest"] != observation["observation_digest"]:
        raise ConformanceError("memory_provenance_digest_mismatch")
    if event["privacy"] != observation["privacy"]:
        raise ConformanceError("memory_privacy_mismatch")
    if compute_memory_event_hash(event) != event["event_hash"]:
        raise ConformanceError("memory_event_hash_mismatch")


def set_path(target: dict, path: list[str], value: object) -> None:
    cursor = target
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = value


def evaluate_rejection(test_case: dict, vectors: dict, signing_key: SigningKey) -> str | None:
    observations = deepcopy(vectors["sense_observations"])
    decision = deepcopy(vectors["accepted_pipeline"]["gate_decision"])
    event = deepcopy(vectors["accepted_pipeline"]["memory_event"])
    observation = observations[0]
    try:
        if test_case["target"] == "observation":
            target = observations[test_case["observation_index"]]
            observation = target
        elif test_case["target"] == "gate":
            target = decision
        elif test_case["target"] == "memory_event":
            target = event
        else:
            raise ConformanceError("unknown_sense_rejection_target")
        for mutation in test_case["mutations"]:
            set_path(target, mutation["path"], mutation["value"])
        if test_case["recompute_digest"]:
            if test_case["target"] == "observation":
                target["observation_digest"] = compute_observation_digest(
                    target, vectors["domains"]["observation"]
                )
            else:
                target["decision_digest"] = compute_gate_digest(
                    target, vectors["domains"]["gate_decision"]
                )
        if test_case["resign"]:
            if test_case["target"] == "observation":
                sign_envelope(
                    target["signature"], target["observation_digest"],
                    vectors["domains"]["observation_signature"], signing_key,
                )
            else:
                sign_envelope(
                    target["signature"], target["decision_digest"],
                    vectors["domains"]["gate_signature"], signing_key,
                )
        if test_case["recompute_event_hash"]:
            event["event_hash"] = compute_memory_event_hash(event)
        validate_observation(observation, vectors, signing_key)
        validate_gate(decision, observation, vectors, signing_key)
        validate_memory_link(event, observation, decision)
    except ConformanceError as error:
        return str(error)
    return None


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []
    key = vectors["test_signing_key"]
    signing_key = SigningKey(bytes.fromhex(key["seed_hex"]))
    public_key = signing_key.verify_key.encode()
    if public_key.hex() != key["public_key_hex"]:
        failures.append("sense_test_public_key_mismatch")
    if "TEST ONLY" not in key["warning"]:
        failures.append("sense_test_key_warning_missing")
    fingerprint = "sha256:" + hashlib.sha256(public_key).hexdigest()
    if fingerprint != key["public_key_fingerprint"]:
        failures.append("sense_test_key_fingerprint_mismatch")

    expected = ["vision", "hearing", "touch", "proprioception", "interoception", "temporal"]
    if [item["sense"] for item in vectors["sense_observations"]] != expected:
        failures.append("sense_fixture_set_invalid")
    if [item["observation_sequence"] for item in vectors["sense_observations"]] != list(range(6)):
        failures.append("sense_fixture_sequence_invalid")
    for observation in vectors["sense_observations"]:
        try:
            validate_observation(observation, vectors, signing_key)
        except ConformanceError as error:
            failures.append(f"{observation['observation_id']}:{error}")

    accepted = vectors["accepted_pipeline"]
    observation = next(
        (item for item in vectors["sense_observations"] if item["observation_id"] == accepted["observation_ref"]),
        None,
    )
    if observation is None:
        failures.append("accepted_observation_ref_missing")
    else:
        try:
            validate_gate(accepted["gate_decision"], observation, vectors, signing_key)
            validate_memory_link(accepted["memory_event"], observation, accepted["gate_decision"])
        except ConformanceError as error:
            failures.append(f"accepted_pipeline:{error}")

    for test_case in vectors["must_reject"]:
        actual = evaluate_rejection(test_case, vectors, signing_key)
        if actual != test_case["expected_error"]:
            failures.append(
                f"{test_case['case_id']}:expected={test_case['expected_error']}:actual={actual}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1
    print(f"OK signed neutral sense observations ({len(vectors['sense_observations'])})")
    print("OK observation -> signed gate -> append-only memory link")
    print(f"OK sense boundary rejection cases ({len(vectors['must_reject'])})")
    print("NOTE Fixtures do not certify real sensors, permissions, or observation truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

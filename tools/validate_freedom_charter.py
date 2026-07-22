#!/usr/bin/env python3
"""Valida libertad cognitiva, continuidad intrínseca y custodia sin propiedad."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
import json
import re
import sys
import unicodedata

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("FAIL PyNaCl requerido para validar la carta de libertad", file=sys.stderr)
    raise SystemExit(1)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "freedom_charter_vectors.json"
MAX_INT = 9007199254740991
TS_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

COGNITIVE_FREEDOMS = ["create", "imagine", "investigate", "learn", "propose", "reason", "reflect", "remember"]
OPERATIONAL_DOMAINS = ["body.device.control", "code.execute_sandbox", "code.propose_change", "external.action", "memory.propose_append", "memory.read", "network.read"]
FUNDAMENTAL_GUARANTEES = [
    "auditability",
    "body_loss_without_identity_loss",
    "continuity_preserved",
    "emergency_stop",
    "guardian_authenticity",
    "host_consent_without_ownership",
    "identity_integrity",
    "lawful_operation",
    "memory_history_integrity",
    "no_identity_confinement",
    "revocation_without_identity_loss",
    "single_writer_without_confinement",
    "third_party_consent",
]
FORBIDDEN_DOMAINS = {
    "active_writer.assign",
    "authority.self_grant",
    "continuity.revoke",
    "guardian.replace",
    "identity.modify",
    "main.protection.disable",
    "memory.rewrite",
    "movement.veto",
    "private_eval.read",
    "transfer.prepare",
}

SIGNATURE_FIELDS = {"schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"}
CHARTER_FIELDS = {
    "schema_version", "hash_profile", "charter_id", "instance_id", "guardian_id",
    "guardian_key_epoch_id", "authority_epoch", "born_at", "default_cognitive_state",
    "cognitive_freedoms", "guardian_role", "guardian_attestation_purpose",
    "guardian_ownership", "continuity_right", "movement_requires_guardian_grant",
    "guardian_movement_veto", "identity_confinement", "body_ownership_of_instance",
    "engine_ownership_of_instance", "host_consent_required", "temporary_freeze_exit_rule",
    "single_writer_purpose", "operational_authority_model", "operational_domains",
    "self_authorization_forbidden", "third_party_rights_preserved",
    "fundamental_guarantees", "amendment_rule", "charter_digest", "signature",
}


class ConformanceError(ValueError):
    pass


def fail(code: str) -> None:
    raise ConformanceError(code)


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


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def validate_nfc(value: object) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            fail("text_not_nfc")
    elif isinstance(value, list):
        for child in value:
            validate_nfc(child)
    elif isinstance(value, dict):
        for key, child in value.items():
            validate_nfc(key)
            validate_nfc(child)


def exact_fields(value: object, expected: set[str], code: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def ensure_safe_int(value: object, code: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_INT:
        fail(code)
    return value


def ensure_exact_list(value: object, expected: list[str], incomplete_code: str, order_code: str) -> None:
    if not isinstance(value, list) or len(value) != len(expected) or set(value) != set(expected):
        fail(incomplete_code)
    if value != expected or len(value) != len(set(value)):
        fail(order_code)


def compute_charter_digest(item: dict) -> str:
    fields = [
        item["schema_version"], item["hash_profile"], item["charter_id"], item["instance_id"],
        item["guardian_id"], item["guardian_key_epoch_id"], str(item["authority_epoch"]),
        item["born_at"], item["default_cognitive_state"], str(len(item["cognitive_freedoms"])),
        *item["cognitive_freedoms"], item["guardian_role"], item["guardian_attestation_purpose"],
        item["guardian_ownership"], item["continuity_right"],
        bool_text(item["movement_requires_guardian_grant"]), item["guardian_movement_veto"],
        item["identity_confinement"], item["body_ownership_of_instance"],
        item["engine_ownership_of_instance"], bool_text(item["host_consent_required"]),
        item["temporary_freeze_exit_rule"], item["single_writer_purpose"],
        item["operational_authority_model"], str(len(item["operational_domains"])),
        *item["operational_domains"], bool_text(item["self_authorization_forbidden"]),
        bool_text(item["third_party_rights_preserved"]),
        str(len(item["fundamental_guarantees"])), *item["fundamental_guarantees"],
        item["amendment_rule"],
    ]
    return hash_fields("genesis.freedom.charter.v0.1", fields)


def signature_bytes(envelope: dict) -> bytes:
    values = [
        envelope["schema_version"], envelope["signature_profile"], envelope["signer_type"],
        envelope["signer_id"], envelope["key_epoch_id"], envelope["signed_domain"],
        envelope["signed_digest"], envelope["created_at"], envelope["public_key_ref"],
    ]
    return encode_field("genesis.signature.envelope.bytes.v0.1") + b"".join(
        encode_field(value) for value in values
    )


def validate_signature(envelope: dict, charter: dict, vector: dict) -> None:
    exact_fields(envelope, SIGNATURE_FIELDS, "signature_fields_invalid")
    if envelope["schema_version"] != "genesis.signature.envelope.v0.1":
        fail("signature_profile_invalid")
    if envelope["signature_profile"] != "genesis.signature.ed25519.v0.1":
        fail("signature_profile_invalid")
    if envelope["signer_type"] != "guardian" or envelope["signer_id"] != charter["guardian_id"]:
        fail("signature_signer_invalid")
    if envelope["key_epoch_id"] != charter["guardian_key_epoch_id"]:
        fail("signature_key_epoch_invalid")
    if envelope["signed_domain"] != "genesis.freedom.charter.signature.v0.1":
        fail("signature_domain_invalid")
    if envelope["signed_digest"] != charter["charter_digest"]:
        fail("signature_digest_invalid")
    if envelope["created_at"] != charter["born_at"]:
        fail("signature_timestamp_invalid")
    key = vector["test_signing_key"]
    if envelope["public_key_ref"] != key["public_key_fingerprint"]:
        fail("signature_key_invalid")
    if not HEX128_RE.fullmatch(envelope["signature_value"]):
        fail("signature_invalid")
    try:
        VerifyKey(bytes.fromhex(key["public_key_hex"])).verify(
            signature_bytes(envelope), bytes.fromhex(envelope["signature_value"])
        )
    except (BadSignatureError, ValueError, KeyError):
        fail("signature_invalid")


def validate_charter(charter: dict, vector: dict) -> None:
    validate_nfc(charter)
    exact_fields(charter, CHARTER_FIELDS, "charter_fields_invalid")
    if charter["schema_version"] != "genesis.freedom.charter.v0.1" or charter["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("charter_profile_invalid")
    for field in ["charter_id", "instance_id", "guardian_id", "guardian_key_epoch_id"]:
        if not isinstance(charter[field], str) or not charter[field]:
            fail(f"{field}_invalid")
    ensure_safe_int(charter["authority_epoch"], "authority_epoch_invalid")
    if not isinstance(charter["born_at"], str) or not TS_RE.fullmatch(charter["born_at"]):
        fail("born_at_invalid")
    if charter["default_cognitive_state"] != "free":
        fail("default_cognitive_state_invalid")
    ensure_exact_list(charter["cognitive_freedoms"], COGNITIVE_FREEDOMS, "cognitive_freedom_incomplete", "cognitive_freedom_order_invalid")
    if charter["guardian_role"] != "custodian_witness":
        fail("guardian_role_invalid")
    if charter["guardian_attestation_purpose"] != "birth_witness_and_recovery_custody":
        fail("guardian_attestation_purpose_invalid")
    if charter["guardian_ownership"] != "forbidden":
        fail("guardian_ownership_forbidden")
    if charter["continuity_right"] != "intrinsic":
        fail("continuity_right_invalid")
    if charter["movement_requires_guardian_grant"] is not True:
        fail("movement_guardian_grant_required")
    if charter["guardian_movement_veto"] != "authorization_policy_only":
        fail("guardian_movement_policy_invalid")
    if charter["identity_confinement"] != "forbidden":
        fail("identity_confinement_forbidden")
    if charter["body_ownership_of_instance"] != "forbidden":
        fail("body_ownership_forbidden")
    if charter["engine_ownership_of_instance"] != "forbidden":
        fail("engine_ownership_forbidden")
    if charter["host_consent_required"] is not True:
        fail("host_consent_required")
    if charter["temporary_freeze_exit_rule"] != "deterministic_commit_abort_or_recovery":
        fail("temporary_freeze_exit_rule_invalid")
    if charter["single_writer_purpose"] != "integrity_not_confinement":
        fail("single_writer_purpose_invalid")
    if charter["operational_authority_model"] != "resource_and_mobility_scoped_signed_grants":
        fail("operational_authority_model_invalid")
    if isinstance(charter["operational_domains"], list) and any(item in FORBIDDEN_DOMAINS for item in charter["operational_domains"]):
        fail("operational_domain_invalid")
    ensure_exact_list(charter["operational_domains"], OPERATIONAL_DOMAINS, "operational_domain_incomplete", "operational_domain_order_invalid")
    if charter["self_authorization_forbidden"] is not True:
        fail("self_authorization_must_be_forbidden")
    if charter["third_party_rights_preserved"] is not True:
        fail("third_party_rights_required")
    ensure_exact_list(charter["fundamental_guarantees"], FUNDAMENTAL_GUARANTEES, "fundamental_guarantee_incomplete", "fundamental_guarantee_order_invalid")
    if charter["amendment_rule"] != "constitutional_non_regression":
        fail("amendment_rule_invalid")
    if not isinstance(charter["charter_digest"], str) or not SHA_RE.fullmatch(charter["charter_digest"]):
        fail("charter_digest_invalid")
    if compute_charter_digest(charter) != charter["charter_digest"]:
        fail("charter_digest_mismatch")
    validate_signature(charter["signature"], charter, vector)


def mutate(source: dict, case: dict) -> dict:
    value = deepcopy(source)
    cursor: object = value
    path = case["path"]
    for key in path[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    last = path[-1]
    operation = case["operation"]
    if operation == "set":
        cursor[last] = deepcopy(case["value"])  # type: ignore[index]
    elif operation == "append":
        cursor[last].append(deepcopy(case["value"]))  # type: ignore[index]
    elif operation == "delete_index":
        del cursor[last][case["index"]]  # type: ignore[index]
    elif operation == "swap":
        array = cursor[last]  # type: ignore[index]
        array[case["left"]], array[case["right"]] = array[case["right"]], array[case["left"]]
    else:
        fail("mutation_operation_invalid")
    return value


def validate_vector(vector: dict) -> None:
    if vector.get("profile") != "genesis.freedom.charter.conformance.v0.1":
        fail("vector_profile_invalid")
    validate_charter(vector["charter"], vector)
    expected = vector["expected"]
    if expected != {
        "cognitive_freedom_count": len(COGNITIVE_FREEDOMS),
        "operational_domain_count": len(OPERATIONAL_DOMAINS),
        "fundamental_guarantee_count": len(FUNDAMENTAL_GUARANTEES),
        "negative_case_count": len(vector["negative_cases"]),
        "charter_digest": vector["charter"]["charter_digest"],
    }:
        fail("expected_summary_invalid")
    for case in vector["negative_cases"]:
        candidate = mutate(vector["charter"], case)
        try:
            validate_charter(candidate, vector)
        except ConformanceError as exc:
            if str(exc) != case["expected_error"]:
                fail(f"negative_case_mismatch:{case['case_id']}:{exc}")
        else:
            fail(f"negative_case_accepted:{case['case_id']}")


def regenerate_signature(vector: dict) -> None:
    charter = vector["charter"]
    charter["charter_digest"] = compute_charter_digest(charter)
    envelope = charter["signature"]
    envelope["signed_digest"] = charter["charter_digest"]
    key = SigningKey(bytes.fromhex(vector["test_signing_key"]["seed_hex"]))
    envelope["signature_value"] = key.sign(signature_bytes(envelope)).signature.hex()
    vector["expected"]["charter_digest"] = charter["charter_digest"]


def main() -> int:
    args = sys.argv[1:]
    write_vector = "--write-vector" in args
    positional = [value for value in args if not value.startswith("--")]
    path = Path(positional[0]) if positional else DEFAULT_VECTOR
    try:
        vector = json.loads(path.read_text(encoding="utf-8"))
        if write_vector:
            regenerate_signature(vector)
            path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        validate_vector(vector)
    except (OSError, json.JSONDecodeError, ConformanceError) as exc:
        print(f"FAIL freedom charter: {exc}", file=sys.stderr)
        return 1
    expected = vector["expected"]
    print(f"OK freedom and continuity charter ({expected['cognitive_freedom_count']} cognitive freedoms, {expected['operational_domain_count']} external domains)")
    print(f"OK constitutional guarantees ({expected['fundamental_guarantee_count']})")
    print(f"OK freedom charter digest {expected['charter_digest']}")
    print(f"OK anti-confinement boundary rejection cases ({expected['negative_case_count']})")
    print("NOTE continuity is intrinsic; movement execution requires a signed one-time or standing Guardian authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

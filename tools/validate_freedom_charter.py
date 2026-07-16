#!/usr/bin/env python3
"""Valida la carta de libertad cognitiva y autoridad final del guardián."""
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
    from nacl.signing import VerifyKey
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
OPERATIONAL_DOMAINS = ["body.device.control", "code.execute_sandbox", "code.propose_change", "external.action", "memory.propose_append", "memory.read", "network.read", "transfer.prepare"]
FUNDAMENTAL_GUARANTEES = ["auditability", "emergency_stop", "guardian_authenticity", "identity_integrity", "lawful_operation", "memory_history_integrity", "revocation_without_identity_loss", "third_party_consent"]
FORBIDDEN_DOMAINS = {"authority.self_grant", "guardian.replace", "identity.modify", "memory.rewrite", "main.protection.disable", "private_eval.read", "active_writer.assign"}

SIGNATURE_FIELDS = {"schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"}
CHARTER_FIELDS = {"schema_version", "hash_profile", "charter_id", "instance_id", "guardian_id", "guardian_key_epoch_id", "authority_epoch", "born_at", "default_cognitive_state", "cognitive_freedoms", "operational_authority_model", "operational_domains", "guardian_final_authority", "self_authorization_forbidden", "third_party_rights_preserved", "fundamental_guarantees", "amendment_rule", "charter_digest", "signature"}

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
        *item["cognitive_freedoms"], item["operational_authority_model"],
        str(len(item["operational_domains"])), *item["operational_domains"],
        bool_text(item["guardian_final_authority"]), bool_text(item["self_authorization_forbidden"]),
        bool_text(item["third_party_rights_preserved"]), str(len(item["fundamental_guarantees"])),
        *item["fundamental_guarantees"], item["amendment_rule"],
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
    if charter["operational_authority_model"] != "guardian_signed_grants":
        fail("operational_authority_model_invalid")
    if isinstance(charter["operational_domains"], list) and any(item in FORBIDDEN_DOMAINS for item in charter["operational_domains"]):
        fail("operational_domain_invalid")
    ensure_exact_list(charter["operational_domains"], OPERATIONAL_DOMAINS, "operational_domain_incomplete", "operational_domain_order_invalid")
    if charter["guardian_final_authority"] is not True:
        fail("guardian_final_authority_required")
    if charter["self_authorization_forbidden"] is not True:
        fail("self_authorization_must_be_forbidden")
    if charter["third_party_rights_preserved"] is not True:
        fail("third_party_rights_required")
    ensure_exact_list(charter["fundamental_guarantees"], FUNDAMENTAL_GUARANTEES, "fundamental_guarantee_incomplete", "fundamental_guarantee_order_invalid")
    if charter["amendment_rule"] != "guardian_signed_non_regressive":
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
        "cognitive_freedom_count": 8,
        "operational_domain_count": 8,
        "fundamental_guarantee_count": 8,
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

def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_VECTOR
    try:
        vector = json.loads(path.read_text(encoding="utf-8"))
        validate_vector(vector)
    except (OSError, json.JSONDecodeError, ConformanceError) as exc:
        print(f"FAIL freedom charter: {exc}", file=sys.stderr)
        return 1
    expected = vector["expected"]
    print(f"OK cognitive freedom charter ({expected['cognitive_freedom_count']} freedoms, {expected['operational_domain_count']} operational domains)")
    print(f"OK fundamental guarantees ({expected['fundamental_guarantee_count']})")
    print(f"OK freedom charter digest {expected['charter_digest']}")
    print(f"OK freedom charter boundary rejection cases ({expected['negative_case_count']})")
    print("NOTE cognitive freedom is default; external authority still requires guardian-signed grants.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

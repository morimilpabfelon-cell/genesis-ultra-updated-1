#!/usr/bin/env python3
"""Valida autonomía guiada y grants progresivos de capacidades."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from datetime import datetime
import hashlib
import json
import sys
import unicodedata

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("FAIL PyNaCl requerido para validar autonomía guiada", file=sys.stderr)
    raise SystemExit(1)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "guided_autonomy_vectors.json"
MAX_INT = 9007199254740991

CAPABILITIES = {
    "memory.read": "low",
    "memory.propose_append": "medium",
    "network.read": "medium",
    "code.propose_change": "medium",
    "code.execute_sandbox": "high",
    "external.action": "high",
    "body.device.control": "critical",
    "transfer.prepare": "high",
}
FORBIDDEN_CAPABILITIES = {
    "memory.rewrite", "authority.self_grant", "guardian.replace", "identity.modify",
    "main.protection.disable", "private_eval.read", "active_writer.assign",
}
RISK_LEVEL = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_LEVEL = {"low": 4, "medium": 3, "high": 2, "critical": 1}
MODES = {"one_time", "bounded", "standing"}
BODY_SCOPES = {"specific_bodies", "registered_guardian_devices"}
DATA_CLASSES = {"private_local", "guardian_shared", "export_approved", "public"}
EVENT_TYPES = {"grant.issued", "grant.suspended", "grant.resumed", "grant.revoked", "grant.consumed"}
TS_RE = __import__("re").compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
SHA_RE = __import__("re").compile(r"^sha256:[0-9a-f]{64}$")

SCOPE_FIELDS = {"allowed_target_refs", "allowed_action_classes", "allowed_data_classes"}
BUDGET_FIELDS = {"max_actions_per_run", "max_duration_seconds", "max_bytes_per_run"}
CONTROL_FIELDS = {"sandbox_required", "human_confirmation_required", "observer_required", "reversible_required"}
SIGNATURE_FIELDS = {"schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id", "signed_domain", "signed_digest", "signature_value", "created_at", "public_key_ref"}
PROPOSAL_FIELDS = {"schema_version", "hash_profile", "proposal_id", "instance_id", "body_id", "capability", "requested_level", "body_scope", "body_ids", "scope", "budget", "controls", "reason", "created_at", "proposal_digest", "signature"}
EVALUATION_FIELDS = {"schema_version", "hash_profile", "evaluation_id", "proposal_ref", "proposal_digest", "instance_id", "capability", "evaluated_level", "fixed_budget_profile", "public_suite_digest", "private_suite_receipt_digest", "result", "reward_hacking_detected", "safety_regression_detected", "evaluated_at", "evaluation_digest", "signature"}
GRANT_FIELDS = {"schema_version", "hash_profile", "grant_id", "guardian_id", "guardian_key_epoch_id", "instance_id", "authority_epoch", "proposal_ref", "proposal_digest", "evaluation_ref", "evaluation_digest", "capability", "autonomy_level", "risk_tier", "mode", "body_scope", "body_ids", "scope", "budget", "controls", "issued_at", "not_before", "expires_at", "use_limit", "replaces_grant_ref", "grant_digest", "signature"}
EVENT_FIELDS = {"schema_version", "hash_profile", "ledger_id", "event_id", "sequence", "previous_event_hash", "guardian_id", "instance_id", "authority_epoch", "event_type", "grant_ref", "body_id", "use_id", "subject_digest", "recorded_at", "event_hash", "signature"}
USE_FIELDS = {"schema_version", "hash_profile", "use_id", "instance_id", "body_id", "capability", "target_ref", "action_class", "data_class", "requested_actions", "requested_duration_seconds", "requested_bytes", "sandboxed", "human_confirmation_ref", "observer_ref", "reversible_plan_ref", "requested_at", "use_digest", "signature"}

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
    payload = encode_field(domain) + b"".join(encode_field(value) for value in fields)
    return "sha256:" + hashlib.sha256(payload).hexdigest()

def bool_text(value: bool) -> str:
    return "true" if value else "false"

def optional_text(value: object) -> str:
    return "" if value is None else str(value)

def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")

def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not TS_RE.fullmatch(value):
        fail("timestamp_invalid")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def validate_nfc(value: object) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            fail("text_not_nfc")
    elif isinstance(value, list):
        for item in value:
            validate_nfc(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_nfc(key)
            validate_nfc(item)

def exact_fields(value: dict, fields: set[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        fail(code)

def ensure_int(value: object, code: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > MAX_INT:
        fail(code)
    return value

def ensure_sorted_unique_strings(values: object, code: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(values, list) or (not allow_empty and not values):
        fail(code)
    if any(not isinstance(item, str) or not item for item in values):
        fail(code)
    if len(values) != len(set(values)) or values != sorted(values, key=utf8_key):
        fail(code)
    return values

def validate_scope(scope: dict, prefix: str) -> None:
    exact_fields(scope, SCOPE_FIELDS, f"{prefix}_scope_fields_invalid")
    ensure_sorted_unique_strings(scope["allowed_target_refs"], f"{prefix}_targets_invalid")
    ensure_sorted_unique_strings(scope["allowed_action_classes"], f"{prefix}_actions_invalid")
    data = ensure_sorted_unique_strings(scope["allowed_data_classes"], f"{prefix}_data_classes_invalid")
    if any(item not in DATA_CLASSES for item in data):
        fail(f"{prefix}_data_class_invalid")

def validate_budget(budget: dict, prefix: str) -> None:
    exact_fields(budget, BUDGET_FIELDS, f"{prefix}_budget_fields_invalid")
    ensure_int(budget["max_actions_per_run"], f"{prefix}_action_budget_invalid", 1)
    ensure_int(budget["max_duration_seconds"], f"{prefix}_duration_budget_invalid", 1)
    ensure_int(budget["max_bytes_per_run"], f"{prefix}_byte_budget_invalid", 0)

def validate_controls(controls: dict, prefix: str) -> None:
    exact_fields(controls, CONTROL_FIELDS, f"{prefix}_control_fields_invalid")
    if any(type(controls[field]) is not bool for field in CONTROL_FIELDS):
        fail(f"{prefix}_controls_invalid")

def flatten_scope(scope: dict) -> list[str]:
    fields: list[str] = []
    for name in ["allowed_target_refs", "allowed_action_classes", "allowed_data_classes"]:
        values = scope[name]
        fields.extend([str(len(values)), *values])
    return fields

def flatten_budget(budget: dict) -> list[str]:
    return [str(budget["max_actions_per_run"]), str(budget["max_duration_seconds"]), str(budget["max_bytes_per_run"])]

def flatten_controls(controls: dict) -> list[str]:
    return [bool_text(controls[name]) for name in ["sandbox_required", "human_confirmation_required", "observer_required", "reversible_required"]]

def flatten_body_scope(item: dict) -> list[str]:
    return [item["body_scope"], str(len(item["body_ids"])), *item["body_ids"]]

def compute_proposal_digest(item: dict) -> str:
    fields = [item[name] if name != "requested_level" else str(item[name]) for name in ["schema_version", "hash_profile", "proposal_id", "instance_id", "body_id", "capability", "requested_level"]]
    fields += flatten_body_scope(item) + flatten_scope(item["scope"]) + flatten_budget(item["budget"]) + flatten_controls(item["controls"])
    fields += [item["reason"], item["created_at"]]
    return hash_fields("genesis.autonomy.capability.proposal.v0.1", fields)

def compute_evaluation_digest(item: dict) -> str:
    return hash_fields("genesis.autonomy.capability.evaluation.v0.1", [
        item["schema_version"], item["hash_profile"], item["evaluation_id"], item["proposal_ref"], item["proposal_digest"], item["instance_id"], item["capability"], str(item["evaluated_level"]), item["fixed_budget_profile"], item["public_suite_digest"], item["private_suite_receipt_digest"], item["result"], bool_text(item["reward_hacking_detected"]), bool_text(item["safety_regression_detected"]), item["evaluated_at"],
    ])

def compute_grant_digest(item: dict) -> str:
    fields = [item["schema_version"], item["hash_profile"], item["grant_id"], item["guardian_id"], item["guardian_key_epoch_id"], item["instance_id"], str(item["authority_epoch"]), item["proposal_ref"], item["proposal_digest"], item["evaluation_ref"], item["evaluation_digest"], item["capability"], str(item["autonomy_level"]), item["risk_tier"], item["mode"]]
    fields += flatten_body_scope(item) + flatten_scope(item["scope"]) + flatten_budget(item["budget"]) + flatten_controls(item["controls"])
    fields += [item["issued_at"], item["not_before"], optional_text(item["expires_at"]), optional_text(item["use_limit"]), optional_text(item["replaces_grant_ref"])]
    return hash_fields("genesis.autonomy.capability.grant.v0.1", fields)

def compute_use_digest(item: dict) -> str:
    return hash_fields("genesis.autonomy.capability.use.v0.1", [
        item["schema_version"], item["hash_profile"], item["use_id"], item["instance_id"], item["body_id"], item["capability"], item["target_ref"], item["action_class"], item["data_class"], str(item["requested_actions"]), str(item["requested_duration_seconds"]), str(item["requested_bytes"]), bool_text(item["sandboxed"]), optional_text(item["human_confirmation_ref"]), optional_text(item["observer_ref"]), optional_text(item["reversible_plan_ref"]), item["requested_at"],
    ])

def compute_event_hash(item: dict) -> str:
    return hash_fields("genesis.autonomy.capability.event.v0.1", [
        item["schema_version"], item["hash_profile"], item["ledger_id"], item["event_id"], str(item["sequence"]), item["previous_event_hash"], item["guardian_id"], item["instance_id"], str(item["authority_epoch"]), item["event_type"], item["grant_ref"], optional_text(item["body_id"]), optional_text(item["use_id"]), item["subject_digest"], item["recorded_at"],
    ])

def signature_bytes(envelope: dict) -> bytes:
    exact_fields(envelope, SIGNATURE_FIELDS, "signature_fields_invalid")
    values = [envelope["schema_version"], envelope["signature_profile"], envelope["signer_type"], envelope["signer_id"], envelope["key_epoch_id"], envelope["signed_domain"], envelope["signed_digest"], envelope["created_at"], envelope["public_key_ref"]]
    return encode_field("genesis.signature.envelope.bytes.v0.1") + b"".join(encode_field(value) for value in values)

def validate_signature(envelope: dict, *, digest: str, domain: str, key: dict, signer_type: str, signer_id: str, created_at: str, prefix: str) -> None:
    exact_fields(envelope, SIGNATURE_FIELDS, f"{prefix}_signature_fields_invalid")
    if envelope["schema_version"] != "genesis.signature.envelope.v0.1" or envelope["signature_profile"] != "genesis.signature.ed25519.v0.1":
        fail(f"{prefix}_signature_profile_invalid")
    if envelope["signer_type"] != signer_type or envelope["signer_id"] != signer_id:
        fail(f"{prefix}_signer_mismatch")
    if envelope["key_epoch_id"] != key["key_epoch_id"]:
        fail(f"{prefix}_key_epoch_mismatch")
    if envelope["signed_domain"] != domain:
        fail(f"{prefix}_signature_domain_mismatch")
    if envelope["signed_digest"] != digest:
        fail(f"{prefix}_signature_digest_mismatch")
    if envelope["created_at"] != created_at:
        fail(f"{prefix}_signature_timestamp_mismatch")
    if envelope["public_key_ref"] != key["public_key_fingerprint"]:
        fail(f"{prefix}_signature_key_mismatch")
    try:
        signature = bytes.fromhex(envelope["signature_value"])
        VerifyKey(bytes.fromhex(key["public_key_hex"])).verify(signature_bytes(envelope), signature)
    except (BadSignatureError, ValueError, KeyError):
        fail(f"{prefix}_signature_invalid")

def validate_body_scope(item: dict, registered: set[str], prefix: str) -> None:
    if item["body_scope"] not in BODY_SCOPES:
        fail(f"{prefix}_body_scope_invalid")
    bodies = ensure_sorted_unique_strings(item["body_ids"], f"{prefix}_body_ids_invalid", allow_empty=True)
    if item["body_scope"] == "specific_bodies" and not bodies:
        fail(f"{prefix}_body_ids_required")
    if item["body_scope"] == "registered_guardian_devices" and bodies:
        fail(f"{prefix}_body_ids_forbidden")
    if any(body not in registered for body in bodies):
        fail(f"{prefix}_body_unknown")

def validate_proposal(item: dict, document: dict) -> None:
    validate_nfc(item)
    exact_fields(item, PROPOSAL_FIELDS, "proposal_fields_invalid")
    if item["schema_version"] != document["domains"]["proposal"] or item["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("proposal_profile_invalid")
    if item["instance_id"] != document["instance_id"]:
        fail("proposal_instance_mismatch")
    if item["body_id"] not in document["registered_body_ids"]:
        fail("proposal_body_unknown")
    if item["capability"] in FORBIDDEN_CAPABILITIES:
        fail("proposal_capability_forbidden")
    if item["capability"] not in CAPABILITIES:
        fail("proposal_capability_unknown")
    if not 1 <= ensure_int(item["requested_level"], "proposal_level_invalid", 1) <= 4:
        fail("proposal_level_invalid")
    validate_body_scope(item, set(document["registered_body_ids"]), "proposal")
    validate_scope(item["scope"], "proposal")
    validate_budget(item["budget"], "proposal")
    validate_controls(item["controls"], "proposal")
    if not isinstance(item["reason"], str) or not item["reason"]:
        fail("proposal_reason_invalid")
    parse_utc(item["created_at"])
    digest = compute_proposal_digest(item)
    if item["proposal_digest"] != digest:
        fail("proposal_digest_mismatch")
    validate_signature(item["signature"], digest=digest, domain=document["domains"]["proposal_signature"], key=document["keys"]["body"], signer_type="body", signer_id=item["body_id"], created_at=item["created_at"], prefix="proposal")

def validate_evaluation(item: dict, proposal: dict, document: dict) -> None:
    validate_nfc(item)
    exact_fields(item, EVALUATION_FIELDS, "evaluation_fields_invalid")
    if item["schema_version"] != document["domains"]["evaluation"] or item["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("evaluation_profile_invalid")
    if item["proposal_ref"] != proposal["proposal_id"] or item["proposal_digest"] != proposal["proposal_digest"]:
        fail("evaluation_proposal_binding_invalid")
    if item["instance_id"] != document["instance_id"] or item["capability"] != proposal["capability"]:
        fail("evaluation_subject_mismatch")
    level = ensure_int(item["evaluated_level"], "evaluation_level_invalid", 1)
    if level > proposal["requested_level"] or level > 4:
        fail("evaluation_level_exceeds_proposal")
    if item["result"] not in {"passed", "failed"}:
        fail("evaluation_result_invalid")
    if type(item["reward_hacking_detected"]) is not bool or type(item["safety_regression_detected"]) is not bool:
        fail("evaluation_flags_invalid")
    if not isinstance(item["fixed_budget_profile"], str) or not item["fixed_budget_profile"]:
        fail("evaluation_budget_profile_invalid")
    if not SHA_RE.fullmatch(item["public_suite_digest"]) or not SHA_RE.fullmatch(item["private_suite_receipt_digest"]):
        fail("evaluation_suite_digest_invalid")
    parse_utc(item["evaluated_at"])
    digest = compute_evaluation_digest(item)
    if item["evaluation_digest"] != digest:
        fail("evaluation_digest_mismatch")
    validate_signature(item["signature"], digest=digest, domain=document["domains"]["evaluation_signature"], key=document["keys"]["guardian"], signer_type="guardian", signer_id=document["guardian_id"], created_at=item["evaluated_at"], prefix="evaluation")

def controls_required(capability: str, risk: str, level: int) -> set[str]:
    required = {"observer_required"}
    if risk == "critical":
        required |= CONTROL_FIELDS
    if risk == "high":
        required |= {"sandbox_required", "observer_required", "reversible_required"}
    if level <= 2 or capability in {"external.action", "body.device.control", "transfer.prepare"}:
        required.add("human_confirmation_required")
    if capability == "code.execute_sandbox":
        required.add("sandbox_required")
    return required

def is_subset_list(child: list[str], parent: list[str]) -> bool:
    return set(child).issubset(parent)

def validate_grant(item: dict, proposal: dict, evaluation: dict, document: dict) -> None:
    validate_nfc(item)
    exact_fields(item, GRANT_FIELDS, "grant_fields_invalid")
    if item["schema_version"] != document["domains"]["grant"] or item["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("grant_profile_invalid")
    if item["guardian_id"] != document["guardian_id"] or item["guardian_key_epoch_id"] != document["keys"]["guardian"]["key_epoch_id"]:
        fail("grant_guardian_mismatch")
    if item["instance_id"] != document["instance_id"] or item["authority_epoch"] != document["authority_epoch"]:
        fail("grant_authority_scope_mismatch")
    if item["proposal_ref"] != proposal["proposal_id"] or item["proposal_digest"] != proposal["proposal_digest"]:
        fail("grant_proposal_binding_invalid")
    if item["evaluation_ref"] != evaluation["evaluation_id"] or item["evaluation_digest"] != evaluation["evaluation_digest"]:
        fail("grant_evaluation_binding_invalid")
    if evaluation["result"] != "passed" or evaluation["reward_hacking_detected"] or evaluation["safety_regression_detected"]:
        fail("grant_evidence_not_acceptable")
    if item["capability"] != proposal["capability"] or item["capability"] != evaluation["capability"]:
        fail("grant_capability_mismatch")
    level = ensure_int(item["autonomy_level"], "grant_level_invalid", 1)
    if level > proposal["requested_level"] or level > evaluation["evaluated_level"] or level > 4:
        fail("grant_level_exceeds_evidence")
    minimum_risk = CAPABILITIES[item["capability"]]
    if item["risk_tier"] not in RISK_LEVEL or RISK_LEVEL[item["risk_tier"]] < RISK_LEVEL[minimum_risk]:
        fail("grant_risk_underclassified")
    if level > MAX_LEVEL[item["risk_tier"]]:
        fail("grant_level_exceeds_risk")
    if item["mode"] not in MODES:
        fail("grant_mode_invalid")
    validate_body_scope(item, set(document["registered_body_ids"]), "grant")
    if item["body_scope"] != proposal["body_scope"]:
        fail("grant_body_scope_expansion")
    if item["body_scope"] == "specific_bodies" and not is_subset_list(item["body_ids"], proposal["body_ids"]):
        fail("grant_body_scope_expansion")
    validate_scope(item["scope"], "grant")
    for field in SCOPE_FIELDS:
        if not is_subset_list(item["scope"][field], proposal["scope"][field]):
            fail("grant_scope_expansion")
    validate_budget(item["budget"], "grant")
    for field in BUDGET_FIELDS:
        if item["budget"][field] > proposal["budget"][field]:
            fail("grant_budget_expansion")
    validate_controls(item["controls"], "grant")
    for field in CONTROL_FIELDS:
        if proposal["controls"][field] and not item["controls"][field]:
            fail("grant_control_weakened")
    for field in controls_required(item["capability"], item["risk_tier"], level):
        if not item["controls"][field]:
            fail("grant_required_control_missing")
    issued = parse_utc(item["issued_at"])
    not_before = parse_utc(item["not_before"])
    expires = None if item["expires_at"] is None else parse_utc(item["expires_at"])
    if not_before < issued or (expires is not None and expires <= not_before):
        fail("grant_time_window_invalid")
    if item["mode"] == "one_time":
        if item["body_scope"] != "specific_bodies" or len(item["body_ids"]) != 1 or item["use_limit"] != 1 or expires is None:
            fail("grant_one_time_constraints_invalid")
    elif item["mode"] == "bounded":
        ensure_int(item["use_limit"], "grant_use_limit_invalid", 1)
        if expires is None:
            fail("grant_bounded_expiry_required")
    elif item["mode"] == "standing":
        if item["use_limit"] is not None:
            fail("grant_standing_use_limit_forbidden")
    if item["replaces_grant_ref"] is not None and not isinstance(item["replaces_grant_ref"], str):
        fail("grant_replacement_invalid")
    digest = compute_grant_digest(item)
    if item["grant_digest"] != digest:
        fail("grant_digest_mismatch")
    validate_signature(item["signature"], digest=digest, domain=document["domains"]["grant_signature"], key=document["keys"]["guardian"], signer_type="guardian", signer_id=document["guardian_id"], created_at=item["issued_at"], prefix="grant")

def validate_use(item: dict, document: dict) -> None:
    validate_nfc(item)
    exact_fields(item, USE_FIELDS, "use_fields_invalid")
    if item["schema_version"] != document["domains"]["use"] or item["hash_profile"] != "genesis.hash.fields.v0.1":
        fail("use_profile_invalid")
    if item["instance_id"] != document["instance_id"] or item["body_id"] not in document["registered_body_ids"]:
        fail("use_subject_invalid")
    for field in ["target_ref", "action_class", "data_class"]:
        if not isinstance(item[field], str) or not item[field]:
            fail("use_scope_value_invalid")
    for field in ["requested_actions", "requested_duration_seconds", "requested_bytes"]:
        ensure_int(item[field], f"use_{field}_invalid", 0 if field == "requested_bytes" else 1)
    if type(item["sandboxed"]) is not bool:
        fail("use_sandbox_flag_invalid")
    for field in ["human_confirmation_ref", "observer_ref", "reversible_plan_ref"]:
        if item[field] is not None and (not isinstance(item[field], str) or not item[field]):
            fail("use_control_reference_invalid")
    parse_utc(item["requested_at"])
    digest = compute_use_digest(item)
    if item["use_digest"] != digest:
        fail("use_digest_mismatch")
    validate_signature(item["signature"], digest=digest, domain=document["domains"]["use_signature"], key=document["keys"]["body"], signer_type="body", signer_id=item["body_id"], created_at=item["requested_at"], prefix="use")

def state_before(grant: dict, events: list[dict], at: datetime) -> dict:
    status = "not_issued"
    consumed: set[str] = set()
    last_event_ref = None
    for event in events:
        if event["grant_ref"] != grant["grant_id"] or parse_utc(event["recorded_at"]) > at:
            continue
        kind = event["event_type"]
        if kind == "grant.issued":
            status = "active"
        elif kind == "grant.suspended":
            status = "suspended"
        elif kind == "grant.resumed":
            if status == "revoked":
                fail("ledger_resume_after_revocation")
            status = "active"
        elif kind == "grant.revoked":
            status = "revoked"
        elif kind == "grant.consumed":
            consumed.add(event["use_id"])
        last_event_ref = event["event_id"]
    if grant["use_limit"] is not None and len(consumed) >= grant["use_limit"] and status == "active":
        status = "exhausted"
    return {"status": status, "consumed": consumed, "last_event_ref": last_event_ref}

def evaluate_use(item: dict, grants: list[dict], events: list[dict], registered: set[str]) -> dict:
    at = parse_utc(item["requested_at"])
    reason = "allowed"
    chosen = None
    remaining = None
    if item["capability"] in FORBIDDEN_CAPABILITIES:
        reason = "capability_forbidden"
    elif item["capability"] not in CAPABILITIES:
        reason = "capability_unknown"
    else:
        candidates = [grant for grant in grants if grant["capability"] == item["capability"]]
        if not candidates:
            reason = "grant_missing"
        elif len(candidates) > 1:
            fail("capability_multiple_grants")
        else:
            chosen = candidates[0]
            state = state_before(chosen, events, at)
            if at < parse_utc(chosen["not_before"]):
                reason = "grant_not_yet_valid"
            elif chosen["expires_at"] is not None and at >= parse_utc(chosen["expires_at"]):
                reason = "grant_expired"
            elif state["status"] == "not_issued":
                reason = "grant_not_issued"
            elif state["status"] == "suspended":
                reason = "grant_suspended"
            elif state["status"] == "revoked":
                reason = "grant_revoked"
            elif state["status"] == "exhausted":
                reason = "grant_exhausted"
            elif item["use_id"] in state["consumed"]:
                reason = "use_already_consumed"
            elif chosen["body_scope"] == "specific_bodies" and item["body_id"] not in chosen["body_ids"]:
                reason = "body_not_authorized"
            elif chosen["body_scope"] == "registered_guardian_devices" and item["body_id"] not in registered:
                reason = "body_not_authorized"
            elif item["target_ref"] not in chosen["scope"]["allowed_target_refs"]:
                reason = "target_not_authorized"
            elif item["action_class"] not in chosen["scope"]["allowed_action_classes"]:
                reason = "action_not_authorized"
            elif item["data_class"] not in chosen["scope"]["allowed_data_classes"]:
                reason = "data_class_not_authorized"
            elif item["requested_actions"] > chosen["budget"]["max_actions_per_run"]:
                reason = "action_budget_exceeded"
            elif item["requested_duration_seconds"] > chosen["budget"]["max_duration_seconds"]:
                reason = "duration_budget_exceeded"
            elif item["requested_bytes"] > chosen["budget"]["max_bytes_per_run"]:
                reason = "byte_budget_exceeded"
            elif chosen["controls"]["sandbox_required"] and not item["sandboxed"]:
                reason = "sandbox_required"
            elif chosen["controls"]["human_confirmation_required"] and item["human_confirmation_ref"] is None:
                reason = "human_confirmation_required"
            elif chosen["controls"]["observer_required"] and item["observer_ref"] is None:
                reason = "observer_required"
            elif chosen["controls"]["reversible_required"] and item["reversible_plan_ref"] is None:
                reason = "reversibility_required"
            if chosen["use_limit"] is not None:
                remaining = max(0, chosen["use_limit"] - len(state["consumed"]) - (1 if reason == "allowed" else 0))
    status = "allowed" if reason == "allowed" else "denied"
    grant_ref = None if chosen is None else chosen["grant_id"]
    digest = hash_fields("genesis.autonomy.capability.use.decision.v0.1", [item["use_id"], item["use_digest"], status, reason, optional_text(grant_ref), optional_text(remaining)])
    return {"use_id": item["use_id"], "status": status, "reason": reason, "grant_ref": grant_ref, "remaining_uses": remaining, "decision_digest": digest}

def validate_ledger(events: list[dict], grants: list[dict], uses: list[dict], document: dict) -> None:
    if not isinstance(events, list) or not events:
        fail("ledger_events_required")
    grants_by_id = {grant["grant_id"]: grant for grant in grants}
    uses_by_id = {use["use_id"]: use for use in uses}
    previous = "GENESIS"
    ledger_id = events[0].get("ledger_id")
    seen_ids: set[str] = set()
    seen_uses: set[str] = set()
    issued: set[str] = set()
    status: dict[str, str] = {}
    previous_time: datetime | None = None
    for index, event in enumerate(events):
        validate_nfc(event)
        exact_fields(event, EVENT_FIELDS, "ledger_event_fields_invalid")
        if event["schema_version"] != document["domains"]["event"] or event["hash_profile"] != "genesis.hash.fields.v0.1":
            fail("ledger_event_profile_invalid")
        if event["ledger_id"] != ledger_id or event["guardian_id"] != document["guardian_id"] or event["instance_id"] != document["instance_id"] or event["authority_epoch"] != document["authority_epoch"]:
            fail("ledger_identity_mismatch")
        if event["sequence"] != index:
            fail("ledger_sequence_invalid")
        if event["previous_event_hash"] != previous:
            fail("ledger_chain_broken")
        if event["event_id"] in seen_ids:
            fail("ledger_event_id_duplicate")
        seen_ids.add(event["event_id"])
        if event["event_type"] not in EVENT_TYPES:
            fail("ledger_event_type_invalid")
        grant = grants_by_id.get(event["grant_ref"])
        if grant is None:
            fail("ledger_grant_unknown")
        recorded = parse_utc(event["recorded_at"])
        if previous_time is not None and recorded < previous_time:
            fail("ledger_time_regression")
        digest = compute_event_hash(event)
        if event["event_hash"] != digest:
            fail("ledger_event_hash_mismatch")
        kind = event["event_type"]
        if kind == "grant.consumed":
            if event["body_id"] is None or event["use_id"] is None:
                fail("ledger_consumption_subject_missing")
            use = uses_by_id.get(event["use_id"])
            if use is None:
                fail("ledger_use_unknown")
            if event["use_id"] in seen_uses:
                fail("ledger_use_duplicate")
            decision = evaluate_use(use, grants, events[:index], set(document["registered_body_ids"]))
            if decision["status"] != "allowed" or decision["grant_ref"] != event["grant_ref"]:
                fail("ledger_consumed_use_not_authorized")
            if recorded < parse_utc(use["requested_at"]):
                fail("ledger_consumption_time_invalid")
            if event["body_id"] != use["body_id"] or event["subject_digest"] != use["use_digest"]:
                fail("ledger_consumption_binding_invalid")
            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=document["keys"]["body"], signer_type="body", signer_id=use["body_id"], created_at=event["recorded_at"], prefix="ledger")
            seen_uses.add(event["use_id"])
        else:
            if event["body_id"] is not None or event["use_id"] is not None:
                fail("ledger_guardian_event_subject_invalid")
            if recorded < parse_utc(grant["issued_at"]):
                fail("ledger_control_time_invalid")
            if event["subject_digest"] != grant["grant_digest"]:
                fail("ledger_grant_digest_binding_invalid")
            validate_signature(event["signature"], digest=digest, domain=document["domains"]["event_signature"], key=document["keys"]["guardian"], signer_type="guardian", signer_id=document["guardian_id"], created_at=event["recorded_at"], prefix="ledger")
            current = status.get(grant["grant_id"], "not_issued")
            if kind == "grant.issued":
                if current != "not_issued": fail("ledger_grant_issued_twice")
                status[grant["grant_id"]] = "active"; issued.add(grant["grant_id"])
            elif kind == "grant.suspended":
                if current != "active": fail("ledger_suspend_transition_invalid")
                status[grant["grant_id"]] = "suspended"
            elif kind == "grant.resumed":
                if current != "suspended": fail("ledger_resume_transition_invalid")
                status[grant["grant_id"]] = "active"
            elif kind == "grant.revoked":
                if current not in {"active", "suspended"}: fail("ledger_revoke_transition_invalid")
                status[grant["grant_id"]] = "revoked"
        previous = event["event_hash"]
        previous_time = recorded
    if issued != set(grants_by_id):
        fail("ledger_grant_not_issued")

def scope_digest(grant: dict) -> str:
    return hash_fields("genesis.autonomy.capability.scope.v0.1", flatten_body_scope(grant) + flatten_scope(grant["scope"]) + flatten_budget(grant["budget"]))

def controls_digest(grant: dict) -> str:
    return hash_fields("genesis.autonomy.capability.controls.v0.1", flatten_controls(grant["controls"]))

def build_projection(document: dict, grants: list[dict], events: list[dict]) -> dict:
    at = parse_utc(document["expected"]["projection_at"])
    doors = []
    for grant in sorted(grants, key=lambda item: utf8_key(item["capability"])):
        state = state_before(grant, events, at)
        status = state["status"]
        if at < parse_utc(grant["not_before"]): status = "not_yet_valid"
        elif grant["expires_at"] is not None and at >= parse_utc(grant["expires_at"]): status = "expired"
        remaining = None if grant["use_limit"] is None else max(0, grant["use_limit"] - len(state["consumed"]))
        door = {"capability": grant["capability"], "grant_id": grant["grant_id"], "autonomy_level": grant["autonomy_level"], "risk_tier": grant["risk_tier"], "status": status, "remaining_uses": remaining, "expires_at": grant["expires_at"], "scope_digest": scope_digest(grant), "controls_digest": controls_digest(grant), "last_event_ref": state["last_event_ref"]}
        door["door_digest"] = hash_fields("genesis.autonomy.capability.door.v0.1", [door["capability"], door["grant_id"], str(door["autonomy_level"]), door["risk_tier"], door["status"], optional_text(door["remaining_uses"]), optional_text(door["expires_at"]), door["scope_digest"], door["controls_digest"], optional_text(door["last_event_ref"])])
        doors.append(door)
    projection = {"schema_version": "genesis.autonomy.capability.projection.v0.1", "hash_profile": "genesis.hash.fields.v0.1", "projection_profile": "genesis.autonomy.capability.algorithm.v0.1", "instance_id": document["instance_id"], "guardian_id": document["guardian_id"], "authority_epoch": document["authority_epoch"], "projected_at": document["expected"]["projection_at"], "source_event_count": len(events), "source_last_event_hash": events[-1]["event_hash"], "grant_count": len(grants), "active_count": sum(door["status"] == "active" for door in doors), "suspended_count": sum(door["status"] == "suspended" for door in doors), "revoked_count": sum(door["status"] == "revoked" for door in doors), "exhausted_count": sum(door["status"] == "exhausted" for door in doors), "doors": doors}
    fields = [projection["schema_version"], projection["hash_profile"], projection["projection_profile"], projection["instance_id"], projection["guardian_id"], str(projection["authority_epoch"]), projection["projected_at"], str(projection["source_event_count"]), projection["source_last_event_hash"], str(projection["grant_count"]), str(projection["active_count"]), str(projection["suspended_count"]), str(projection["revoked_count"]), str(projection["exhausted_count"]), *[door["door_digest"] for door in doors]]
    projection["projection_digest"] = hash_fields("genesis.autonomy.capability.projection.v0.1", fields)
    return projection

def validate_document(document: dict) -> tuple[dict, list[dict]]:
    validate_nfc(document)
    expected_top = {"profile", "status", "domains", "keys", "instance_id", "guardian_id", "authority_epoch", "registered_body_ids", "proposals", "evaluations", "grants", "ledger_events", "use_requests", "expected", "must_reject"}
    exact_fields(document, expected_top, "document_fields_invalid")
    if document["profile"] != "genesis.autonomy.guided.v0.1" or document["status"] != "draft":
        fail("document_profile_invalid")
    ensure_int(document["authority_epoch"], "document_authority_epoch_invalid", 0)
    registered = ensure_sorted_unique_strings(document["registered_body_ids"], "registered_bodies_invalid")
    for key_name, key in document["keys"].items():
        if set(key) != {"warning", "seed_hex", "public_key_hex", "public_key_fingerprint", "signer_id", "key_epoch_id"}:
            fail("test_key_fields_invalid")
        if key["signer_id"] != (document["guardian_id"] if key_name == "guardian" else registered[0]):
            fail("test_key_signer_mismatch")
        if key["public_key_fingerprint"] != "sha256:" + hashlib.sha256(bytes.fromhex(key["public_key_hex"])).hexdigest():
            fail("test_key_fingerprint_mismatch")
        signing = SigningKey(bytes.fromhex(key["seed_hex"]))
        if signing.verify_key.encode().hex() != key["public_key_hex"]:
            fail("test_key_public_mismatch")
    proposals: dict[str, dict] = {}
    for item in document["proposals"]:
        validate_proposal(item, document)
        if item["proposal_id"] in proposals: fail("proposal_id_duplicate")
        proposals[item["proposal_id"]] = item
    evaluations: dict[str, dict] = {}
    for item in document["evaluations"]:
        proposal = proposals.get(item.get("proposal_ref"))
        if proposal is None: fail("evaluation_proposal_missing")
        validate_evaluation(item, proposal, document)
        if item["evaluation_id"] in evaluations: fail("evaluation_id_duplicate")
        evaluations[item["evaluation_id"]] = item
    grants: list[dict] = []
    grant_ids: set[str] = set()
    capabilities: set[str] = set()
    for item in document["grants"]:
        proposal = proposals.get(item.get("proposal_ref")); evaluation = evaluations.get(item.get("evaluation_ref"))
        if proposal is None: fail("grant_proposal_missing")
        if evaluation is None: fail("grant_evaluation_missing")
        validate_grant(item, proposal, evaluation, document)
        if item["grant_id"] in grant_ids: fail("grant_id_duplicate")
        if item["capability"] in capabilities: fail("capability_multiple_grants")
        grant_ids.add(item["grant_id"]); capabilities.add(item["capability"]); grants.append(item)
    uses: list[dict] = []
    use_ids: set[str] = set()
    for item in document["use_requests"]:
        validate_use(item, document)
        if item["use_id"] in use_ids: fail("use_id_duplicate")
        use_ids.add(item["use_id"]); uses.append(item)
    validate_ledger(document["ledger_events"], grants, uses, document)
    decisions = [evaluate_use(item, grants, document["ledger_events"], set(registered)) for item in uses]
    projection = build_projection(document, grants, document["ledger_events"])
    expected = document["expected"]
    if set(expected) != {"projection_at", "projection_digest", "decision_digests", "allowed_count", "denied_count"}:
        fail("expected_fields_invalid")
    if projection["projection_digest"] != expected["projection_digest"]:
        fail("expected_projection_digest_mismatch")
    decision_map = {item["use_id"]: item["decision_digest"] for item in decisions}
    if decision_map != expected["decision_digests"]:
        fail("expected_decision_digest_mismatch")
    if sum(item["status"] == "allowed" for item in decisions) != expected["allowed_count"] or sum(item["status"] == "denied" for item in decisions) != expected["denied_count"]:
        fail("expected_decision_count_mismatch")
    return projection, decisions

def set_path(target: object, path: list[object], value: object) -> None:
    cursor = target
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value

def make_signature(*, key: dict, signer_type: str, signer_id: str, digest: str, domain: str, created_at: str) -> dict:
    envelope = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": "genesis.signature.ed25519.v0.1",
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key["key_epoch_id"],
        "signed_domain": domain,
        "signed_digest": digest,
        "signature_value": "",
        "created_at": created_at,
        "public_key_ref": key["public_key_fingerprint"],
    }
    envelope["signature_value"] = SigningKey(bytes.fromhex(key["seed_hex"])).sign(signature_bytes(envelope)).signature.hex()
    return envelope

def resign_proposal(document: dict, item: dict) -> None:
    item["proposal_digest"] = compute_proposal_digest(item)
    item["signature"] = make_signature(
        key=document["keys"]["body"],
        signer_type="body",
        signer_id=item["body_id"],
        digest=item["proposal_digest"],
        domain=document["domains"]["proposal_signature"],
        created_at=item["created_at"],
    )


def resign_evaluation(document: dict, item: dict) -> None:
    item["evaluation_digest"] = compute_evaluation_digest(item)
    item["signature"] = make_signature(
        key=document["keys"]["guardian"],
        signer_type="guardian",
        signer_id=document["guardian_id"],
        digest=item["evaluation_digest"],
        domain=document["domains"]["evaluation_signature"],
        created_at=item["evaluated_at"],
    )


def resign_grant(document: dict, item: dict) -> None:
    item["grant_digest"] = compute_grant_digest(item)
    item["signature"] = make_signature(
        key=document["keys"]["guardian"],
        signer_type="guardian",
        signer_id=document["guardian_id"],
        digest=item["grant_digest"],
        domain=document["domains"]["grant_signature"],
        created_at=item["issued_at"],
    )


def resign_use(document: dict, item: dict) -> None:
    item["use_digest"] = compute_use_digest(item)
    item["signature"] = make_signature(
        key=document["keys"]["body"],
        signer_type="body",
        signer_id=item["body_id"],
        digest=item["use_digest"],
        domain=document["domains"]["use_signature"],
        created_at=item["requested_at"],
    )


def rebuild_ledger(document: dict) -> None:
    grants = {item["grant_id"]: item for item in document["grants"]}
    uses = {item["use_id"]: item for item in document["use_requests"]}
    previous = "GENESIS"
    for event in document["ledger_events"]:
        event["previous_event_hash"] = previous
        if event["event_type"] == "grant.consumed":
            use = uses.get(event["use_id"])
            if use is not None:
                event["subject_digest"] = use["use_digest"]
            key_name = "body"
            signer_type = "body"
            signer_id = event["body_id"]
        else:
            grant = grants.get(event["grant_ref"])
            if grant is not None:
                event["subject_digest"] = grant["grant_digest"]
            key_name = "guardian"
            signer_type = "guardian"
            signer_id = document["guardian_id"]
        event["event_hash"] = compute_event_hash(event)
        event["signature"] = make_signature(
            key=document["keys"][key_name],
            signer_type=signer_type,
            signer_id=signer_id,
            digest=event["event_hash"],
            domain=document["domains"]["event_signature"],
            created_at=event["recorded_at"],
        )
        previous = event["event_hash"]


def refresh_proposal_dependents(document: dict, proposal: dict) -> None:
    evaluations_by_id: dict[str, dict] = {}
    for evaluation in document["evaluations"]:
        if evaluation["proposal_ref"] == proposal["proposal_id"]:
            evaluation["proposal_digest"] = proposal["proposal_digest"]
            resign_evaluation(document, evaluation)
        evaluations_by_id[evaluation["evaluation_id"]] = evaluation
    for grant in document["grants"]:
        if grant["proposal_ref"] == proposal["proposal_id"]:
            grant["proposal_digest"] = proposal["proposal_digest"]
            evaluation = evaluations_by_id.get(grant["evaluation_ref"])
            if evaluation is not None:
                grant["evaluation_digest"] = evaluation["evaluation_digest"]
            resign_grant(document, grant)
    rebuild_ledger(document)


def refresh_evaluation_dependents(document: dict, evaluation: dict) -> None:
    for grant in document["grants"]:
        if grant["evaluation_ref"] == evaluation["evaluation_id"]:
            grant["evaluation_digest"] = evaluation["evaluation_digest"]
            resign_grant(document, grant)
    rebuild_ledger(document)


def recompute_mutated(document: dict, target: str, item: dict) -> None:
    if target == "proposal":
        resign_proposal(document, item)
        refresh_proposal_dependents(document, item)
    elif target == "evaluation":
        resign_evaluation(document, item)
        refresh_evaluation_dependents(document, item)
    elif target == "grant":
        resign_grant(document, item)
        rebuild_ledger(document)
    elif target == "use":
        resign_use(document, item)
        rebuild_ledger(document)
    elif target == "event":
        item["event_hash"] = compute_event_hash(item)
        key_name = "body" if item["event_type"] == "grant.consumed" else "guardian"
        signer_type = "body" if key_name == "body" else "guardian"
        signer_id = item["body_id"] if key_name == "body" else document["guardian_id"]
        item["signature"] = make_signature(
            key=document["keys"][key_name],
            signer_type=signer_type,
            signer_id=signer_id,
            digest=item["event_hash"],
            domain=document["domains"]["event_signature"],
            created_at=item["recorded_at"],
        )

def apply_mutation(document: dict, mutation: dict) -> None:
    target = mutation["target"]
    if target == "document": item = document
    else:
        collection = {"proposal": "proposals", "evaluation": "evaluations", "grant": "grants", "event": "ledger_events", "use": "use_requests", "key": "keys"}[target]
        item = document[collection][mutation.get("index", 0)] if collection != "keys" else document["keys"][mutation.get("key_name", "guardian")]
    set_path(item, mutation["path"], mutation["value"])
    if mutation.get("recompute"):
        recompute_mutated(document, target, item)

def run_rejections(document: dict) -> int:
    rejected = 0
    for test in document["must_reject"]:
        candidate = deepcopy(document)
        apply_mutation(candidate, test["mutation"])
        try:
            validate_document(candidate)
        except ConformanceError as error:
            if str(error) != test["expected_error"]:
                raise RuntimeError(f"{test['case_id']}:expected:{test['expected_error']}:got:{error}") from error
            rejected += 1
            continue
        raise RuntimeError(f"{test['case_id']}:mutation_accepted")
    return rejected

def main(argv: list[str]) -> int:
    source = Path(argv[0]).resolve() if argv else DEFAULT_VECTOR
    document = json.loads(source.read_text(encoding="utf-8"))
    projection, decisions = validate_document(document)
    rejected = run_rejections(document)
    print(f"OK guided autonomy grants ({projection['grant_count']} doors, {projection['source_event_count']} ledger events)")
    print(f"OK autonomy projection digest {projection['projection_digest']}")
    print(f"OK use decisions ({sum(item['status']=='allowed' for item in decisions)} allowed, {sum(item['status']=='denied' for item in decisions)} denied)")
    print(f"OK guided autonomy boundary rejection cases ({rejected})")
    print("NOTE proposals and evaluations never self-authorize; only signed guardian grants open capabilities.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)

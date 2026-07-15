#!/usr/bin/env python3
"""Validate the signed memory-gate -> append-only event -> retrieval bridge independently."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unicodedata
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from validate_memory_retrieval import (
    ConformanceError as RetrievalError,
    DOMAINS as RETRIEVAL_DOMAINS,
    build_projection,
    hash_fields as retrieval_hash_fields,
    normalize_terms,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "memory_gate_retrieval_bridge_vectors.json"
PROFILE = "genesis.memory.gate.retrieval.bridge.v0.1"
RECEIPT_SCHEMA = "genesis.memory.gate.retrieval.bridge.receipt.v0.1"
VIEW_SCHEMA = "genesis.memory.retrieval.accepted.view.v0.1"
HASH_PROFILE = "genesis.hash.fields.v0.1"
DOMAINS = {
    "observation": "genesis.sense.observation.v0.1",
    "observation_signature": "genesis.sense.observation.signature.v0.1",
    "gate_decision": "genesis.memory.gate.decision.v0.1",
    "gate_signature": "genesis.memory.gate.decision.signature.v0.1",
    "memory_event": "genesis.memory.event.v0.1",
    "accepted_view": "genesis.memory.retrieval.accepted.view.v0.1",
    "bridge_receipt": "genesis.memory.gate.retrieval.bridge.receipt.v0.1",
}
OBSERVATION_FIELDS = {
    "schema_version", "hash_profile", "observation_id", "instance_id", "body_id",
    "observation_sequence", "sense", "source_kind", "captured_at", "payload_digest",
    "payload_media_type", "evidence_digest", "privacy", "observation_digest", "signature",
}
GATE_FIELDS = {
    "schema_version", "hash_profile", "decision_id", "observation_id", "observation_digest",
    "instance_id", "body_id", "decision", "reason_code", "policy_profile", "decided_at",
    "memory_event_ref", "decision_digest", "signature",
}
EVENT_FIELDS = {
    "schema_version", "hash_profile", "event_id", "instance_id", "body_id", "sequence",
    "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
    "observed_at", "provenance_digest", "privacy", "event_hash",
}
VIEW_FIELDS = {
    "schema_version", "hash_profile", "event_id", "content_digest", "content_type",
    "normalized_text", "generated_at", "generator_profile", "view_digest",
}
KEY_FIELDS = {"public_key_ref", "public_key_hex"}
QUERY_FIELDS = {"query_id", "text", "top_k", "as_of_sequence", "anchor_event_refs"}
SENSITIVE_FIELDS = {
    "raw_content", "payload", "private_key", "secret", "credential", "token",
    "absolute_path", "platform_account", "platform_handle", "embedding",
}


class BridgeError(ValueError):
    """Stable bridge error shared by independent implementations."""


def frame(value: str) -> bytes:
    if not isinstance(value, str):
        raise BridgeError("bridge_field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise BridgeError("bridge_text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    return prefix + hashlib.sha256(frame(domain) + b"".join(frame(item) for item in fields)).hexdigest()


def exact_fields(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise BridgeError(f"{label}_invalid")
    extra = set(value) - expected
    if extra & SENSITIVE_FIELDS:
        raise BridgeError("bridge_contains_sensitive_field")
    if set(value) != expected:
        raise BridgeError(f"{label}_fields_invalid")


def validate_nfc(value) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise BridgeError("bridge_text_not_nfc")
    elif isinstance(value, list):
        for child in value:
            validate_nfc(child)
    elif isinstance(value, dict):
        for key, child in value.items():
            validate_nfc(key)
            validate_nfc(child)


def signature_bytes(envelope: dict) -> bytes:
    return frame("genesis.signature.envelope.bytes.v0.1") + b"".join(frame(envelope[field]) for field in [
        "schema_version", "signature_profile", "signer_type", "signer_id", "key_epoch_id",
        "signed_domain", "signed_digest", "created_at", "public_key_ref",
    ])


def load_verification_keys(entries: list[dict]) -> dict[str, VerifyKey]:
    if not isinstance(entries, list) or not entries:
        raise BridgeError("bridge_verification_keys_invalid")
    result: dict[str, VerifyKey] = {}
    for entry in entries:
        exact_fields(entry, KEY_FIELDS, "bridge_verification_key")
        raw_hex = entry["public_key_hex"]
        if len(raw_hex) != 64 or any(char not in "0123456789abcdef" for char in raw_hex):
            raise BridgeError("bridge_public_key_encoding_invalid")
        raw = bytes.fromhex(raw_hex)
        fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
        if fingerprint != entry["public_key_ref"]:
            raise BridgeError("bridge_public_key_ref_mismatch")
        if fingerprint in result:
            raise BridgeError("bridge_public_key_duplicate")
        result[fingerprint] = VerifyKey(raw)
    return result


def verify_signature(envelope: dict, expected: dict, keys: dict[str, VerifyKey], prefix: str) -> None:
    if not isinstance(envelope, dict):
        raise BridgeError(f"{prefix}_signature_invalid")
    if (
        envelope.get("schema_version") != "genesis.signature.envelope.v0.1"
        or envelope.get("signature_profile") != "genesis.signature.ed25519.v0.1"
        or envelope.get("signer_type") != "body"
        or envelope.get("signer_id") != expected["body_id"]
        or envelope.get("signed_domain") != expected["domain"]
        or envelope.get("signed_digest") != expected["digest"]
        or envelope.get("created_at") != expected["created_at"]
    ):
        raise BridgeError(f"{prefix}_signature_unbound")
    verify_key = keys.get(envelope.get("public_key_ref"))
    if verify_key is None:
        raise BridgeError(f"{prefix}_signature_key_unknown")
    signature_hex = envelope.get("signature_value")
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        raise BridgeError(f"{prefix}_signature_invalid")
    try:
        signature = bytes.fromhex(signature_hex)
        verify_key.verify(signature_bytes(envelope), signature)
    except (ValueError, BadSignatureError):
        raise BridgeError(f"{prefix}_signature_invalid") from None


def compute_observation_digest(observation: dict) -> str:
    return hash_fields(DOMAINS["observation"], [
        observation["schema_version"], observation["hash_profile"], observation["observation_id"],
        observation["instance_id"], observation["body_id"], str(observation["observation_sequence"]),
        observation["sense"], observation["source_kind"], observation["captured_at"],
        observation["payload_digest"], observation["payload_media_type"], observation["evidence_digest"],
        observation["privacy"],
    ])


def compute_gate_digest(decision: dict) -> str:
    return hash_fields(DOMAINS["gate_decision"], [
        decision["schema_version"], decision["hash_profile"], decision["decision_id"],
        decision["observation_id"], decision["observation_digest"], decision["instance_id"],
        decision["body_id"], decision["decision"], decision["reason_code"], decision["policy_profile"],
        decision["decided_at"], "" if decision["memory_event_ref"] is None else decision["memory_event_ref"],
    ])


def compute_memory_event_hash(event: dict) -> str:
    return hash_fields(DOMAINS["memory_event"], [
        event["schema_version"], event["event_id"], event["instance_id"], event["body_id"],
        str(event["sequence"]), event["previous_event_hash"], event["event_type"], event["actor"],
        event["content_digest"], event["content_type"], event["observed_at"],
        event["provenance_digest"], event["privacy"],
    ], "evsha256:")


def compute_view_digest(view: dict) -> str:
    return hash_fields(DOMAINS["accepted_view"], [
        view["schema_version"], view["hash_profile"], view["event_id"], view["content_digest"],
        view["content_type"], view["normalized_text"], view["generated_at"], view["generator_profile"],
    ])


def compute_record_id(record: dict) -> str:
    return retrieval_hash_fields(RETRIEVAL_DOMAINS["record"], [
        record["event_id"], record["gate_decision_ref"], record["content_digest"], record["accepted_at"],
    ], "rrsha256:")


def validate_top_level(document: dict) -> None:
    if not isinstance(document, dict):
        raise BridgeError("bridge_document_invalid")
    if document.get("profile") != PROFILE:
        raise BridgeError("bridge_profile_invalid")
    if document.get("domains") != DOMAINS:
        raise BridgeError("bridge_domains_invalid")
    for field in ["observations", "gate_decisions", "source_memory_events", "accepted_content_views", "queries"]:
        if not isinstance(document.get(field), list):
            raise BridgeError(f"bridge_{field}_invalid")
        validate_nfc(document[field])
    validate_nfc(document.get("verification_keys"))
    validate_nfc(document.get("associative_projection", {}))
    count = len(document["source_memory_events"])
    if count == 0:
        raise BridgeError("bridge_source_memory_events_invalid")
    if not (
        len(document["observations"]) == count
        and len(document["gate_decisions"]) == count
        and len(document["accepted_content_views"]) == count
    ):
        raise BridgeError("bridge_coverage_invalid")
    for query in document["queries"]:
        exact_fields(query, QUERY_FIELDS, "bridge_query")


def build_accepted_records(document: dict) -> list[dict]:
    validate_top_level(document)
    keys = load_verification_keys(document.get("verification_keys"))
    observations = document["observations"]
    decisions = document["gate_decisions"]
    events = document["source_memory_events"]
    views = document["accepted_content_views"]
    observation_by_id: dict[str, dict] = {}
    decision_by_event: dict[str, tuple[dict, dict]] = {}
    view_by_event: dict[str, dict] = {}

    for observation in observations:
        exact_fields(observation, OBSERVATION_FIELDS, "bridge_observation")
        digest = compute_observation_digest(observation)
        if digest != observation["observation_digest"]:
            raise BridgeError("observation_digest_mismatch")
        verify_signature(observation["signature"], {
            "digest": digest,
            "domain": DOMAINS["observation_signature"],
            "body_id": observation["body_id"],
            "created_at": observation["captured_at"],
        }, keys, "observation")
        if observation["observation_id"] in observation_by_id:
            raise BridgeError("bridge_observation_duplicate")
        observation_by_id[observation["observation_id"]] = observation

    for decision in decisions:
        exact_fields(decision, GATE_FIELDS, "bridge_gate_decision")
        if decision["decision"] != "accepted":
            raise BridgeError("bridge_gate_not_accepted")
        if not isinstance(decision["memory_event_ref"], str):
            raise BridgeError("bridge_gate_event_ref_missing")
        observation = observation_by_id.get(decision["observation_id"])
        if observation is None:
            raise BridgeError("bridge_gate_observation_unknown")
        if (
            decision["observation_digest"] != observation["observation_digest"]
            or decision["instance_id"] != observation["instance_id"]
            or decision["body_id"] != observation["body_id"]
        ):
            raise BridgeError("bridge_gate_observation_mismatch")
        digest = compute_gate_digest(decision)
        if digest != decision["decision_digest"]:
            raise BridgeError("gate_decision_digest_mismatch")
        verify_signature(decision["signature"], {
            "digest": digest,
            "domain": DOMAINS["gate_signature"],
            "body_id": decision["body_id"],
            "created_at": decision["decided_at"],
        }, keys, "gate")
        if decision["memory_event_ref"] in decision_by_event:
            raise BridgeError("bridge_gate_duplicate")
        decision_by_event[decision["memory_event_ref"]] = (decision, observation)

    for view in views:
        exact_fields(view, VIEW_FIELDS, "accepted_view")
        if view["schema_version"] != VIEW_SCHEMA or view["hash_profile"] != HASH_PROFILE:
            raise BridgeError("accepted_view_profile_invalid")
        if view["view_digest"] != compute_view_digest(view):
            raise BridgeError("accepted_view_digest_mismatch")
        terms = normalize_terms(view["normalized_text"])
        if not terms:
            raise BridgeError("accepted_record_text_empty")
        if len(view["normalized_text"].encode("utf-8")) > 4096:
            raise BridgeError("accepted_record_text_too_large")
        if view["event_id"] in view_by_event:
            raise BridgeError("accepted_view_duplicate")
        view_by_event[view["event_id"]] = view

    records: list[dict] = []
    expected_previous = "GENESIS"
    instance_id = events[0]["instance_id"]
    event_ids: set[str] = set()
    for index, event in enumerate(events):
        exact_fields(event, EVENT_FIELDS, "bridge_memory_event")
        if event["instance_id"] != instance_id:
            raise BridgeError("bridge_instance_mismatch")
        if event["sequence"] != index:
            raise BridgeError("source_memory_sequence_invalid")
        if event["previous_event_hash"] != expected_previous:
            raise BridgeError("source_memory_chain_broken")
        if event["event_hash"] != compute_memory_event_hash(event):
            raise BridgeError("source_memory_event_hash_mismatch")
        if event["event_id"] in event_ids:
            raise BridgeError("source_memory_event_duplicate")
        event_ids.add(event["event_id"])
        expected_previous = event["event_hash"]
        linked = decision_by_event.get(event["event_id"])
        view = view_by_event.get(event["event_id"])
        if linked is None or view is None:
            raise BridgeError("bridge_coverage_invalid")
        decision, observation = linked
        if decision["memory_event_ref"] != event["event_id"]:
            raise BridgeError("bridge_gate_event_ref_mismatch")
        if (
            event["instance_id"] != observation["instance_id"]
            or event["body_id"] != observation["body_id"]
            or event["actor"] != "body"
            or event["event_type"] != f"sense.{observation['sense']}.observation"
        ):
            raise BridgeError("bridge_memory_observation_mismatch")
        if event["content_digest"] != observation["payload_digest"]:
            raise BridgeError("memory_content_digest_mismatch")
        if event["content_type"] != observation["payload_media_type"]:
            raise BridgeError("memory_content_type_mismatch")
        if event["observed_at"] != observation["captured_at"]:
            raise BridgeError("memory_observed_at_mismatch")
        if event["provenance_digest"] != observation["observation_digest"]:
            raise BridgeError("memory_provenance_digest_mismatch")
        if event["privacy"] != observation["privacy"]:
            raise BridgeError("memory_privacy_mismatch")
        if view["content_digest"] != event["content_digest"]:
            raise BridgeError("bridge_view_content_digest_mismatch")
        if view["content_type"] != event["content_type"]:
            raise BridgeError("bridge_view_content_type_mismatch")
        if view["generated_at"] < decision["decided_at"]:
            raise BridgeError("accepted_view_before_gate")
        record = {
            "record_id": "",
            "event_id": event["event_id"],
            "gate_decision_ref": decision["decision_id"],
            "content_digest": event["content_digest"],
            "normalized_text": view["normalized_text"],
            "accepted_at": decision["decided_at"],
        }
        record["record_id"] = compute_record_id(record)
        records.append(record)
    return records


def compute_bridge_digest(receipt: dict, document: dict, records: list[dict], projection: dict) -> str:
    return hash_fields(DOMAINS["bridge_receipt"], [
        receipt["schema_version"], receipt["bridge_profile"], receipt["instance_id"],
        str(receipt["source_first_sequence"]), str(receipt["source_last_sequence"]), str(len(records)),
        *[item["observation_digest"] for item in document["observations"]],
        *[item["decision_digest"] for item in document["gate_decisions"]],
        *[item["event_hash"] for item in document["source_memory_events"]],
        *[item["view_digest"] for item in document["accepted_content_views"]],
        *[item["record_id"] for item in records], projection["projection_digest"],
    ])


def build_bridge_snapshot(document: dict) -> dict:
    records = build_accepted_records(document)
    retrieval_document = {
        "profile": "genesis.memory.retrieval.conformance.v0.1",
        "status": "runtime-derived",
        "domains": RETRIEVAL_DOMAINS,
        "source_memory_events": deepcopy(document["source_memory_events"]),
        "accepted_records": records,
        "associative_projection": deepcopy(document.get("associative_projection", {})),
        "queries": deepcopy(document.get("queries", [])),
    }
    projection = build_projection(retrieval_document)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "hash_profile": HASH_PROFILE,
        "bridge_profile": PROFILE,
        "instance_id": document["source_memory_events"][0]["instance_id"],
        "source_first_sequence": document["source_memory_events"][0]["sequence"],
        "source_last_sequence": document["source_memory_events"][-1]["sequence"],
        "accepted_record_count": len(records),
        "bridge_digest": "",
    }
    receipt["bridge_digest"] = compute_bridge_digest(receipt, document, records, projection)
    return {**retrieval_document, "projection": projection, "bridge_receipt": receipt}


def set_path(target, parts: list, value) -> None:
    cursor = target
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = value


def delete_path(target, parts: list) -> None:
    cursor = target
    for part in parts[:-1]:
        cursor = cursor[part]
    last = parts[-1]
    if isinstance(cursor, list):
        cursor.pop(int(last))
    else:
        del cursor[last]


def apply_mutation(document: dict, mutation: dict) -> None:
    operation = mutation["operation"]
    if operation == "set":
        set_path(document, mutation["path"], mutation["value"])
    elif operation == "delete":
        delete_path(document, mutation["path"])
    elif operation == "duplicate":
        source = document
        for part in mutation["path"]:
            source = source[part]
        array = document
        for part in mutation["target"]:
            array = array[part]
        array.append(deepcopy(source))
    else:
        raise ValueError(f"unknown_bridge_mutation:{operation}")
    if isinstance(mutation.get("recompute_view_digest_index"), int):
        view = document["accepted_content_views"][mutation["recompute_view_digest_index"]]
        view["view_digest"] = compute_view_digest(view)
    if isinstance(mutation.get("recompute_event_hash_index"), int):
        event = document["source_memory_events"][mutation["recompute_event_hash_index"]]
        event["event_hash"] = compute_memory_event_hash(event)


def validate_conformance(document: dict) -> tuple[dict, int]:
    snapshot = build_bridge_snapshot(document)
    expected = document.get("expected")
    if not isinstance(expected, dict):
        raise BridgeError("bridge_expected_missing")
    if snapshot["accepted_records"] != expected["accepted_records"]:
        raise BridgeError("bridge_expected_records_mismatch")
    if snapshot["projection"]["projection_digest"] != expected["projection_digest"]:
        raise BridgeError("bridge_expected_projection_digest_mismatch")
    if snapshot["bridge_receipt"]["bridge_digest"] != expected["bridge_digest"]:
        raise BridgeError("bridge_expected_receipt_digest_mismatch")
    actual_query = snapshot["projection"]["query_results"][0]["result_digest"] if snapshot["projection"]["query_results"] else None
    if actual_query != expected["query_result_digest"]:
        raise BridgeError("bridge_expected_query_digest_mismatch")
    rejected = 0
    for case in document.get("must_reject", []):
        mutated = deepcopy(document)
        try:
            apply_mutation(mutated, case["mutation"])
            build_bridge_snapshot(mutated)
        except (BridgeError, RetrievalError) as error:
            if str(error) != case["expected_error"]:
                raise RuntimeError(f"{case['case_id']}: expected {case['expected_error']}, got {error}") from error
            rejected += 1
            continue
        raise RuntimeError(f"{case['case_id']}: mutation accepted")
    return snapshot, rejected


def main() -> None:
    path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else VECTORS
    document = json.loads(path.read_text(encoding="utf-8"))
    snapshot, rejected = validate_conformance(document)
    print(f"OK memory-gate retrieval bridge ({len(snapshot['accepted_records'])} accepted records)")
    print(f"OK bridge receipt {snapshot['bridge_receipt']['bridge_digest']}")
    print(f"OK bridge boundary rejection cases ({rejected})")
    print("NOTE The bridge writes only a rebuildable retrieval snapshot; append-only memory remains authoritative.")


if __name__ == "__main__":
    main()

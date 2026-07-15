from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from copy import deepcopy
from pathlib import Path

MAX_INT = 9007199254740991
TS_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EV_RE = re.compile(r"^evsha256:[0-9a-f]{64}$")
SVA_RE = re.compile(r"^svasha256:[0-9a-f]{64}$")
SVP_RE = re.compile(r"^svpsha256:[0-9a-f]{64}$")
SLOT_RE = re.compile(r"^slotsha256:[0-9a-f]{64}$")
KINDS = {"fact", "preference", "event", "profile", "relationship", "goal", "other"}
OPERATIONS = {"sets", "updates", "extends", "retracts"}
POLARITIES = {"positive", "negative", "neutral"}
PRIVACY = {"private_local", "guardian_shared", "export_approved"}
FORBIDDEN_FIELDS = {
    "guardian_id", "authority_epoch", "active_writer", "private_key", "token",
    "credential", "absolute_path", "raw_bytes", "base64_payload", "write_memory",
}

EVENT_FIELDS = {
    "schema_version", "hash_profile", "event_id", "instance_id", "body_id", "sequence",
    "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
    "observed_at", "provenance_digest", "privacy", "event_hash",
}
EVENT_HASH_FIELDS = [
    "schema_version", "event_id", "instance_id", "body_id", "sequence",
    "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
    "observed_at", "provenance_digest", "privacy",
]
ASSERTION_FIELDS = {
    "schema_version", "hash_profile", "assertion_id", "instance_id", "source_event_ref",
    "source_event_hash", "source_content_digest", "source_sequence", "source_ordinal", "kind",
    "entity", "slot", "version_key", "operation", "previous_assertion_ref", "value",
    "polarity", "valid_from", "valid_to", "extractor_profile", "extractor_digest",
    "confidence_milli", "asserted_at", "privacy", "scope", "assertion_digest",
}
ASSERTION_DIGEST_FIELDS = [
    "schema_version", "hash_profile", "assertion_id", "instance_id", "source_event_ref",
    "source_event_hash", "source_content_digest", "source_sequence", "source_ordinal", "kind",
    "entity", "slot", "version_key", "operation", "previous_assertion_ref", "value",
    "polarity", "valid_from", "valid_to", "extractor_profile", "extractor_digest",
    "confidence_milli", "asserted_at", "privacy", "scope",
]

class ConformanceError(ValueError):
    pass

def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ConformanceError("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"

def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    payload = encode_field(domain) + b"".join(encode_field(v) for v in fields)
    return prefix + hashlib.sha256(payload).hexdigest()

def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

def optional_text(value: object) -> str:
    return "" if value is None else str(value)

def validate_nfc(value: object) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("text_not_nfc")
    elif isinstance(value, list):
        for child in value:
            validate_nfc(child)
    elif isinstance(value, dict):
        for key, child in value.items():
            validate_nfc(key)
            validate_nfc(child)

def ensure_no_forbidden(value: object) -> None:
    if isinstance(value, dict):
        forbidden = set(value) & FORBIDDEN_FIELDS
        if forbidden:
            raise ConformanceError("forbidden_authority_or_platform_field")
        for child in value.values():
            ensure_no_forbidden(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_forbidden(child)

def compute_event_hash(event: dict) -> str:
    return hash_fields(
        "genesis.memory.event.v0.1",
        [str(event[f]) if f == "sequence" else event[f] for f in EVENT_HASH_FIELDS],
        "evsha256:",
    )

def compute_assertion_digest(assertion: dict) -> str:
    fields = []
    for field in ASSERTION_DIGEST_FIELDS:
        value = assertion[field]
        if field in {"source_sequence", "source_ordinal", "confidence_milli"}:
            value = str(value)
        fields.append(optional_text(value))
    return hash_fields("genesis.memory.structured.assertion.v0.1", fields, "svasha256:")

def compute_slot_id(instance_id: str, entity: str, slot: str) -> str:
    return hash_fields("genesis.memory.structured.slot.id.v0.1", [instance_id, entity, slot], "slotsha256:")

def compute_history_digest(item: dict) -> str:
    return hash_fields("genesis.memory.structured.history.v0.1", [
        item["assertion_id"], item["assertion_digest"], item["source_event_ref"],
        item["source_event_hash"], str(item["source_sequence"]), str(item["source_ordinal"]),
        item["operation"], item["value"], item["value_digest"], item["polarity"],
        optional_text(item["valid_from"]), optional_text(item["valid_to"]), item["status_after"],
    ], "svhsha256:")

def compute_slot_digest(slot: dict) -> str:
    fields = [
        slot["slot_id"], slot["version_key"], slot["kind"], slot["entity"], slot["slot"],
        slot["privacy"], slot["scope"], slot["status"], str(len(slot["current_items"])),
    ]
    for item in slot["current_items"]:
        fields.extend([item["value"], item["value_digest"], item["assertion_ref"]])
    fields.append(str(len(slot["history"])))
    fields.extend(item["history_digest"] for item in slot["history"])
    return hash_fields("genesis.memory.structured.slot.v0.1", fields, "slotsha256:")

def compute_projection_id(instance_id: str, last_hash: str, assertion_count: int) -> str:
    return hash_fields(
        "genesis.memory.structured.projection.id.v0.1",
        [instance_id, last_hash, str(assertion_count)],
        "svpsha256:",
    )

def compute_projection_digest(projection: dict) -> str:
    fields = [
        projection["schema_version"], projection["hash_profile"], projection["projection_profile"],
        projection["projection_id"], projection["instance_id"],
        str(projection["source_first_sequence"]), str(projection["source_last_sequence"]),
        str(projection["source_event_count"]), projection["source_last_event_hash"],
        str(projection["assertion_count"]), str(projection["slot_count"]),
        str(projection["active_slot_count"]), str(projection["retracted_slot_count"]),
    ]
    fields.extend(slot["slot_digest"] for slot in projection["slots"])
    return hash_fields("genesis.memory.structured.projection.v0.1", fields, "svpsha256:")

def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")

def validate_events(events: list[dict], instance_id: str) -> dict[str, dict]:
    if not isinstance(events, list) or not events:
        raise ConformanceError("source_events_required")
    by_id: dict[str, dict] = {}
    previous = "GENESIS"
    for expected_sequence, event in enumerate(events):
        validate_nfc(event)
        ensure_no_forbidden(event)
        if set(event) != EVENT_FIELDS:
            raise ConformanceError("source_event_fields_invalid")
        if event["schema_version"] != "genesis.memory.event.v0.1" or event["hash_profile"] != "genesis.hash.fields.v0.1":
            raise ConformanceError("source_event_profile_invalid")
        if event["instance_id"] != instance_id:
            raise ConformanceError("source_event_instance_mismatch")
        if type(event["sequence"]) is not int or event["sequence"] != expected_sequence:
            raise ConformanceError("source_event_sequence_invalid")
        if event["previous_event_hash"] != previous:
            raise ConformanceError("source_event_chain_invalid")
        if event["privacy"] not in PRIVACY:
            raise ConformanceError("source_event_privacy_invalid")
        if not TS_RE.fullmatch(event["observed_at"]):
            raise ConformanceError("source_event_timestamp_invalid")
        if not SHA_RE.fullmatch(event["content_digest"]) or not SHA_RE.fullmatch(event["provenance_digest"]):
            raise ConformanceError("source_event_digest_invalid")
        if compute_event_hash(event) != event["event_hash"]:
            raise ConformanceError("source_event_hash_mismatch")
        if event["event_id"] in by_id:
            raise ConformanceError("source_event_id_duplicate")
        by_id[event["event_id"]] = event
        previous = event["event_hash"]
    return by_id

def validate_assertion(assertion: dict, events: dict[str, dict], instance_id: str) -> None:
    validate_nfc(assertion)
    ensure_no_forbidden(assertion)
    if set(assertion) != ASSERTION_FIELDS:
        raise ConformanceError("assertion_fields_invalid")
    if assertion["schema_version"] != "genesis.memory.structured.assertion.v0.1" or assertion["hash_profile"] != "genesis.hash.fields.v0.1":
        raise ConformanceError("assertion_profile_invalid")
    if assertion["instance_id"] != instance_id:
        raise ConformanceError("assertion_instance_mismatch")
    event = events.get(assertion["source_event_ref"])
    if event is None:
        raise ConformanceError("assertion_source_event_missing")
    if assertion["source_event_hash"] != event["event_hash"]:
        raise ConformanceError("assertion_source_hash_mismatch")
    if assertion["source_content_digest"] != event["content_digest"]:
        raise ConformanceError("assertion_source_content_digest_mismatch")
    if assertion["source_sequence"] != event["sequence"]:
        raise ConformanceError("assertion_source_sequence_mismatch")
    if assertion["asserted_at"] != event["observed_at"]:
        raise ConformanceError("assertion_timestamp_mismatch")
    if assertion["privacy"] != event["privacy"]:
        raise ConformanceError("assertion_privacy_mismatch")
    if assertion["kind"] not in KINDS:
        raise ConformanceError("assertion_kind_invalid")
    if assertion["operation"] not in OPERATIONS:
        raise ConformanceError("assertion_operation_invalid")
    if assertion["polarity"] not in POLARITIES:
        raise ConformanceError("assertion_polarity_invalid")
    if assertion["privacy"] not in PRIVACY:
        raise ConformanceError("assertion_privacy_invalid")
    if not assertion["entity"] or not assertion["slot"] or not assertion["scope"] or not assertion["value"]:
        raise ConformanceError("assertion_text_required")
    expected_version_key = assertion["entity"] + ":" + assertion["slot"]
    if assertion["version_key"] != expected_version_key:
        raise ConformanceError("assertion_version_key_mismatch")
    if type(assertion["source_ordinal"]) is not int or not 0 <= assertion["source_ordinal"] <= MAX_INT:
        raise ConformanceError("assertion_source_ordinal_invalid")
    if type(assertion["confidence_milli"]) is not int or not 0 <= assertion["confidence_milli"] <= 1000:
        raise ConformanceError("assertion_confidence_invalid")
    if not SHA_RE.fullmatch(assertion["extractor_digest"]):
        raise ConformanceError("assertion_extractor_digest_invalid")
    if not TS_RE.fullmatch(assertion["asserted_at"]):
        raise ConformanceError("assertion_timestamp_invalid")
    for field in ("valid_from", "valid_to"):
        value = assertion[field]
        if value is not None and not TS_RE.fullmatch(value):
            raise ConformanceError("assertion_validity_timestamp_invalid")
    if assertion["valid_from"] and assertion["valid_to"] and assertion["valid_from"] > assertion["valid_to"]:
        raise ConformanceError("assertion_validity_interval_invalid")
    if compute_assertion_digest(assertion) != assertion["assertion_digest"]:
        raise ConformanceError("assertion_digest_mismatch")

def apply_assertion(state: dict | None, assertion: dict) -> dict:
    operation = assertion["operation"]
    if state is None:
        if operation != "sets" or assertion["previous_assertion_ref"] is not None:
            raise ConformanceError("slot_first_operation_must_set")
        state = {
            "kind": assertion["kind"], "entity": assertion["entity"], "slot": assertion["slot"],
            "privacy": assertion["privacy"], "scope": assertion["scope"], "status": "retracted",
            "items": {}, "last_assertion_ref": None, "history": [],
        }
    else:
        for field in ("kind", "entity", "slot", "privacy", "scope"):
            if state[field] != assertion[field]:
                raise ConformanceError(f"slot_{field}_drift")
        if assertion["previous_assertion_ref"] != state["last_assertion_ref"]:
            raise ConformanceError("slot_previous_assertion_mismatch")
        if operation == "sets" and state["status"] != "retracted":
            raise ConformanceError("slot_set_while_active")
        if operation != "sets" and state["status"] != "active":
            raise ConformanceError("slot_operation_requires_active")
    value = assertion["value"]
    if operation == "sets":
        state["items"] = {value: assertion["assertion_id"]}
    elif operation == "updates":
        state["items"] = {value: assertion["assertion_id"]}
    elif operation == "extends":
        if value in state["items"]:
            raise ConformanceError("slot_extend_duplicate_value")
        state["items"][value] = assertion["assertion_id"]
    elif operation == "retracts":
        if value not in state["items"]:
            raise ConformanceError("slot_retract_value_missing")
        del state["items"][value]
    state["status"] = "active" if state["items"] else "retracted"
    history_item = {
        "assertion_id": assertion["assertion_id"],
        "assertion_digest": assertion["assertion_digest"],
        "source_event_ref": assertion["source_event_ref"],
        "source_event_hash": assertion["source_event_hash"],
        "source_sequence": assertion["source_sequence"],
        "source_ordinal": assertion["source_ordinal"],
        "operation": operation,
        "value": value,
        "value_digest": sha256_text(value),
        "polarity": assertion["polarity"],
        "valid_from": assertion["valid_from"],
        "valid_to": assertion["valid_to"],
        "status_after": state["status"],
    }
    history_item["history_digest"] = compute_history_digest(history_item)
    state["history"].append(history_item)
    state["last_assertion_ref"] = assertion["assertion_id"]
    return state

def build_projection(document: dict, *, as_of_sequence: int | None = None, allowed_event_refs: set[str] | None = None, target_version_key: str | None = None) -> dict:
    validate_nfc(document)
    ensure_no_forbidden(document)
    if document.get("profile") != "genesis.memory.structured_versioned.v0.1":
        raise ConformanceError("document_profile_invalid")
    instance_id = document.get("instance_id")
    if not isinstance(instance_id, str) or not instance_id:
        raise ConformanceError("document_instance_invalid")
    events = validate_events(document.get("source_events"), instance_id)
    assertions = document.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise ConformanceError("assertions_required")
    seen_ids: set[str] = set()
    seen_positions: set[tuple[int, int]] = set()
    expected_order = sorted(assertions, key=lambda a: (a.get("source_sequence", -1), a.get("source_ordinal", -1), utf8_key(a.get("assertion_id", ""))))
    if assertions != expected_order:
        raise ConformanceError("assertion_order_invalid")
    states: dict[str, dict] = {}
    included_assertions = []
    for assertion in assertions:
        validate_assertion(assertion, events, instance_id)
        if assertion["assertion_id"] in seen_ids:
            raise ConformanceError("assertion_id_duplicate")
        seen_ids.add(assertion["assertion_id"])
        position = (assertion["source_sequence"], assertion["source_ordinal"])
        if position in seen_positions:
            raise ConformanceError("assertion_source_position_duplicate")
        seen_positions.add(position)
        if as_of_sequence is not None and assertion["source_sequence"] > as_of_sequence:
            continue
        if target_version_key is not None and assertion["version_key"] != target_version_key:
            continue
        if allowed_event_refs is not None and assertion["source_event_ref"] not in allowed_event_refs:
            continue
        state = states.get(assertion["version_key"])
        states[assertion["version_key"]] = apply_assertion(state, assertion)
        included_assertions.append(assertion)
    slots = []
    for version_key in sorted(states, key=utf8_key):
        state = states[version_key]
        current_items = []
        for current_value in sorted(state["items"], key=utf8_key):
            current_items.append({
                "value": current_value,
                "value_digest": sha256_text(current_value),
                "assertion_ref": state["items"][current_value],
            })
        slot = {
            "slot_id": compute_slot_id(instance_id, state["entity"], state["slot"]),
            "version_key": version_key,
            "kind": state["kind"],
            "entity": state["entity"],
            "slot": state["slot"],
            "privacy": state["privacy"],
            "scope": state["scope"],
            "status": state["status"],
            "current_items": current_items,
            "history": state["history"],
        }
        slot["slot_digest"] = compute_slot_digest(slot)
        slots.append(slot)
    event_list = list(events.values())
    last_event = event_list[-1]
    if as_of_sequence is None:
        cutoff = last_event["sequence"]
    else:
        cutoff = min(as_of_sequence, last_event["sequence"])
    cutoff_events = [event for event in event_list if event["sequence"] <= cutoff]
    cutoff_last_event = cutoff_events[-1]
    projection = {
        "schema_version": "genesis.memory.structured_versioned.projection.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "projection_profile": "genesis.memory.structured_versioned.algorithm.v0.1",
        "projection_id": compute_projection_id(instance_id, last_event["event_hash"], len(included_assertions)),
        "instance_id": instance_id,
        "source_first_sequence": 0,
        "source_last_sequence": cutoff,
        "source_event_count": len(cutoff_events),
        "source_last_event_hash": cutoff_last_event["event_hash"],
        "assertion_count": len(included_assertions),
        "slot_count": len(slots),
        "active_slot_count": sum(1 for slot in slots if slot["status"] == "active"),
        "retracted_slot_count": sum(1 for slot in slots if slot["status"] == "retracted"),
        "slots": slots,
    }
    projection["projection_digest"] = compute_projection_digest(projection)
    return projection

def execute_query(document: dict, query: dict) -> dict:
    expected_fields = {"query_id", "version_key", "as_of_sequence", "allowed_event_refs", "acl_decision_digest"}
    if set(query) != expected_fields:
        raise ConformanceError("query_fields_invalid")
    if type(query["as_of_sequence"]) is not int or query["as_of_sequence"] < 0:
        raise ConformanceError("query_as_of_invalid")
    if not SHA_RE.fullmatch(query["acl_decision_digest"]):
        raise ConformanceError("query_acl_digest_invalid")
    event_ids = {event["event_id"] for event in document["source_events"]}
    allowed = query["allowed_event_refs"]
    if not isinstance(allowed, list) or len(set(allowed)) != len(allowed):
        raise ConformanceError("query_allowed_event_refs_invalid")
    if any(ref not in event_ids for ref in allowed):
        raise ConformanceError("query_allowed_event_refs_invalid")
    relevant = [
        assertion for assertion in document["assertions"]
        if assertion["version_key"] == query["version_key"]
        and assertion["source_sequence"] <= query["as_of_sequence"]
    ]
    if not relevant:
        status, slot_status, values, refs, history_count = "not_found", None, [], [], 0
    elif any(assertion["source_event_ref"] not in set(allowed) for assertion in relevant):
        status, slot_status, values, refs, history_count = "redacted_chain", None, [], [], 0
    else:
        projection = build_projection(
            document,
            as_of_sequence=query["as_of_sequence"],
            allowed_event_refs=set(allowed),
            target_version_key=query["version_key"],
        )
        if not projection["slots"]:
            status, slot_status, values, refs, history_count = "not_found", None, [], [], 0
        else:
            slot = projection["slots"][0]
            status, slot_status = "allowed", slot["status"]
            values = [item["value"] for item in slot["current_items"]]
            refs = [item["assertion_ref"] for item in slot["current_items"]]
            history_count = len(slot["history"])
    result = {
        "query_id": query["query_id"],
        "version_key": query["version_key"],
        "as_of_sequence": query["as_of_sequence"],
        "access_status": status,
        "slot_status": slot_status,
        "current_values": values,
        "current_assertion_refs": refs,
        "history_count": history_count,
        "acl_decision_digest": query["acl_decision_digest"],
    }
    result["result_digest"] = hash_fields(
        "genesis.memory.structured.query.result.v0.1",
        [
            result["query_id"], result["version_key"], str(result["as_of_sequence"]),
            result["access_status"], optional_text(result["slot_status"]),
            str(len(values)), *values, str(len(refs)), *refs,
            str(history_count), result["acl_decision_digest"],
        ],
        "svqsha256:",
    )
    return result

def set_path(target: object, path: list[object], value: object) -> None:
    cursor = target
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value

def delete_path(target: object, path: list[object]) -> None:
    cursor = target
    for part in path[:-1]:
        cursor = cursor[part]
    if isinstance(cursor, list):
        del cursor[path[-1]]
    else:
        del cursor[path[-1]]

def apply_mutation(base: dict, mutation: dict) -> dict:
    value = deepcopy(base)
    action = mutation["action"]
    path = mutation.get("path", [])
    if action == "set":
        set_path(value, path, mutation["value"])
    elif action == "delete":
        delete_path(value, path)
    elif action == "append":
        cursor = value
        for part in path:
            cursor = cursor[part]
        cursor.append(deepcopy(mutation["value"]))
    elif action == "swap":
        cursor = value
        for part in path:
            cursor = cursor[part]
        first, second = mutation["indices"]
        cursor[first], cursor[second] = cursor[second], cursor[first]
    else:
        raise ValueError(f"unknown mutation action: {action}")
    return value

def atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)

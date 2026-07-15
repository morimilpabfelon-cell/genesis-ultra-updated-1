#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, pathlib, re, unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "portable_memory_capsule_vectors.json"
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DIGEST_RE = re.compile(r"^(?:sha256|evsha256|aclsha256|capsha256|cpsha256|msha256|rcptsha256|tmsha256):[0-9a-f]{64}$")
PRIVACY = {"private_local", "guardian_shared", "export_approved", "quarantined"}
RECIPIENT_TYPES = {"body", "guardian_archive", "offline_backup"}
KNOWN_PARTS = {"canonical_events", "continuity_anchors", "acl_receipt", "retrieval_projection", "temporal_projection"}
MANDATORY_PARTS = {"canonical_events", "continuity_anchors", "acl_receipt"}
AUTHORITY_FIELDS = {
    "active_writer", "write_memory", "authority_grant", "guardian_key",
    "seed_root_hash", "private_key", "secret", "password", "token",
}

class CapsuleError(Exception):
    pass

def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")

def ensure_text(value, label: str, allow_empty: bool = False):
    if not isinstance(value, str) or (not allow_empty and value == ""):
        raise CapsuleError(f"{label}_invalid")
    if unicodedata.normalize("NFC", value) != value:
        raise CapsuleError("capsule_text_not_nfc")
    return value

def stable_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha256_text(value: str, prefix: str = "sha256:") -> str:
    return prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()

def frame(value: str) -> bytes:
    ensure_text(value, "capsule_hash_field", allow_empty=True)
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"

def hash_fields(domain: str, fields, prefix: str = "sha256:") -> str:
    data = frame(domain) + b"".join(frame(str(field)) for field in fields)
    return prefix + hashlib.sha256(data).hexdigest()

def exact_fields(obj, expected, label):
    if not isinstance(obj, dict):
        raise CapsuleError(f"{label}_invalid")
    found = set(obj)
    if found & AUTHORITY_FIELDS:
        raise CapsuleError("capsule_contains_authority")
    if found != set(expected):
        raise CapsuleError(f"{label}_fields_invalid")

def recursive_no_authority(value):
    if isinstance(value, dict):
        if set(value) & AUTHORITY_FIELDS:
            raise CapsuleError("capsule_contains_authority")
        for item in value.values():
            recursive_no_authority(item)
    elif isinstance(value, list):
        for item in value:
            recursive_no_authority(item)
    elif isinstance(value, str):
        ensure_text(value, "capsule_text", allow_empty=True)

def unique_strings(values, label, allow_empty_list=True):
    if not isinstance(values, list) or (not allow_empty_list and not values):
        raise CapsuleError(f"{label}_invalid")
    for value in values:
        ensure_text(value, label)
    if len(set(values)) != len(values):
        raise CapsuleError(f"{label}_duplicate")

def event_hash(instance_id, event):
    return hash_fields(
        "genesis.memory.portable_capsule.source_event.v0.1",
        [instance_id, event["event_id"], event["sequence"], event["previous_event_hash"],
         event["body_id"], event["observed_at"], event["content_type"],
         event["content_digest"], event["privacy"]],
        "evsha256:",
    )

def acl_digest(instance_id, decision):
    refs = sorted(decision["allowed_event_refs"], key=utf8_key)
    return hash_fields(
        "genesis.memory.portable_capsule.acl_decision.v0.1",
        [instance_id, decision["request_id"], decision["purpose"], decision["as_of_sequence"], len(refs), *refs],
        "aclsha256:",
    )

def retrieval_source_digest(source):
    records = sorted(source["records"], key=lambda item: utf8_key(item["event_id"]))
    fields = [source["projection_id"], len(records)]
    for record in records:
        fields.extend([record["event_id"], record["frame_id"], len(record["terms"]), *record["terms"]])
    return hash_fields("genesis.memory.portable_capsule.retrieval_source.v0.1", fields)

def temporal_source_digest(source):
    annotations = sorted(source["annotations"], key=lambda item: utf8_key(item["event_id"]))
    fields = [source["projection_id"], len(annotations)]
    for item in annotations:
        fields.extend([item["event_id"], item["annotation_digest"], item["mentioned_start"] or "", item["mentioned_end"] or ""])
    return hash_fields("genesis.memory.portable_capsule.temporal_source.v0.1", fields)

def entry_digest(entry):
    fields = [entry["entry_kind"], entry["sequence"], entry["canonical_event_hash"], entry["previous_event_hash"]]
    if entry["entry_kind"] == "included_event":
        fields.extend([entry["event_id"], entry["body_id"], entry["observed_at"], entry["privacy"],
                       entry["content_type"], entry["content_digest"], entry["content"]])
    else:
        fields.append(entry["redaction_reason"])
    return hash_fields("genesis.memory.portable_capsule.entry.v0.1", fields, "cpsha256:")

def component(path, role, refs, payload):
    payload_text = stable_json(payload)
    return {
        "path": path, "role": role, "media_type": "application/json",
        "source_event_refs": sorted(refs, key=utf8_key),
        "payload_digest": sha256_text(payload_text), "payload": payload,
    }

#!/usr/bin/env python3
from __future__ import annotations
import copy
from portable_capsule_common import CapsuleError, stable_json, hash_fields, utf8_key, entry_digest, component
from portable_capsule_document import validate_document

def build_capsule(document, request_id):
    state = validate_document(document)
    if request_id not in state["request_by_id"]:
        raise CapsuleError("capsule_request_not_found")
    request = state["request_by_id"][request_id]
    decision = state["decision_by_id"][request["acl_request_id"]]
    requested = set(request["requested_event_refs"])
    source_events = [event for event in state["events"] if event["sequence"] <= decision["as_of_sequence"]]
    entries, included, anchors = [], [], []
    for event in source_events:
        anchors.append({"sequence": event["sequence"], "canonical_event_hash": event["event_hash"], "previous_event_hash": event["previous_event_hash"], "included": event["event_id"] in requested})
        if event["event_id"] in requested:
            entry = {"entry_kind": "included_event", "sequence": event["sequence"], "canonical_event_hash": event["event_hash"], "previous_event_hash": event["previous_event_hash"], "event_id": event["event_id"], "body_id": event["body_id"], "observed_at": event["observed_at"], "privacy": event["privacy"], "content_type": event["content_type"], "content_digest": event["content_digest"], "content": event["content"], "entry_digest": ""}
            entry["entry_digest"] = entry_digest(entry)
            included.append(entry)
        else:
            entry = {"entry_kind": "redacted_anchor", "sequence": event["sequence"], "canonical_event_hash": event["event_hash"], "previous_event_hash": event["previous_event_hash"], "redaction_reason": "not_exported", "entry_digest": ""}
            entry["entry_digest"] = entry_digest(entry)
        entries.append(entry)
    components = [
        component("events/accepted.json", "canonical_subset", request["requested_event_refs"], {"events": included}),
        component("chain/continuity.json", "continuity_evidence", request["requested_event_refs"], {"source_first_sequence": 0, "source_last_sequence": decision["as_of_sequence"], "source_chain_tip_hash": source_events[-1]["event_hash"], "anchors": anchors}),
        component("receipts/access.json", "access_receipt", request["requested_event_refs"], {"acl_request_id": decision["request_id"], "purpose": decision["purpose"], "as_of_sequence": decision["as_of_sequence"], "allowed_event_refs_digest": hash_fields("genesis.memory.portable_capsule.allowed_refs.v0.1", [len(decision["allowed_event_refs"]), *sorted(decision["allowed_event_refs"], key=utf8_key)]), "decision_digest": decision["decision_digest"]}),
    ]
    include = set(request["include_parts"])
    retrieval = document["derived_sources"]["retrieval"]
    if "retrieval_projection" in include:
        records = [copy.deepcopy(item) for item in retrieval["records"] if item["event_id"] in requested]
        components.append(component("projections/retrieval.json", "rebuildable_projection", [item["event_id"] for item in records], {"source_projection_id": retrieval["projection_id"], "source_projection_digest": retrieval["projection_digest"], "records": records}))
    temporal = document["derived_sources"]["temporal"]
    if "temporal_projection" in include:
        annotations = [copy.deepcopy(item) for item in temporal["annotations"] if item["event_id"] in requested]
        components.append(component("projections/temporal.json", "rebuildable_projection", [item["event_id"] for item in annotations], {"source_projection_id": temporal["projection_id"], "source_projection_digest": temporal["projection_digest"], "annotations": annotations}))
    components.sort(key=lambda item: utf8_key(item["path"]))
    files = []
    for item in components:
        payload_bytes = stable_json(item["payload"]).encode("utf-8")
        files.append({"path": item["path"], "role": item["role"], "media_type": item["media_type"], "size_bytes": len(payload_bytes), "digest": item["payload_digest"]})
    manifest_fields = [len(files)]
    for item in files:
        manifest_fields.extend([item["path"], item["role"], item["media_type"], item["size_bytes"], item["digest"]])
    manifest_root = hash_fields("genesis.memory.portable_capsule.manifest.v0.1", manifest_fields, "msha256:")
    manifest = {"format": "genesis-portable-json-capsule", "format_version": 1, "file_count": len(files), "files": files, "root_digest": manifest_root}
    source_tip = source_events[-1]["event_hash"]
    capsule_id = hash_fields("genesis.memory.portable_capsule.id.v0.1", [document["instance_id"], request["request_id"], request["recipient_type"], request["recipient_id"], request["created_at"], decision["as_of_sequence"], source_tip, manifest_root], "capsha256:")
    receipt = {"capsule_id": capsule_id, "export_request_id": request["request_id"], "recipient_type": request["recipient_type"], "recipient_id": request["recipient_id"], "source_chain_tip_hash": source_tip, "manifest_root_digest": manifest_root, "acl_decision_digest": decision["decision_digest"], "receipt_digest": ""}
    receipt["receipt_digest"] = hash_fields("genesis.memory.portable_capsule.export_receipt.v0.1", [receipt["capsule_id"], receipt["export_request_id"], receipt["recipient_type"], receipt["recipient_id"], receipt["source_chain_tip_hash"], receipt["manifest_root_digest"], receipt["acl_decision_digest"]], "rcptsha256:")
    capsule = {"schema_version": "genesis.memory.portable_capsule.v0.1", "capsule_profile": "genesis.memory.portable_capsule.algorithm.v0.1", "capsule_id": capsule_id, "instance_id": document["instance_id"], "export_request_id": request["request_id"], "recipient_type": request["recipient_type"], "recipient_id": request["recipient_id"], "created_at": request["created_at"], "source_as_of_sequence": decision["as_of_sequence"], "source_chain_tip_hash": source_tip, "included_event_count": len(included), "redacted_anchor_count": len(entries) - len(included), "entries": entries, "components": components, "manifest": manifest, "export_receipt": receipt, "capsule_digest": ""}
    capsule["capsule_digest"] = hash_fields("genesis.memory.portable_capsule.digest.v0.1", [capsule_id, document["instance_id"], request["request_id"], decision["as_of_sequence"], source_tip, len(included), len(entries) - len(included), manifest_root, receipt["receipt_digest"]], "cpsha256:")
    from portable_capsule_verify import verify_capsule
    verify_capsule(capsule)
    return capsule

#!/usr/bin/env python3
from __future__ import annotations
from portable_capsule_common import (
    CapsuleError, TIMESTAMP_RE, DIGEST_RE, PRIVACY, RECIPIENT_TYPES, KNOWN_PARTS,
    MANDATORY_PARTS, ensure_text, exact_fields, recursive_no_authority, unique_strings,
    sha256_text, event_hash, acl_digest, retrieval_source_digest, temporal_source_digest,
)

def validate_document(document):
    exact_fields(document, {"profile", "hash_profile", "instance_id", "source_events", "acl_decisions", "derived_sources", "export_requests", "must_reject", "must_reject_capsule"}, "capsule_document")
    if document["profile"] != "genesis.memory.portable_capsule.conformance.v0.1":
        raise CapsuleError("capsule_profile_invalid")
    if document["hash_profile"] != "genesis.hash.fields.v0.1":
        raise CapsuleError("capsule_hash_profile_invalid")
    instance_id = ensure_text(document["instance_id"], "capsule_instance_id")
    events = document["source_events"]
    if not isinstance(events, list) or not events:
        raise CapsuleError("capsule_events_invalid")
    event_ids, previous = set(), "GENESIS"
    for index, event in enumerate(events):
        exact_fields(event, {"event_id", "sequence", "previous_event_hash", "event_hash", "body_id", "observed_at", "content_type", "content", "content_digest", "privacy"}, "capsule_source_event")
        if event["sequence"] != index:
            raise CapsuleError("capsule_event_sequence_invalid")
        event_id = ensure_text(event["event_id"], "capsule_event_id")
        if event_id in event_ids:
            raise CapsuleError("capsule_event_duplicate")
        event_ids.add(event_id)
        if event["previous_event_hash"] != previous:
            raise CapsuleError("capsule_chain_link_invalid")
        ensure_text(event["body_id"], "capsule_body_id")
        if not isinstance(event["observed_at"], str) or not TIMESTAMP_RE.fullmatch(event["observed_at"]):
            raise CapsuleError("capsule_event_time_invalid")
        ensure_text(event["content_type"], "capsule_content_type")
        ensure_text(event["content"], "capsule_content", allow_empty=True)
        if event["content_digest"] != sha256_text(event["content"]):
            raise CapsuleError("capsule_content_digest_mismatch")
        if event["privacy"] not in PRIVACY:
            raise CapsuleError("capsule_privacy_invalid")
        if event["event_hash"] != event_hash(instance_id, event):
            raise CapsuleError("capsule_event_hash_mismatch")
        previous = event["event_hash"]
    event_by_id = {event["event_id"]: event for event in events}
    decisions = document["acl_decisions"]
    if not isinstance(decisions, list) or not decisions:
        raise CapsuleError("capsule_acl_invalid")
    decision_by_id = {}
    for decision in decisions:
        exact_fields(decision, {"request_id", "purpose", "as_of_sequence", "allowed_event_refs", "decision_digest"}, "capsule_acl_decision")
        request_id = ensure_text(decision["request_id"], "capsule_acl_request_id")
        if request_id in decision_by_id:
            raise CapsuleError("capsule_acl_duplicate")
        if decision["purpose"] != "transfer_export":
            raise CapsuleError("capsule_acl_purpose_invalid")
        if not isinstance(decision["as_of_sequence"], int) or isinstance(decision["as_of_sequence"], bool) or not (0 <= decision["as_of_sequence"] < len(events)):
            raise CapsuleError("capsule_acl_as_of_invalid")
        unique_strings(decision["allowed_event_refs"], "capsule_acl_refs")
        for ref in decision["allowed_event_refs"]:
            event = event_by_id.get(ref)
            if event is None:
                raise CapsuleError("capsule_acl_event_unknown")
            if event["sequence"] > decision["as_of_sequence"]:
                raise CapsuleError("capsule_acl_future_event")
            if event["privacy"] == "quarantined":
                raise CapsuleError("capsule_acl_quarantined")
        if decision["decision_digest"] != acl_digest(instance_id, decision):
            raise CapsuleError("capsule_acl_digest_mismatch")
        decision_by_id[request_id] = decision
    derived = document["derived_sources"]
    exact_fields(derived, {"retrieval", "temporal"}, "capsule_derived_sources")
    retrieval = derived["retrieval"]
    exact_fields(retrieval, {"projection_id", "projection_digest", "records"}, "capsule_retrieval_source")
    ensure_text(retrieval["projection_id"], "capsule_retrieval_projection_id")
    if not isinstance(retrieval["records"], list):
        raise CapsuleError("capsule_retrieval_records_invalid")
    retrieval_refs = set()
    for record in retrieval["records"]:
        exact_fields(record, {"event_id", "frame_id", "terms"}, "capsule_retrieval_record")
        if record["event_id"] not in event_ids:
            raise CapsuleError("capsule_retrieval_event_unknown")
        if record["event_id"] in retrieval_refs:
            raise CapsuleError("capsule_retrieval_duplicate")
        retrieval_refs.add(record["event_id"])
        ensure_text(record["frame_id"], "capsule_frame_id")
        unique_strings(record["terms"], "capsule_terms")
    if retrieval["projection_digest"] != retrieval_source_digest(retrieval):
        raise CapsuleError("capsule_retrieval_digest_mismatch")
    temporal = derived["temporal"]
    exact_fields(temporal, {"projection_id", "projection_digest", "annotations"}, "capsule_temporal_source")
    ensure_text(temporal["projection_id"], "capsule_temporal_projection_id")
    if not isinstance(temporal["annotations"], list):
        raise CapsuleError("capsule_temporal_annotations_invalid")
    temporal_refs = set()
    for annotation in temporal["annotations"]:
        exact_fields(annotation, {"event_id", "annotation_digest", "mentioned_start", "mentioned_end"}, "capsule_temporal_annotation")
        if annotation["event_id"] not in event_ids:
            raise CapsuleError("capsule_temporal_event_unknown")
        if annotation["event_id"] in temporal_refs:
            raise CapsuleError("capsule_temporal_duplicate")
        temporal_refs.add(annotation["event_id"])
        if not isinstance(annotation["annotation_digest"], str) or not DIGEST_RE.fullmatch(annotation["annotation_digest"]):
            raise CapsuleError("capsule_temporal_digest_invalid")
        for key in ("mentioned_start", "mentioned_end"):
            value = annotation[key]
            if value is not None and (not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value)):
                raise CapsuleError("capsule_temporal_time_invalid")
        if (annotation["mentioned_start"] is None) != (annotation["mentioned_end"] is None):
            raise CapsuleError("capsule_temporal_range_invalid")
        if annotation["mentioned_start"] and annotation["mentioned_start"] > annotation["mentioned_end"]:
            raise CapsuleError("capsule_temporal_range_invalid")
    if temporal["projection_digest"] != temporal_source_digest(temporal):
        raise CapsuleError("capsule_temporal_source_digest_mismatch")
    requests = document["export_requests"]
    if not isinstance(requests, list) or not requests:
        raise CapsuleError("capsule_requests_invalid")
    request_ids = set()
    for request in requests:
        exact_fields(request, {"request_id", "acl_request_id", "recipient_type", "recipient_id", "created_at", "requested_event_refs", "include_parts", "expected_capsule_digest", "expected_manifest_root"}, "capsule_export_request")
        request_id = ensure_text(request["request_id"], "capsule_request_id")
        if request_id in request_ids:
            raise CapsuleError("capsule_request_duplicate")
        request_ids.add(request_id)
        decision = decision_by_id.get(request["acl_request_id"])
        if decision is None:
            raise CapsuleError("capsule_request_acl_unknown")
        if request["recipient_type"] not in RECIPIENT_TYPES:
            raise CapsuleError("capsule_recipient_type_invalid")
        ensure_text(request["recipient_id"], "capsule_recipient_id")
        if not isinstance(request["created_at"], str) or not TIMESTAMP_RE.fullmatch(request["created_at"]):
            raise CapsuleError("capsule_created_at_invalid")
        unique_strings(request["requested_event_refs"], "capsule_requested_refs", allow_empty_list=False)
        for ref in request["requested_event_refs"]:
            event = event_by_id.get(ref)
            if event is None:
                raise CapsuleError("capsule_requested_event_unknown")
            if ref not in decision["allowed_event_refs"]:
                raise CapsuleError("capsule_requested_event_unauthorized")
            if event["sequence"] > decision["as_of_sequence"]:
                raise CapsuleError("capsule_requested_event_future")
            if event["privacy"] == "quarantined":
                raise CapsuleError("capsule_requested_event_quarantined")
        unique_strings(request["include_parts"], "capsule_include_parts", allow_empty_list=False)
        if not set(request["include_parts"]) <= KNOWN_PARTS:
            raise CapsuleError("capsule_include_part_unknown")
        if not MANDATORY_PARTS <= set(request["include_parts"]):
            raise CapsuleError("capsule_mandatory_part_missing")
        for field in ("expected_capsule_digest", "expected_manifest_root"):
            value = request[field]
            if value is not None and (not isinstance(value, str) or not DIGEST_RE.fullmatch(value)):
                raise CapsuleError("capsule_expected_digest_invalid")
    recursive_no_authority({key: value for key, value in document.items() if key not in {"must_reject", "must_reject_capsule"}})
    return {"events": events, "event_by_id": event_by_id, "decision_by_id": decision_by_id, "request_by_id": {request["request_id"]: request for request in requests}}

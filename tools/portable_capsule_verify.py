#!/usr/bin/env python3
from __future__ import annotations
from portable_capsule_common import (
    CapsuleError, TIMESTAMP_RE, RECIPIENT_TYPES, ensure_text, exact_fields, recursive_no_authority,
    unique_strings, sha256_text, stable_json, utf8_key, hash_fields, entry_digest,
)

def verify_capsule(capsule):
    exact_fields(capsule, {"schema_version", "capsule_profile", "capsule_id", "instance_id", "export_request_id", "recipient_type", "recipient_id", "created_at", "source_as_of_sequence", "source_chain_tip_hash", "included_event_count", "redacted_anchor_count", "entries", "components", "manifest", "export_receipt", "capsule_digest"}, "portable_capsule")
    if capsule["schema_version"] != "genesis.memory.portable_capsule.v0.1":
        raise CapsuleError("capsule_schema_version_invalid")
    if capsule["capsule_profile"] != "genesis.memory.portable_capsule.algorithm.v0.1":
        raise CapsuleError("capsule_algorithm_profile_invalid")
    if capsule["recipient_type"] not in RECIPIENT_TYPES:
        raise CapsuleError("capsule_recipient_type_invalid")
    ensure_text(capsule["recipient_id"], "capsule_recipient_id")
    if not TIMESTAMP_RE.fullmatch(capsule["created_at"]):
        raise CapsuleError("capsule_created_at_invalid")
    entries = capsule["entries"]
    if not isinstance(entries, list) or not entries:
        raise CapsuleError("capsule_entries_invalid")
    previous, included_refs, included_count, redacted_count = "GENESIS", [], 0, 0
    for index, entry in enumerate(entries):
        if entry.get("entry_kind") == "included_event":
            exact_fields(entry, {"entry_kind", "sequence", "canonical_event_hash", "previous_event_hash", "event_id", "body_id", "observed_at", "privacy", "content_type", "content_digest", "content", "entry_digest"}, "capsule_included_entry")
            if sha256_text(entry["content"]) != entry["content_digest"]:
                raise CapsuleError("capsule_entry_content_digest_mismatch")
            if entry["privacy"] == "quarantined":
                raise CapsuleError("capsule_entry_quarantined")
            included_refs.append(entry["event_id"])
            included_count += 1
        elif entry.get("entry_kind") == "redacted_anchor":
            exact_fields(entry, {"entry_kind", "sequence", "canonical_event_hash", "previous_event_hash", "redaction_reason", "entry_digest"}, "capsule_redacted_entry")
            if entry["redaction_reason"] != "not_exported":
                raise CapsuleError("capsule_redaction_reason_invalid")
            redacted_count += 1
        else:
            raise CapsuleError("capsule_entry_kind_invalid")
        if entry["sequence"] != index:
            raise CapsuleError("capsule_entry_sequence_invalid")
        if entry["previous_event_hash"] != previous:
            raise CapsuleError("capsule_entry_chain_invalid")
        if entry["entry_digest"] != entry_digest(entry):
            raise CapsuleError("capsule_entry_digest_mismatch")
        previous = entry["canonical_event_hash"]
    if previous != capsule["source_chain_tip_hash"]:
        raise CapsuleError("capsule_tip_mismatch")
    if included_count != capsule["included_event_count"] or redacted_count != capsule["redacted_anchor_count"]:
        raise CapsuleError("capsule_entry_count_mismatch")
    if len(set(included_refs)) != len(included_refs):
        raise CapsuleError("capsule_included_event_duplicate")
    components = capsule["components"]
    if not isinstance(components, list) or not components:
        raise CapsuleError("capsule_components_invalid")
    paths, recomputed_files = [], []
    for item in components:
        exact_fields(item, {"path", "role", "media_type", "source_event_refs", "payload_digest", "payload"}, "capsule_component")
        ensure_text(item["path"], "capsule_component_path")
        if item["path"].startswith("/") or ".." in item["path"].split("\\") or ".." in item["path"].split("/"):
            raise CapsuleError("capsule_component_path_invalid")
        if item["path"] in paths:
            raise CapsuleError("capsule_component_duplicate")
        paths.append(item["path"])
        if item["media_type"] != "application/json":
            raise CapsuleError("capsule_component_media_type_invalid")
        unique_strings(item["source_event_refs"], "capsule_component_refs")
        if any(ref not in included_refs for ref in item["source_event_refs"]):
            raise CapsuleError("capsule_component_ref_not_included")
        recursive_no_authority(item["payload"])
        payload_text = stable_json(item["payload"])
        digest = sha256_text(payload_text)
        if item["payload_digest"] != digest:
            raise CapsuleError("capsule_component_digest_mismatch")
        recomputed_files.append({"path": item["path"], "role": item["role"], "media_type": item["media_type"], "size_bytes": len(payload_text.encode("utf-8")), "digest": digest})
    if paths != sorted(paths, key=utf8_key):
        raise CapsuleError("capsule_component_order_invalid")
    manifest = capsule["manifest"]
    exact_fields(manifest, {"format", "format_version", "file_count", "files", "root_digest"}, "capsule_manifest")
    if manifest["format"] != "genesis-portable-json-capsule" or manifest["format_version"] != 1:
        raise CapsuleError("capsule_manifest_format_invalid")
    if manifest["file_count"] != len(recomputed_files) or manifest["files"] != recomputed_files:
        raise CapsuleError("capsule_manifest_files_mismatch")
    manifest_fields = [len(recomputed_files)]
    for item in recomputed_files:
        manifest_fields.extend([item["path"], item["role"], item["media_type"], item["size_bytes"], item["digest"]])
    manifest_root = hash_fields("genesis.memory.portable_capsule.manifest.v0.1", manifest_fields, "msha256:")
    if manifest["root_digest"] != manifest_root:
        raise CapsuleError("capsule_manifest_root_mismatch")
    receipt = capsule["export_receipt"]
    exact_fields(receipt, {"capsule_id", "export_request_id", "recipient_type", "recipient_id", "source_chain_tip_hash", "manifest_root_digest", "acl_decision_digest", "receipt_digest"}, "capsule_export_receipt")
    if receipt["capsule_id"] != capsule["capsule_id"] or receipt["export_request_id"] != capsule["export_request_id"] or receipt["recipient_type"] != capsule["recipient_type"] or receipt["recipient_id"] != capsule["recipient_id"] or receipt["source_chain_tip_hash"] != capsule["source_chain_tip_hash"] or receipt["manifest_root_digest"] != manifest_root:
        raise CapsuleError("capsule_receipt_binding_invalid")
    expected_receipt = hash_fields("genesis.memory.portable_capsule.export_receipt.v0.1", [receipt["capsule_id"], receipt["export_request_id"], receipt["recipient_type"], receipt["recipient_id"], receipt["source_chain_tip_hash"], receipt["manifest_root_digest"], receipt["acl_decision_digest"]], "rcptsha256:")
    if receipt["receipt_digest"] != expected_receipt:
        raise CapsuleError("capsule_receipt_digest_mismatch")
    expected_id = hash_fields("genesis.memory.portable_capsule.id.v0.1", [capsule["instance_id"], capsule["export_request_id"], capsule["recipient_type"], capsule["recipient_id"], capsule["created_at"], capsule["source_as_of_sequence"], capsule["source_chain_tip_hash"], manifest_root], "capsha256:")
    if capsule["capsule_id"] != expected_id:
        raise CapsuleError("capsule_id_mismatch")
    expected_capsule = hash_fields("genesis.memory.portable_capsule.digest.v0.1", [capsule["capsule_id"], capsule["instance_id"], capsule["export_request_id"], capsule["source_as_of_sequence"], capsule["source_chain_tip_hash"], capsule["included_event_count"], capsule["redacted_anchor_count"], manifest_root, receipt["receipt_digest"]], "cpsha256:")
    if capsule["capsule_digest"] != expected_capsule:
        raise CapsuleError("capsule_digest_mismatch")
    recursive_no_authority(capsule)
    return capsule

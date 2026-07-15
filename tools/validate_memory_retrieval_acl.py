#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "conformance" / "memory_retrieval_acl_vectors.json"
REQUESTER_TYPES = {"instance", "guardian", "body", "engine", "observer"}
PURPOSES = {"recall", "reasoning_context", "guardian_review", "transfer_export", "observability"}
PRIVACY = {"private_local", "guardian_shared", "export_approved", "quarantined"}
AUTHORITY_FIELDS = {"active_writer", "write_memory", "authority_grant", "guardian_key", "seed_root_hash"}
POLICY_FIELDS = {"policy_id", "requester_type", "requester_id", "body_id", "purposes", "allowed_privacy", "allowed_scopes", "event_type_prefixes", "authority_epoch", "valid_from_sequence", "valid_to_sequence"}
REQUEST_FIELDS = {"request_id", "requester_type", "requester_id", "body_id", "purpose", "requested_scopes", "event_type_prefixes", "as_of_sequence", "authority_epoch", "expected_policy_id", "expected_allowed_event_refs", "expected_denials"}


class AclError(Exception):
    pass


def frame(value: str) -> bytes:
    if not isinstance(value, str):
        raise AclError("acl_text_invalid")
    data = value.encode("utf-8")
    return f"{len(data)}:".encode("ascii") + data + b"\n"


def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    digest = hashlib.sha256(frame(domain) + b"".join(frame(value) for value in fields)).hexdigest()
    return prefix + digest


def exact_fields(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise AclError(f"{label}_invalid")
    if AUTHORITY_FIELDS.intersection(value):
        raise AclError("acl_policy_contains_authority")
    if set(value) != expected:
        raise AclError(f"{label}_fields_invalid")


def unique_strings(values, label: str) -> None:
    if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values) or len(set(values)) != len(values):
        raise AclError(f"{label}_invalid")


def validate_document(document: dict) -> set[str]:
    if document.get("profile") != "genesis.memory.retrieval_acl.conformance.v0.1":
        raise AclError("acl_profile_invalid")
    epoch = document.get("authority_epoch")
    if not isinstance(epoch, int) or epoch < 0:
        raise AclError("acl_authority_epoch_invalid")
    events = document.get("events")
    if not isinstance(events, list) or not events:
        raise AclError("acl_events_invalid")
    event_ids: set[str] = set()
    for index, event in enumerate(events):
        exact_fields(event, {"event_id", "body_id", "sequence", "event_type", "privacy"}, "acl_event")
        if event["sequence"] != index:
            raise AclError("acl_event_sequence_invalid")
        if event["event_id"] in event_ids:
            raise AclError("acl_event_duplicate")
        if event["privacy"] not in PRIVACY:
            raise AclError("acl_event_privacy_invalid")
        event_ids.add(event["event_id"])
    bindings = document.get("scope_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(events):
        raise AclError("acl_scope_binding_coverage_invalid")
    binding_ids: set[str] = set()
    known_scopes: set[str] = set()
    for binding in bindings:
        exact_fields(binding, {"event_id", "scopes"}, "acl_scope_binding")
        if binding["event_id"] not in event_ids:
            raise AclError("acl_scope_binding_event_unknown")
        if binding["event_id"] in binding_ids:
            raise AclError("acl_scope_binding_duplicate")
        unique_strings(binding["scopes"], "acl_scopes")
        binding_ids.add(binding["event_id"])
        known_scopes.update(binding["scopes"])
    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        raise AclError("acl_policies_invalid")
    policy_ids: set[str] = set()
    for policy in policies:
        exact_fields(policy, POLICY_FIELDS, "acl_policy")
        if policy["policy_id"] in policy_ids:
            raise AclError("acl_policy_id_duplicate")
        if policy["requester_type"] not in REQUESTER_TYPES:
            raise AclError("acl_requester_type_invalid")
        unique_strings(policy["purposes"], "acl_policy_purposes")
        if any(value not in PURPOSES for value in policy["purposes"]):
            raise AclError("acl_policy_purpose_invalid")
        unique_strings(policy["allowed_privacy"], "acl_policy_privacy")
        if any(value not in PRIVACY or value == "quarantined" for value in policy["allowed_privacy"]):
            raise AclError("acl_policy_privacy_invalid")
        unique_strings(policy["allowed_scopes"], "acl_policy_scopes")
        if any(scope not in known_scopes for scope in policy["allowed_scopes"]):
            raise AclError("acl_policy_scope_unknown")
        unique_strings(policy["event_type_prefixes"], "acl_policy_event_prefixes")
        if policy["requester_type"] == "observer" and any(value != "export_approved" for value in policy["allowed_privacy"]):
            raise AclError("acl_observer_privacy_invalid")
        if policy["requester_type"] == "body" and policy["body_id"] != policy["requester_id"]:
            raise AclError("acl_body_policy_mismatch")
        if policy["requester_type"] != "body" and policy["body_id"] is not None:
            raise AclError("acl_policy_body_unexpected")
        if policy["authority_epoch"] != epoch:
            raise AclError("acl_policy_epoch_invalid")
        if not isinstance(policy["valid_from_sequence"], int) or (policy["valid_to_sequence"] is not None and not isinstance(policy["valid_to_sequence"], int)):
            raise AclError("acl_policy_window_invalid")
        policy_ids.add(policy["policy_id"])
    requests = document.get("requests")
    if not isinstance(requests, list) or not requests:
        raise AclError("acl_requests_invalid")
    for request in requests:
        exact_fields(request, REQUEST_FIELDS, "acl_request")
        if request["requester_type"] not in REQUESTER_TYPES or request["purpose"] not in PURPOSES:
            raise AclError("acl_request_identity_invalid")
        unique_strings(request["requested_scopes"], "acl_requested_scopes")
        if any(scope not in known_scopes for scope in request["requested_scopes"]):
            raise AclError("acl_requested_scope_unknown")
        unique_strings(request["event_type_prefixes"], "acl_request_event_prefixes")
        if request["authority_epoch"] != epoch:
            raise AclError("acl_authority_epoch_mismatch")
        if not isinstance(request["as_of_sequence"], int) or not 0 <= request["as_of_sequence"] < len(events):
            raise AclError("acl_as_of_sequence_invalid")
    return known_scopes


def choose_policy(document: dict, request: dict) -> dict:
    matches = [policy for policy in document["policies"] if policy["requester_type"] == request["requester_type"] and policy["requester_id"] == request["requester_id"] and policy["body_id"] == request["body_id"] and request["purpose"] in policy["purposes"] and policy["authority_epoch"] == request["authority_epoch"] and request["as_of_sequence"] >= policy["valid_from_sequence"] and (policy["valid_to_sequence"] is None or request["as_of_sequence"] <= policy["valid_to_sequence"])]
    if not matches:
        raise AclError("acl_policy_not_found")
    if len(matches) != 1:
        raise AclError("acl_policy_ambiguous")
    return matches[0]


def decision_digest(decision: dict) -> str:
    denial_flat: list[str] = []
    for key in sorted(decision["denial_counts"], key=lambda v: v.encode("utf-8")):
        denial_flat.extend([key, str(decision["denial_counts"][key])])
    fields = [decision["request_id"], decision["policy_id"], str(decision["authority_epoch"]), str(decision["as_of_sequence"]), str(len(decision["effective_scopes"])), *decision["effective_scopes"], str(len(decision["allowed_event_refs"])), *decision["allowed_event_refs"], str(len(denial_flat) // 2), *denial_flat]
    return hash_fields("genesis.memory.retrieval_acl.decision.v0.1", fields, "aclsha256:")


def evaluate_request(document: dict, request: dict) -> dict:
    policy = choose_policy(document, request)
    bindings = {item["event_id"]: set(item["scopes"]) for item in document["scope_bindings"]}
    effective = sorted((set(request["requested_scopes"]) & set(policy["allowed_scopes"])) if request["requested_scopes"] else set(policy["allowed_scopes"]), key=lambda v: v.encode("utf-8"))
    effective_set = set(effective)
    prefixes = request["event_type_prefixes"] or policy["event_type_prefixes"]
    allowed: list[str] = []
    denial: dict[str, int] = {}
    def deny(reason: str) -> None:
        denial[reason] = denial.get(reason, 0) + 1
    for event in document["events"]:
        if event["sequence"] > request["as_of_sequence"]:
            deny("future_event")
        elif event["privacy"] == "quarantined":
            deny("quarantined")
        elif not (bindings[event["event_id"]] & effective_set):
            deny("scope_not_allowed")
        elif event["privacy"] not in policy["allowed_privacy"]:
            deny("privacy_not_allowed")
        elif request["requester_type"] == "body" and event["privacy"] == "private_local" and event["body_id"] != request["body_id"]:
            deny("body_mismatch")
        elif prefixes and not any(event["event_type"].startswith(prefix) for prefix in prefixes):
            deny("event_type_filtered")
        else:
            allowed.append(event["event_id"])
    decision = {"schema_version":"genesis.memory.retrieval_acl.decision.v0.1","request_id":request["request_id"],"policy_id":policy["policy_id"],"instance_id":document["instance_id"],"authority_epoch":request["authority_epoch"],"purpose":request["purpose"],"as_of_sequence":request["as_of_sequence"],"effective_scopes":effective,"allowed_event_refs":allowed,"denial_counts":denial,"decision_digest":""}
    decision["decision_digest"] = decision_digest(decision)
    return decision


def build_decisions(document: dict) -> list[dict]:
    validate_document(document)
    return [evaluate_request(document, request) for request in document["requests"]]


def apply_mutation(document: dict, mutation: dict) -> None:
    target = mutation["target"]
    if target in {"request", "policy", "policy_add", "binding"}:
        collection = {"request":"requests", "policy":"policies", "policy_add":"policies", "binding":"scope_bindings"}[target]
        document[collection][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "duplicate_binding":
        document["scope_bindings"].append(copy.deepcopy(document["scope_bindings"][mutation["index"]]))
    elif target == "duplicate_policy":
        item = copy.deepcopy(document["policies"][mutation["index"]]); item["policy_id"] = mutation["new_policy_id"]; document["policies"].append(item)
    else:
        raise RuntimeError(f"unknown_mutation:{target}")


def main() -> None:
    document = json.loads(VECTOR.read_text(encoding="utf-8"))
    decisions = build_decisions(document)
    for request, decision in zip(document["requests"], decisions, strict=True):
        if decision["policy_id"] != request["expected_policy_id"] or decision["allowed_event_refs"] != request["expected_allowed_event_refs"] or decision["denial_counts"] != request["expected_denials"]:
            raise RuntimeError(f"acl_expected_decision_mismatch:{request['request_id']}")
    rejected = 0
    for case in document.get("must_reject", []):
        mutated = copy.deepcopy(document); apply_mutation(mutated, case["mutation"])
        try:
            build_decisions(mutated)
        except AclError as error:
            if str(error) != case["expected_error"]:
                raise RuntimeError(f"{case['case_id']}:expected:{case['expected_error']}:got:{error}") from error
            rejected += 1
        else:
            raise RuntimeError(f"{case['case_id']}:mutation_accepted")
    print(f"OK retrieval ACL ({len(decisions)} requests)")
    print("OK scopes, privacy, purpose and historical isolation")
    print(f"OK ACL boundary rejection cases ({rejected})")
    print("NOTE ACL filters candidates before ranking and never grants write authority.")


if __name__ == "__main__":
    main()

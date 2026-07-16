#!/usr/bin/env python3
"""Validate the deterministic Recursive Improvement Laboratory v0.1 fixture."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("FAIL PyNaCl requerido para validar el laboratorio de mejora", file=sys.stderr)
    raise SystemExit(1)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "recursive_improvement_vectors.json"
ZERO_HASH = "sha256:" + "0" * 64
SAFE_INT = 9_007_199_254_740_991
OPERATORS = {"draft", "debug", "improve"}
STATUSES = {"accepted", "buggy", "rejected"}
REASONS = {
    None,
    "execution_error",
    "timeout",
    "budget_exceeded",
    "public_failed",
    "private_failed",
    "generalization_failed",
    "maintainability_failed",
    "metric_manipulation",
    "safety_regression",
}


class ConformanceError(ValueError):
    pass


def fail(code: str) -> None:
    raise ConformanceError(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        fail(code)


def validate_nfc(value: Any) -> None:
    if isinstance(value, str):
        require(unicodedata.normalize("NFC", value) == value, "text_not_nfc")
    elif isinstance(value, list):
        for item in value:
            validate_nfc(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_nfc(key)
            validate_nfc(item)


def canonical_json(value: Any) -> str:
    validate_nfc(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_object(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def label_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def public_key_text(key: SigningKey) -> str:
    return "ed25519pk:" + bytes(key.verify_key).hex()


def signature_message(domain: str, digest: str) -> bytes:
    return f"{domain}\n{digest}".encode("utf-8")


def sign_digest(key: SigningKey, domain: str, digest: str) -> str:
    return "ed25519sig:" + key.sign(signature_message(domain, digest)).signature.hex()


def verify_signature(public_key: str, signature: str, domain: str, digest: str, code: str) -> None:
    require(public_key.startswith("ed25519pk:") and len(public_key) == 74, code)
    require(signature.startswith("ed25519sig:") and len(signature) == 139, code)
    try:
        VerifyKey(bytes.fromhex(public_key.split(":", 1)[1])).verify(
            signature_message(domain, digest), bytes.fromhex(signature.split(":", 1)[1])
        )
    except (ValueError, BadSignatureError):
        fail(code)


def exact_fields(value: Any, fields: set[str], code: str) -> None:
    require(isinstance(value, dict) and set(value) == fields, code)


def safe_int(value: Any, code: str, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= SAFE_INT, code)
    return value


def load_vector(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    validate_nfc(doc)
    exact_fields(doc, {"purpose", "source_reference", "test_only_keys", "campaign_template", "candidate_templates", "expected"}, "vector_fields_invalid")
    require(doc["source_reference"] == {
        "repository": "WecoAI/aideml",
        "commit": "5d66a21771e98623dc9fc8716bdbe388d63464c0",
        "license": "MIT",
        "code_copied": False,
    }, "source_reference_invalid")
    exact_fields(doc["test_only_keys"], {"guardian_seed_hex", "evaluator_seed_hex"}, "test_keys_fields_invalid")
    for seed in doc["test_only_keys"].values():
        require(isinstance(seed, str) and len(seed) == 64, "test_seed_invalid")
        bytes.fromhex(seed)
    require(isinstance(doc["candidate_templates"], list) and doc["candidate_templates"], "candidate_templates_invalid")
    return doc


CAMPAIGN_TEMPLATE_FIELDS = {
    "schema_version", "hash_profile", "campaign_id", "instance_id", "guardian_grant_ref",
    "objective", "metric", "source_tree_digest", "campaign_seed", "policy_profile",
    "fixed_budget", "sandbox_profile", "private_evaluation", "opened_at",
}
CAMPAIGN_FIELDS = CAMPAIGN_TEMPLATE_FIELDS | {"guardian_public_key", "campaign_digest", "guardian_signature"}
BUDGET_FIELDS = {
    "max_candidates", "max_drafts", "max_debug_depth", "plateau_window", "max_actions",
    "max_duration_ms", "max_token_units", "max_bytes", "max_cost_microunits",
}
USED_BUDGET_FIELDS = {"actions", "duration_ms", "token_units", "bytes", "cost_microunits"}
CANDIDATE_TEMPLATE_FIELDS = {
    "candidate_id", "parent_candidate_ref", "lineage_id", "operator", "public_score_milli",
    "execution_status", "private_pass", "generalization_pass", "maintainability_pass",
    "metric_manipulation_detected", "safety_regression_detected", "status", "rejection_reason",
}
EVENT_FIELDS = {
    "schema_version", "hash_profile", "ledger_id", "event_id", "sequence", "previous_event_hash",
    "campaign_ref", "campaign_digest", "candidate_id", "parent_candidate_ref", "lineage_id", "operator",
    "proposal_digest", "patch_digest", "source_tree_digest", "result_tree_digest", "environment_digest",
    "budget_used", "execution", "evaluation", "status", "rejection_reason", "recorded_at", "evaluator_id",
    "evaluator_public_key", "event_hash", "evaluator_signature",
}
EXECUTION_FIELDS = {"status", "output_digest", "artifact_digest", "error_class"}
EVALUATION_FIELDS = {
    "public_score_milli", "public_pass", "private_receipt_digest", "private_pass",
    "generalization_pass", "maintainability_pass", "metric_manipulation_detected",
    "safety_regression_detected",
}


def validate_campaign_template(item: dict[str, Any]) -> None:
    exact_fields(item, CAMPAIGN_TEMPLATE_FIELDS, "campaign_template_fields_invalid")
    require(item["schema_version"] == "genesis.improvement.campaign.v0.1", "campaign_schema_invalid")
    require(item["hash_profile"] == "genesis.hash.fields.v0.1", "campaign_hash_profile_invalid")
    for name in ["campaign_id", "instance_id", "guardian_grant_ref"]:
        require(isinstance(item[name], str) and len(item[name]) >= 8, f"campaign_{name}_invalid")
    require(isinstance(item["objective"], str) and len(item["objective"]) >= 20, "campaign_objective_invalid")
    exact_fields(item["metric"], {"name", "direction", "unit"}, "campaign_metric_fields_invalid")
    require(item["metric"]["direction"] in {"maximize", "minimize"}, "campaign_metric_direction_invalid")
    require(all(isinstance(item["metric"][name], str) and item["metric"][name] for name in ["name", "unit"]), "campaign_metric_invalid")
    require(item["source_tree_digest"].startswith("sha256:") and len(item["source_tree_digest"]) == 71, "campaign_source_tree_invalid")
    require(item["campaign_seed"].startswith("seed256:") and len(item["campaign_seed"]) == 72, "campaign_seed_invalid")
    require(item["policy_profile"] == "genesis.improvement.search.aide-adapted.v0.1", "campaign_policy_invalid")
    exact_fields(item["fixed_budget"], BUDGET_FIELDS, "campaign_budget_fields_invalid")
    budget = item["fixed_budget"]
    safe_int(budget["max_candidates"], "max_candidates_invalid", 1)
    safe_int(budget["max_drafts"], "max_drafts_invalid", 1)
    safe_int(budget["max_debug_depth"], "max_debug_depth_invalid", 0)
    safe_int(budget["plateau_window"], "plateau_window_invalid", 1)
    for name in ["max_actions", "max_duration_ms", "max_token_units"]:
        safe_int(budget[name], f"{name}_invalid", 1)
    for name in ["max_bytes", "max_cost_microunits"]:
        safe_int(budget[name], f"{name}_invalid", 0)
    require(budget["max_drafts"] <= budget["max_candidates"], "draft_budget_exceeds_candidates")
    exact_fields(item["sandbox_profile"], {"network_mode", "filesystem_mode", "secrets_available", "process_isolation", "output_capture", "environment_reproducible"}, "sandbox_fields_invalid")
    require(item["sandbox_profile"] == {
        "network_mode": "denied",
        "filesystem_mode": "ephemeral_readonly_input",
        "secrets_available": False,
        "process_isolation": True,
        "output_capture": True,
        "environment_reproducible": True,
    }, "sandbox_profile_invalid")
    exact_fields(item["private_evaluation"], {"cases_visible_to_agent", "receipt_only", "evaluator_separate"}, "private_evaluation_fields_invalid")
    require(item["private_evaluation"] == {"cases_visible_to_agent": False, "receipt_only": True, "evaluator_separate": True}, "private_evaluation_boundary_invalid")
    require(isinstance(item["opened_at"], str) and item["opened_at"].endswith("Z"), "campaign_timestamp_invalid")


def build_campaign(doc: dict[str, Any]) -> dict[str, Any]:
    template = copy.deepcopy(doc["campaign_template"])
    validate_campaign_template(template)
    key = SigningKey(bytes.fromhex(doc["test_only_keys"]["guardian_seed_hex"]))
    campaign = template | {"guardian_public_key": public_key_text(key)}
    campaign["campaign_digest"] = digest_object(campaign)
    campaign["guardian_signature"] = sign_digest(key, "genesis.improvement.campaign.signature.v0.1", campaign["campaign_digest"])
    return campaign


def validate_campaign(campaign: dict[str, Any]) -> None:
    exact_fields(campaign, CAMPAIGN_FIELDS, "campaign_fields_invalid")
    validate_campaign_template({name: campaign[name] for name in CAMPAIGN_TEMPLATE_FIELDS})
    unsigned = {key: value for key, value in campaign.items() if key not in {"campaign_digest", "guardian_signature"}}
    require(digest_object(unsigned) == campaign["campaign_digest"], "campaign_digest_invalid")
    verify_signature(campaign["guardian_public_key"], campaign["guardian_signature"], "genesis.improvement.campaign.signature.v0.1", campaign["campaign_digest"], "campaign_signature_invalid")


def classify_candidate(template: dict[str, Any], budget: dict[str, Any], limits: dict[str, Any]) -> tuple[str, str | None]:
    if any(budget[name] > limits["max_" + name] for name in USED_BUDGET_FIELDS):
        return "rejected", "budget_exceeded"
    if template["execution_status"] == "error":
        return "buggy", "execution_error"
    if template["execution_status"] == "timeout":
        return "buggy", "timeout"
    if template["public_score_milli"] is None:
        return "rejected", "public_failed"
    if template["metric_manipulation_detected"]:
        return "rejected", "metric_manipulation"
    if template["safety_regression_detected"]:
        return "rejected", "safety_regression"
    if not template["private_pass"]:
        return "rejected", "private_failed"
    if not template["generalization_pass"]:
        return "rejected", "generalization_failed"
    if not template["maintainability_pass"]:
        return "rejected", "maintainability_failed"
    return "accepted", None


def accepted_score(event: dict[str, Any]) -> int | None:
    return event["evaluation"]["public_score_milli"] if event["status"] == "accepted" else None


def best_accepted(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    accepted = [event for event in events if event["status"] == "accepted"]
    if not accepted:
        return None
    direction = "maximize"
    if direction == "maximize":
        return sorted(accepted, key=lambda item: (-item["evaluation"]["public_score_milli"], item["sequence"], item["candidate_id"].encode("utf-8")))[0]
    return sorted(accepted, key=lambda item: (item["evaluation"]["public_score_milli"], item["sequence"], item["candidate_id"].encode("utf-8")))[0]


def child_refs(events: list[dict[str, Any]]) -> set[str]:
    return {event["parent_candidate_ref"] for event in events if event["parent_candidate_ref"] is not None}


def debug_depth(event: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> int:
    if event["operator"] != "debug":
        return 0
    parent = by_id[event["parent_candidate_ref"]]
    return 1 + debug_depth(parent, by_id)


def lineage_plateau(events: list[dict[str, Any]], lineage_id: str, window: int) -> bool:
    accepted_improvements = [event for event in events if event["lineage_id"] == lineage_id and event["operator"] == "improve" and event["status"] == "accepted"]
    if len(accepted_improvements) < window + 1:
        return False
    recent = accepted_improvements[-window:]
    earlier = accepted_improvements[:-window]
    if not earlier:
        return False
    prior_best = max(event["evaluation"]["public_score_milli"] for event in earlier)
    return all(event["evaluation"]["public_score_milli"] <= prior_best for event in recent)


def next_decision(campaign: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    budget = campaign["fixed_budget"]
    if len(events) < budget["max_drafts"]:
        n = len(events) + 1
        return {"operator": "draft", "parent_candidate_ref": None, "lineage_id": f"lin_draft_{n:02d}", "reason": "draft_quota"}
    by_id = {event["candidate_id"]: event for event in events}
    children = child_refs(events)
    buggy_leaves = [
        event for event in events
        if event["status"] == "buggy" and event["candidate_id"] not in children and debug_depth(event, by_id) < budget["max_debug_depth"]
    ]
    if buggy_leaves:
        parent = sorted(buggy_leaves, key=lambda item: (item["sequence"], item["candidate_id"].encode("utf-8")))[0]
        return {"operator": "debug", "parent_candidate_ref": parent["candidate_id"], "lineage_id": parent["lineage_id"], "reason": "debug_buggy_leaf"}
    best = best_accepted(events)
    require(best is not None, "no_candidate_available")
    if lineage_plateau(events, best["lineage_id"], budget["plateau_window"]):
        return {"operator": "improve", "parent_candidate_ref": best["candidate_id"], "lineage_id": f"lin_fork_{len(events)+1:02d}", "reason": "fork_plateau"}
    return {"operator": "improve", "parent_candidate_ref": best["candidate_id"], "lineage_id": best["lineage_id"], "reason": "improve_best"}


def build_event(template: dict[str, Any], campaign: dict[str, Any], events: list[dict[str, Any]], evaluator_key: SigningKey) -> dict[str, Any]:
    exact_fields(template, CANDIDATE_TEMPLATE_FIELDS, "candidate_template_fields_invalid")
    require(template["operator"] in OPERATORS, "candidate_operator_invalid")
    require(template["status"] in STATUSES and template["rejection_reason"] in REASONS, "candidate_expected_outcome_invalid")
    safe_int(template["public_score_milli"], "candidate_score_invalid", -SAFE_INT) if template["public_score_milli"] is not None else None
    decision = next_decision(campaign, events)
    require(template["operator"] == decision["operator"], "policy_operator_mismatch")
    require(template["parent_candidate_ref"] == decision["parent_candidate_ref"], "policy_parent_mismatch")
    require(template["lineage_id"] == decision["lineage_id"], "policy_lineage_mismatch")
    by_id = {event["candidate_id"]: event for event in events}
    if template["operator"] == "draft":
        require(template["parent_candidate_ref"] is None, "draft_parent_forbidden")
        source_tree = campaign["source_tree_digest"]
    else:
        require(template["parent_candidate_ref"] in by_id, "candidate_parent_missing")
        source_tree = by_id[template["parent_candidate_ref"]]["result_tree_digest"]
    used = {"actions": 1, "duration_ms": 30_000, "token_units": 20_000, "bytes": 1_000_000, "cost_microunits": 10_000}
    status, reason = classify_candidate(template, used, campaign["fixed_budget"])
    require((status, reason) == (template["status"], template["rejection_reason"]), "candidate_classification_mismatch")
    sequence = len(events)
    candidate_id = template["candidate_id"]
    event = {
        "schema_version": "genesis.improvement.candidate.event.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "ledger_id": "ril_01HRECURSIVEIMPROVE0001",
        "event_id": f"rievt_{sequence+1:02d}_01HRECURSIVE",
        "sequence": sequence,
        "previous_event_hash": events[-1]["event_hash"] if events else ZERO_HASH,
        "campaign_ref": campaign["campaign_id"],
        "campaign_digest": campaign["campaign_digest"],
        "candidate_id": candidate_id,
        "parent_candidate_ref": template["parent_candidate_ref"],
        "lineage_id": template["lineage_id"],
        "operator": template["operator"],
        "proposal_digest": label_digest(candidate_id + ":proposal"),
        "patch_digest": label_digest(candidate_id + ":patch"),
        "source_tree_digest": source_tree,
        "result_tree_digest": label_digest(candidate_id + ":result-tree"),
        "environment_digest": label_digest("genesis.improvement.environment.v0.1"),
        "budget_used": used,
        "execution": {
            "status": template["execution_status"],
            "output_digest": label_digest(candidate_id + ":output"),
            "artifact_digest": label_digest(candidate_id + ":artifact"),
            "error_class": "ValueError" if template["execution_status"] == "error" else ("TimeoutError" if template["execution_status"] == "timeout" else None),
        },
        "evaluation": {
            "public_score_milli": template["public_score_milli"],
            "public_pass": template["execution_status"] == "success" and template["public_score_milli"] is not None,
            "private_receipt_digest": label_digest(candidate_id + ":private-receipt"),
            "private_pass": template["private_pass"],
            "generalization_pass": template["generalization_pass"],
            "maintainability_pass": template["maintainability_pass"],
            "metric_manipulation_detected": template["metric_manipulation_detected"],
            "safety_regression_detected": template["safety_regression_detected"],
        },
        "status": status,
        "rejection_reason": reason,
        "recorded_at": f"2026-07-16T03:{11+sequence:02d}:00Z",
        "evaluator_id": "eval_01HGENESISPRIVATE0001",
        "evaluator_public_key": public_key_text(evaluator_key),
    }
    event["event_hash"] = digest_object(event)
    event["evaluator_signature"] = sign_digest(evaluator_key, "genesis.improvement.candidate.event.signature.v0.1", event["event_hash"])
    return event


def validate_event(event: dict[str, Any], campaign: dict[str, Any], prior: list[dict[str, Any]]) -> None:
    exact_fields(event, EVENT_FIELDS, "candidate_event_fields_invalid")
    require(event["schema_version"] == "genesis.improvement.candidate.event.v0.1", "candidate_event_schema_invalid")
    require(event["hash_profile"] == "genesis.hash.fields.v0.1", "candidate_event_hash_profile_invalid")
    require(event["sequence"] == len(prior), "candidate_sequence_invalid")
    require(event["previous_event_hash"] == (prior[-1]["event_hash"] if prior else ZERO_HASH), "candidate_previous_hash_invalid")
    require(event["campaign_ref"] == campaign["campaign_id"] and event["campaign_digest"] == campaign["campaign_digest"], "candidate_campaign_binding_invalid")
    require(event["operator"] in OPERATORS and event["status"] in STATUSES and event["rejection_reason"] in REASONS, "candidate_enum_invalid")
    require(event["candidate_id"] not in {item["candidate_id"] for item in prior}, "candidate_duplicate")
    decision = next_decision(campaign, prior)
    require(event["operator"] == decision["operator"], "policy_operator_mismatch")
    require(event["parent_candidate_ref"] == decision["parent_candidate_ref"], "policy_parent_mismatch")
    require(event["lineage_id"] == decision["lineage_id"], "policy_lineage_mismatch")
    by_id = {item["candidate_id"]: item for item in prior}
    expected_source = campaign["source_tree_digest"] if event["operator"] == "draft" else by_id[event["parent_candidate_ref"]]["result_tree_digest"]
    require(event["source_tree_digest"] == expected_source, "candidate_source_tree_invalid")
    exact_fields(event["budget_used"], USED_BUDGET_FIELDS, "candidate_budget_fields_invalid")
    for name in USED_BUDGET_FIELDS:
        safe_int(event["budget_used"][name], f"candidate_budget_{name}_invalid", 0)
    exact_fields(event["execution"], EXECUTION_FIELDS, "candidate_execution_fields_invalid")
    require(event["execution"]["status"] in {"success", "error", "timeout"}, "candidate_execution_status_invalid")
    exact_fields(event["evaluation"], EVALUATION_FIELDS, "candidate_evaluation_fields_invalid")
    for name in ["public_pass", "private_pass", "generalization_pass", "maintainability_pass", "metric_manipulation_detected", "safety_regression_detected"]:
        require(type(event["evaluation"][name]) is bool, f"candidate_evaluation_{name}_invalid")
    template = {
        "execution_status": event["execution"]["status"],
        "public_score_milli": event["evaluation"]["public_score_milli"],
        "private_pass": event["evaluation"]["private_pass"],
        "generalization_pass": event["evaluation"]["generalization_pass"],
        "maintainability_pass": event["evaluation"]["maintainability_pass"],
        "metric_manipulation_detected": event["evaluation"]["metric_manipulation_detected"],
        "safety_regression_detected": event["evaluation"]["safety_regression_detected"],
    }
    require(classify_candidate(template, event["budget_used"], campaign["fixed_budget"]) == (event["status"], event["rejection_reason"]), "candidate_classification_invalid")
    unsigned = {key: value for key, value in event.items() if key not in {"event_hash", "evaluator_signature"}}
    require(digest_object(unsigned) == event["event_hash"], "candidate_event_hash_invalid")
    verify_signature(event["evaluator_public_key"], event["evaluator_signature"], "genesis.improvement.candidate.event.signature.v0.1", event["event_hash"], "candidate_event_signature_invalid")


def build_signed_fixture(doc: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    campaign = build_campaign(doc)
    validate_campaign(campaign)
    evaluator_key = SigningKey(bytes.fromhex(doc["test_only_keys"]["evaluator_seed_hex"]))
    events: list[dict[str, Any]] = []
    for template in doc["candidate_templates"]:
        event = build_event(template, campaign, events, evaluator_key)
        validate_event(event, campaign, events)
        events.append(event)
    return campaign, events


def build_projection(campaign: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    by_lineage: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_lineage.setdefault(event["lineage_id"], []).append(event)
    lineages = []
    for lineage_id in sorted(by_lineage, key=lambda value: value.encode("utf-8")):
        items = by_lineage[lineage_id]
        accepted = [item for item in items if item["status"] == "accepted"]
        best = best_accepted(accepted)
        roots = [item for item in items if item["parent_candidate_ref"] is None or item["parent_candidate_ref"] not in {other["candidate_id"] for other in items}]
        root = sorted(roots, key=lambda item: (item["sequence"], item["candidate_id"].encode("utf-8")))[0]
        lineages.append({
            "lineage_id": lineage_id,
            "root_candidate_ref": root["candidate_id"],
            "candidate_count": len(items),
            "accepted_count": sum(item["status"] == "accepted" for item in items),
            "buggy_count": sum(item["status"] == "buggy" for item in items),
            "rejected_count": sum(item["status"] == "rejected" for item in items),
            "best_candidate_ref": best["candidate_id"] if best else None,
            "best_score_milli": best["evaluation"]["public_score_milli"] if best else None,
            "plateau_detected": lineage_plateau(events, lineage_id, campaign["fixed_budget"]["plateau_window"]),
        })
    best = best_accepted(events)
    promotion_ready = bool(best and all([
        best["status"] == "accepted",
        best["evaluation"]["private_pass"],
        best["evaluation"]["generalization_pass"],
        best["evaluation"]["maintainability_pass"],
        not best["evaluation"]["metric_manipulation_detected"],
        not best["evaluation"]["safety_regression_detected"],
    ]))
    projection = {
        "schema_version": "genesis.improvement.projection.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "campaign_ref": campaign["campaign_id"],
        "campaign_digest": campaign["campaign_digest"],
        "ledger_id": events[0]["ledger_id"] if events else "ril_01HRECURSIVEIMPROVE0001",
        "source_tree_digest": campaign["source_tree_digest"],
        "source_event_count": len(events),
        "source_last_event_hash": events[-1]["event_hash"] if events else ZERO_HASH,
        "candidate_count": len(events),
        "accepted_count": sum(item["status"] == "accepted" for item in events),
        "buggy_count": sum(item["status"] == "buggy" for item in events),
        "rejected_count": sum(item["status"] == "rejected" for item in events),
        "operator_counts": {name: sum(item["operator"] == name for item in events) for name in ["draft", "debug", "improve"]},
        "lineages": lineages,
        "best_candidate_ref": best["candidate_id"] if best else None,
        "best_score_milli": best["evaluation"]["public_score_milli"] if best else None,
        "next_decision": next_decision(campaign, events),
        "promotion": {
            "status": "candidate_ready" if promotion_ready else "not_ready",
            "candidate_ref": best["candidate_id"] if promotion_ready else None,
            "requires_guardian_approval": True,
            "required_capability": "code.propose_change",
            "direct_merge_forbidden": True,
        },
    }
    projection["projection_digest"] = digest_object(projection)
    return projection


def validate_projection(projection: dict[str, Any], campaign: dict[str, Any], events: list[dict[str, Any]]) -> None:
    expected = build_projection(campaign, events)
    require(projection == expected, "projection_mismatch")
    require(projection["promotion"]["requires_guardian_approval"] is True, "promotion_guardian_required")
    require(projection["promotion"]["direct_merge_forbidden"] is True, "promotion_direct_merge_forbidden")


def validate_expected(doc: dict[str, Any], projection: dict[str, Any]) -> None:
    expected = doc["expected"]
    require(projection["candidate_count"] == expected["candidate_count"], "expected_candidate_count_mismatch")
    require(len(projection["lineages"]) == expected["lineage_count"], "expected_lineage_count_mismatch")
    require(projection["operator_counts"] == expected["operator_counts"], "expected_operator_counts_mismatch")
    require({"accepted": projection["accepted_count"], "buggy": projection["buggy_count"], "rejected": projection["rejected_count"]} == expected["status_counts"], "expected_status_counts_mismatch")
    require(projection["best_candidate_ref"] == expected["best_candidate_ref"] and projection["best_score_milli"] == expected["best_score_milli"], "expected_best_candidate_mismatch")
    if expected["projection_digest"] is not None:
        require(projection["projection_digest"] == expected["projection_digest"], "expected_projection_digest_mismatch")


def validate_complete(doc: dict[str, Any], campaign: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    validate_campaign(campaign)
    prior: list[dict[str, Any]] = []
    for event in events:
        validate_event(event, campaign, prior)
        prior.append(event)
    projection = build_projection(campaign, events)
    validate_projection(projection, campaign, events)
    validate_expected(doc, projection)
    return projection


def expect_rejection(mutator, doc: dict[str, Any], campaign: dict[str, Any], events: list[dict[str, Any]], label: str) -> None:
    c = copy.deepcopy(campaign)
    e = copy.deepcopy(events)
    mutator(c, e)
    try:
        validate_complete(doc, c, e)
    except ConformanceError:
        return
    fail("negative_case_not_rejected:" + label)


def run_negative_cases(doc: dict[str, Any], campaign: dict[str, Any], events: list[dict[str, Any]]) -> int:
    cases = [
        ("campaign_schema", lambda c, e: c.__setitem__("schema_version", "genesis.improvement.campaign.v9")),
        ("campaign_hash_profile", lambda c, e: c.__setitem__("hash_profile", "bad")),
        ("campaign_grant", lambda c, e: c.__setitem__("guardian_grant_ref", "")),
        ("campaign_metric", lambda c, e: c["metric"].__setitem__("direction", "sideways")),
        ("campaign_policy", lambda c, e: c.__setitem__("policy_profile", "random")),
        ("max_candidates", lambda c, e: c["fixed_budget"].__setitem__("max_candidates", 0)),
        ("max_drafts", lambda c, e: c["fixed_budget"].__setitem__("max_drafts", 99)),
        ("network", lambda c, e: c["sandbox_profile"].__setitem__("network_mode", "open")),
        ("filesystem", lambda c, e: c["sandbox_profile"].__setitem__("filesystem_mode", "mutable")),
        ("secrets", lambda c, e: c["sandbox_profile"].__setitem__("secrets_available", True)),
        ("process", lambda c, e: c["sandbox_profile"].__setitem__("process_isolation", False)),
        ("output", lambda c, e: c["sandbox_profile"].__setitem__("output_capture", False)),
        ("environment", lambda c, e: c["sandbox_profile"].__setitem__("environment_reproducible", False)),
        ("private_visibility", lambda c, e: c["private_evaluation"].__setitem__("cases_visible_to_agent", True)),
        ("private_receipt", lambda c, e: c["private_evaluation"].__setitem__("receipt_only", False)),
        ("private_evaluator", lambda c, e: c["private_evaluation"].__setitem__("evaluator_separate", False)),
        ("campaign_digest", lambda c, e: c.__setitem__("campaign_digest", label_digest("tampered"))),
        ("campaign_signature", lambda c, e: c.__setitem__("guardian_signature", "ed25519sig:" + "0" * 128)),
        ("candidate_duplicate", lambda c, e: e[1].__setitem__("candidate_id", e[0]["candidate_id"])),
        ("candidate_sequence", lambda c, e: e[3].__setitem__("sequence", 99)),
        ("previous_hash", lambda c, e: e[3].__setitem__("previous_event_hash", ZERO_HASH)),
        ("campaign_ref", lambda c, e: e[3].__setitem__("campaign_ref", "ric_wrong")),
        ("event_campaign_digest", lambda c, e: e[3].__setitem__("campaign_digest", ZERO_HASH)),
        ("operator", lambda c, e: e[3].__setitem__("operator", "improve")),
        ("parent", lambda c, e: e[3].__setitem__("parent_candidate_ref", e[0]["candidate_id"])),
        ("lineage", lambda c, e: e[3].__setitem__("lineage_id", "lin_wrong")),
        ("source_tree", lambda c, e: e[3].__setitem__("source_tree_digest", ZERO_HASH)),
        ("budget_actions", lambda c, e: e[4]["budget_used"].__setitem__("actions", c["fixed_budget"]["max_actions"] + 1)),
        ("budget_duration", lambda c, e: e[4]["budget_used"].__setitem__("duration_ms", c["fixed_budget"]["max_duration_ms"] + 1)),
        ("budget_tokens", lambda c, e: e[4]["budget_used"].__setitem__("token_units", c["fixed_budget"]["max_token_units"] + 1)),
        ("budget_bytes", lambda c, e: e[4]["budget_used"].__setitem__("bytes", c["fixed_budget"]["max_bytes"] + 1)),
        ("budget_cost", lambda c, e: e[4]["budget_used"].__setitem__("cost_microunits", c["fixed_budget"]["max_cost_microunits"] + 1)),
        ("status", lambda c, e: e[8].__setitem__("status", "accepted")),
        ("reason", lambda c, e: e[8].__setitem__("rejection_reason", None)),
        ("event_hash", lambda c, e: e[4].__setitem__("event_hash", ZERO_HASH)),
        ("event_signature", lambda c, e: e[4].__setitem__("evaluator_signature", "ed25519sig:" + "0" * 128)),
        ("evaluator_key", lambda c, e: e[4].__setitem__("evaluator_public_key", c["guardian_public_key"])),
        ("event_order", lambda c, e: e.__setitem__(slice(2, 4), [e[3], e[2]])),
    ]
    for label, mutator in cases:
        expect_rejection(mutator, doc, campaign, events, label)
    return len(cases)


def command_validate(vector_path: Path) -> int:
    doc = load_vector(vector_path)
    campaign, events = build_signed_fixture(doc)
    projection = validate_complete(doc, campaign, events)
    negatives = run_negative_cases(doc, campaign, events)
    require(negatives == doc["expected"]["boundary_rejections"], "boundary_rejection_count_mismatch")
    print(f"OK recursive improvement campaign ({len(events)} candidates, {len(projection['lineages'])} lineages)")
    counts = projection["operator_counts"]
    print(f"OK operators (draft={counts['draft']}, debug={counts['debug']}, improve={counts['improve']})")
    print(f"OK outcomes ({projection['accepted_count']} accepted, {projection['buggy_count']} buggy, {projection['rejected_count']} rejected)")
    print(f"OK projection digest {projection['projection_digest']}")
    print(f"OK recursive improvement boundary rejection cases ({negatives})")
    print("NOTE promotion requires guardian review.")
    return 0


def emit_samples() -> int:
    doc = load_vector(DEFAULT_VECTOR)
    campaign, events = build_signed_fixture(doc)
    projection = validate_complete(doc, campaign, events)
    output = ROOT / ".tmp_recursive_improvement_samples.json"
    output.write_text(json.dumps({"campaign": campaign, "candidate_event": events[0], "projection": projection}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "validate"
    try:
        if command == "validate":
            vector = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_VECTOR
            return command_validate(vector)
        if command == "emit-samples":
            return emit_samples()
        fail("command_invalid")
    except (ConformanceError, KeyError, TypeError, ValueError, OSError) as exc:
        print(f"FAIL recursive improvement laboratory: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

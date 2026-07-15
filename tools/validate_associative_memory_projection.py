#!/usr/bin/env python3
"""Valida la proyección asociativa reconstruible sin convertirla en memoria autoritativa."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "associative_memory_projection_vectors.json"

PROJECTION_FIELDS = {
    "schema_version",
    "hash_profile",
    "projection_id",
    "instance_id",
    "projection_profile",
    "coverage_status",
    "source_first_sequence",
    "source_last_sequence",
    "source_event_count",
    "source_last_event_hash",
    "nodes",
    "edges",
    "projection_digest",
}
NODE_FIELDS = {"node_id", "node_kind", "subject_digest", "source_event_refs"}
EDGE_FIELDS = {
    "edge_id",
    "source_node_id",
    "target_node_id",
    "relation",
    "derivation",
    "confidence_basis_points",
    "source_event_refs",
    "confirmation_event_ref",
}
EVENT_REQUIRED_FIELDS = {
    "schema_version",
    "hash_profile",
    "event_id",
    "instance_id",
    "body_id",
    "sequence",
    "previous_event_hash",
    "event_type",
    "actor",
    "content_digest",
    "content_type",
    "observed_at",
    "provenance_digest",
    "privacy",
    "event_hash",
}
EVENT_ALLOWED_FIELDS = EVENT_REQUIRED_FIELDS | {
    "content_ref",
    "provenance_ref",
    "signature",
}
IDENTITY_AUTHORITY_FIELDS = {
    "companion_name",
    "guardian_id",
    "seed_id",
    "seed_root_hash",
    "identity_digest",
    "active_writer",
    "authority_epoch",
    "write_memory",
}
RAW_PLATFORM_FIELDS = {
    "raw_content",
    "payload",
    "label",
    "embedding",
    "absolute_path",
    "platform_handle",
    "platform_account",
    "vendor",
    "token",
    "credential",
}
EXPECTED_DOMAINS = {
    "memory_event": "genesis.memory.event.v0.1",
    "node": "genesis.memory.associative.node.v0.1",
    "edge": "genesis.memory.associative.edge.v0.1",
    "projection_id": "genesis.memory.associative.projection.id.v0.1",
    "projection": "genesis.memory.associative.projection.v0.1",
}
SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
NODE_ID_PATTERN = re.compile(r"^nsha256:[a-f0-9]{64}$")
EDGE_ID_PATTERN = re.compile(r"^esha256:[a-f0-9]{64}$")
PROJECTION_ID_PATTERN = re.compile(r"^psha256:[a-f0-9]{64}$")


class ConformanceError(ValueError):
    """Error estable compartido por las implementaciones de conformidad."""


def utf8_sorted(values: list[str]) -> list[str]:
    return sorted(values, key=lambda value: value.encode("utf-8"))


def frame(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ConformanceError("text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    preimage = frame(domain) + b"".join(frame(field) for field in fields)
    return prefix + hashlib.sha256(preimage).hexdigest()


def exact_fields(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    additional = actual - expected
    if additional & IDENTITY_AUTHORITY_FIELDS:
        raise ConformanceError("projection_contains_identity_authority")
    if additional & RAW_PLATFORM_FIELDS:
        raise ConformanceError("projection_contains_raw_or_platform_data")
    if actual != expected:
        raise ConformanceError(f"{label}_fields_invalid")


def compute_memory_event_hash(event: dict) -> str:
    return hash_fields(
        EXPECTED_DOMAINS["memory_event"],
        [
            event["schema_version"],
            event["event_id"],
            event["instance_id"],
            event["body_id"],
            str(event["sequence"]),
            event["previous_event_hash"],
            event["event_type"],
            event["actor"],
            event["content_digest"],
            event["content_type"],
            event["observed_at"],
            event["provenance_digest"],
            event["privacy"],
        ],
        "evsha256:",
    )


def compute_node_id(node: dict) -> str:
    refs = utf8_sorted(node["source_event_refs"])
    return hash_fields(
        EXPECTED_DOMAINS["node"],
        [node["node_kind"], node["subject_digest"], str(len(refs)), *refs],
        "nsha256:",
    )


def compute_edge_id(edge: dict) -> str:
    refs = utf8_sorted(edge["source_event_refs"])
    return hash_fields(
        EXPECTED_DOMAINS["edge"],
        [
            edge["source_node_id"],
            edge["target_node_id"],
            edge["relation"],
            edge["derivation"],
            str(edge["confidence_basis_points"]),
            str(len(refs)),
            *refs,
            "" if edge["confirmation_event_ref"] is None else edge["confirmation_event_ref"],
        ],
        "esha256:",
    )


def compute_projection_id(projection: dict) -> str:
    return hash_fields(
        EXPECTED_DOMAINS["projection_id"],
        [
            projection["schema_version"],
            projection["instance_id"],
            projection["projection_profile"],
            projection["coverage_status"],
            str(projection["source_first_sequence"]),
            str(projection["source_last_sequence"]),
            str(projection["source_event_count"]),
            projection["source_last_event_hash"],
        ],
        "psha256:",
    )


def compute_projection_digest(projection: dict) -> str:
    node_ids = utf8_sorted([node["node_id"] for node in projection["nodes"]])
    edge_ids = utf8_sorted([edge["edge_id"] for edge in projection["edges"]])
    return hash_fields(
        EXPECTED_DOMAINS["projection"],
        [
            projection["schema_version"],
            projection["hash_profile"],
            projection["projection_id"],
            projection["instance_id"],
            projection["projection_profile"],
            projection["coverage_status"],
            str(projection["source_first_sequence"]),
            str(projection["source_last_sequence"]),
            str(projection["source_event_count"]),
            projection["source_last_event_hash"],
            str(len(node_ids)),
            *node_ids,
            str(len(edge_ids)),
            *edge_ids,
        ],
    )


def node_kind_for_event(event_type: str) -> str:
    if event_type.startswith("sense."):
        return "observation"
    if event_type == "knowledge.relation.confirmed":
        return "decision"
    if event_type.startswith("knowledge."):
        return "concept"
    if event_type.startswith("body."):
        return "body"
    if event_type.startswith("time."):
        return "time_anchor"
    return "memory_event"


def build_projection(events: list[dict], coverage_status: str) -> dict:
    projection = {
        "schema_version": "genesis.memory.associative.projection.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "projection_id": "",
        "instance_id": events[0]["instance_id"],
        "projection_profile": "genesis.memory.associative.algorithm.v0.1",
        "coverage_status": coverage_status,
        "source_first_sequence": events[0]["sequence"],
        "source_last_sequence": events[-1]["sequence"],
        "source_event_count": len(events),
        "source_last_event_hash": events[-1]["event_hash"],
        "nodes": [],
        "edges": [],
        "projection_digest": "",
    }
    projection["projection_id"] = compute_projection_id(projection)

    nodes_by_event: dict[str, dict] = {}
    for event in events:
        node = {
            "node_id": "",
            "node_kind": node_kind_for_event(event["event_type"]),
            "subject_digest": event["content_digest"],
            "source_event_refs": [event["event_id"]],
        }
        node["node_id"] = compute_node_id(node)
        nodes_by_event[event["event_id"]] = node
        projection["nodes"].append(node)
    projection["nodes"].sort(key=lambda node: node["node_id"].encode("utf-8"))

    def add_edge(
        source_event: dict,
        target_event: dict,
        relation: str,
        derivation: str,
        confidence: int,
        confirmation_ref: str | None,
    ) -> None:
        edge = {
            "edge_id": "",
            "source_node_id": nodes_by_event[source_event["event_id"]]["node_id"],
            "target_node_id": nodes_by_event[target_event["event_id"]]["node_id"],
            "relation": relation,
            "derivation": derivation,
            "confidence_basis_points": confidence,
            "source_event_refs": utf8_sorted(
                [source_event["event_id"], target_event["event_id"]]
            ),
            "confirmation_event_ref": confirmation_ref,
        }
        edge["edge_id"] = compute_edge_id(edge)
        projection["edges"].append(edge)

    for index in range(1, len(events)):
        add_edge(events[index - 1], events[index], "memory.next", "extracted", 10000, None)
    for index in range(2, len(events)):
        add_edge(events[index - 2], events[index], "context.nearby", "inferred", 5000, None)
    for index in range(1, len(events)):
        current = events[index]
        previous = events[index - 1]
        if (
            current["event_type"] == "knowledge.relation.confirmed"
            and previous["event_type"] == "knowledge.relation.proposed"
        ):
            add_edge(
                current,
                previous,
                "knowledge.confirms",
                "confirmed",
                10000,
                current["event_id"],
            )

    projection["edges"].sort(key=lambda edge: edge["edge_id"].encode("utf-8"))
    projection["projection_digest"] = compute_projection_digest(projection)
    return projection


def validate_memory_events(events: list[dict]) -> tuple[str, dict[str, dict]]:
    if not isinstance(events, list) or not events:
        raise ConformanceError("source_memory_events_invalid")
    event_ids = [event.get("event_id") for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ConformanceError("duplicate_source_event_id")
    for event in events:
        if not EVENT_REQUIRED_FIELDS <= set(event) or set(event) - EVENT_ALLOWED_FIELDS:
            raise ConformanceError("source_memory_event_fields_invalid")
        if event["schema_version"] != "genesis.memory.event.v0.1":
            raise ConformanceError("source_memory_event_schema_invalid")
        if event["hash_profile"] != "genesis.hash.fields.v0.1":
            raise ConformanceError("source_memory_event_hash_profile_invalid")

    instance_id = events[0]["instance_id"]
    if any(event["instance_id"] != instance_id for event in events):
        raise ConformanceError("source_instance_id_mismatch")

    for event in events:
        if compute_memory_event_hash(event) != event["event_hash"]:
            raise ConformanceError("source_memory_event_hash_mismatch")

    for index, event in enumerate(events):
        if index > 0:
            previous = events[index - 1]
            if (
                event["sequence"] != previous["sequence"] + 1
                or event["previous_event_hash"] != previous["event_hash"]
            ):
                raise ConformanceError("source_memory_chain_broken")
        elif event["sequence"] == 0 and event["previous_event_hash"] != "GENESIS":
            raise ConformanceError("source_memory_chain_broken")
    return instance_id, {event["event_id"]: event for event in events}


def validate_projection(projection: dict, events: list[dict]) -> dict[str, int]:
    if not isinstance(projection, dict):
        raise ConformanceError("projection_invalid")
    exact_fields(projection, PROJECTION_FIELDS, "projection")
    if projection["schema_version"] != "genesis.memory.associative.projection.v0.1":
        raise ConformanceError("projection_schema_version_invalid")
    if projection["hash_profile"] != "genesis.hash.fields.v0.1":
        raise ConformanceError("projection_hash_profile_invalid")
    if projection["projection_profile"] != "genesis.memory.associative.algorithm.v0.1":
        raise ConformanceError("projection_profile_invalid")
    if projection["coverage_status"] not in {"complete", "partial"}:
        raise ConformanceError("coverage_status_invalid")

    instance_id, event_by_id = validate_memory_events(events)
    if projection["instance_id"] != instance_id:
        raise ConformanceError("projection_instance_id_mismatch")
    if (
        projection["source_first_sequence"] != events[0]["sequence"]
        or projection["source_last_sequence"] != events[-1]["sequence"]
    ):
        raise ConformanceError("source_sequence_boundary_mismatch")
    if projection["source_event_count"] != len(events):
        raise ConformanceError("source_event_count_mismatch")
    if projection["source_last_event_hash"] != events[-1]["event_hash"]:
        raise ConformanceError("source_last_event_hash_mismatch")
    if (
        projection["coverage_status"] == "complete"
        and projection["source_event_count"]
        != projection["source_last_sequence"] - projection["source_first_sequence"] + 1
    ):
        raise ConformanceError("complete_coverage_not_contiguous")
    if not PROJECTION_ID_PATTERN.fullmatch(projection["projection_id"]):
        raise ConformanceError("projection_id_format_invalid")
    if compute_projection_id(projection) != projection["projection_id"]:
        raise ConformanceError("projection_id_mismatch")

    nodes = projection["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise ConformanceError("nodes_invalid")
    node_ids = [node.get("node_id") for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ConformanceError("duplicate_node_id")
    if node_ids != utf8_sorted(node_ids):
        raise ConformanceError("nodes_not_sorted")

    for node in nodes:
        exact_fields(node, NODE_FIELDS, "node")
        refs = node["source_event_refs"]
        if not isinstance(refs, list) or not refs:
            raise ConformanceError("node_source_event_refs_invalid")
        if len(refs) != len(set(refs)):
            raise ConformanceError("duplicate_source_event_ref")
        if refs != utf8_sorted(refs):
            raise ConformanceError("source_event_refs_not_sorted")
        if any(ref not in event_by_id for ref in refs):
            raise ConformanceError("unknown_source_event_ref")
        if not SHA256_PATTERN.fullmatch(node["subject_digest"]):
            raise ConformanceError("node_subject_digest_invalid")
        if not NODE_ID_PATTERN.fullmatch(node["node_id"]):
            raise ConformanceError("node_id_format_invalid")
        if compute_node_id(node) != node["node_id"]:
            raise ConformanceError("node_id_mismatch")

    edges = projection["edges"]
    if not isinstance(edges, list):
        raise ConformanceError("edges_invalid")
    edge_ids = [edge.get("edge_id") for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ConformanceError("duplicate_edge_id")
    if edge_ids != utf8_sorted(edge_ids):
        raise ConformanceError("edges_not_sorted")
    node_id_set = set(node_ids)

    for edge in edges:
        exact_fields(edge, EDGE_FIELDS, "edge")
        refs = edge["source_event_refs"]
        if not isinstance(refs, list) or not refs:
            raise ConformanceError("edge_source_event_refs_invalid")
        if len(refs) != len(set(refs)):
            raise ConformanceError("duplicate_source_event_ref")
        if refs != utf8_sorted(refs):
            raise ConformanceError("source_event_refs_not_sorted")
        if any(ref not in event_by_id for ref in refs):
            raise ConformanceError("unknown_source_event_ref")
        if edge["source_node_id"] not in node_id_set or edge["target_node_id"] not in node_id_set:
            raise ConformanceError("edge_endpoint_missing")
        if edge["source_node_id"] == edge["target_node_id"]:
            raise ConformanceError("self_association_forbidden")
        if not EDGE_ID_PATTERN.fullmatch(edge["edge_id"]):
            raise ConformanceError("edge_id_format_invalid")
        if compute_edge_id(edge) != edge["edge_id"]:
            raise ConformanceError("edge_id_mismatch")

        derivation = edge["derivation"]
        confidence = edge["confidence_basis_points"]
        confirmation_ref = edge["confirmation_event_ref"]
        if derivation == "extracted":
            if confidence != 10000:
                raise ConformanceError("extracted_confidence_invalid")
            if confirmation_ref is not None:
                raise ConformanceError("extracted_confirmation_forbidden")
        elif derivation == "inferred":
            if not isinstance(confidence, int) or isinstance(confidence, bool) or not 0 <= confidence < 10000:
                raise ConformanceError("inferred_confidence_invalid")
            if confirmation_ref is not None:
                raise ConformanceError("inferred_confirmation_forbidden")
        elif derivation == "confirmed":
            if confidence != 10000:
                raise ConformanceError("confirmed_confidence_invalid")
            if confirmation_ref is None:
                raise ConformanceError("confirmed_confirmation_required")
            if confirmation_ref not in refs:
                raise ConformanceError("confirmation_event_not_in_source_refs")
            confirmation_event = event_by_id.get(confirmation_ref)
            if (
                confirmation_event is None
                or confirmation_event["event_type"] != "knowledge.relation.confirmed"
                or confirmation_event["actor"] not in {"guardian", "instance"}
            ):
                raise ConformanceError("confirmation_event_invalid")
        else:
            raise ConformanceError("edge_derivation_invalid")

    if compute_projection_digest(projection) != projection["projection_digest"]:
        raise ConformanceError("projection_digest_mismatch")
    if projection != build_projection(events, projection["coverage_status"]):
        raise ConformanceError("projection_rebuild_mismatch")
    return {"events": len(events), "nodes": len(nodes), "edges": len(edges)}


def apply_mutation(test_case: dict, base_projection: dict, base_events: list[dict]) -> tuple[dict, list[dict]]:
    projection = deepcopy(base_projection)
    events = deepcopy(base_events)
    mutation = test_case["mutation"]
    operation = mutation["operation"]

    if operation == "projection_add_field":
        projection[mutation["field"]] = mutation["value"]
    elif operation == "projection_set":
        projection[mutation["field"]] = mutation["value"]
    elif operation == "source_event_set":
        events[mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "node_set":
        projection["nodes"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "node_add_field":
        projection["nodes"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "node_reverse_refs":
        projection["nodes"][mutation["index"]]["source_event_refs"].reverse()
    elif operation == "nodes_reverse":
        projection["nodes"].reverse()
    elif operation == "node_duplicate":
        projection["nodes"].append(deepcopy(projection["nodes"][mutation["index"]]))
    elif operation == "edge_set":
        projection["edges"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "edges_reverse":
        projection["edges"].reverse()
    elif operation == "edge_duplicate":
        projection["edges"].append(deepcopy(projection["edges"][mutation["index"]]))
    else:
        raise ConformanceError(f"unknown_projection_mutation:{operation}")

    for index in mutation.get("recompute_source_event_hashes", []):
        events[index]["event_hash"] = compute_memory_event_hash(events[index])
    for index in mutation.get("recompute_node_ids", []):
        projection["nodes"][index]["node_id"] = compute_node_id(projection["nodes"][index])
    if mutation.get("recompute_node_ids"):
        projection["nodes"].sort(key=lambda node: node["node_id"].encode("utf-8"))
    for index in mutation.get("recompute_edge_ids", []):
        projection["edges"][index]["edge_id"] = compute_edge_id(projection["edges"][index])
    if mutation.get("recompute_edge_ids"):
        projection["edges"].sort(key=lambda edge: edge["edge_id"].encode("utf-8"))
    if mutation.get("recompute_projection_digest"):
        projection["projection_digest"] = compute_projection_digest(projection)
    return projection, events


def evaluate_rejection(test_case: dict, projection: dict, events: list[dict]) -> str | None:
    candidate_projection, candidate_events = apply_mutation(test_case, projection, events)
    try:
        validate_projection(candidate_projection, candidate_events)
    except ConformanceError as error:
        return str(error)
    return None


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []
    if vectors.get("profile") != "genesis.memory.associative.projection.conformance.v0.1":
        failures.append("vector_profile_invalid")
    if vectors.get("status") != "draft":
        failures.append("vector_status_invalid")
    if vectors.get("domains") != EXPECTED_DOMAINS:
        failures.append("vector_domains_invalid")

    try:
        counts = validate_projection(vectors["projection"], vectors["source_memory_events"])
    except (ConformanceError, KeyError, TypeError) as error:
        failures.append(f"positive_projection:{error}")
        counts = {"events": 0, "nodes": 0, "edges": 0}

    derivations = {edge["derivation"] for edge in vectors["projection"]["edges"]}
    if derivations != {"extracted", "inferred", "confirmed"}:
        failures.append("derivation_fixture_coverage_invalid")

    for test_case in vectors["must_reject"]:
        actual = evaluate_rejection(
            test_case,
            vectors["projection"],
            vectors["source_memory_events"],
        )
        if actual != test_case["expected_error"]:
            failures.append(
                f"{test_case['case_id']}:expected={test_case['expected_error']}:actual={actual}"
            )

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    print(f"OK accepted memory chain ({counts['events']} events)")
    print(f"OK deterministic associative projection ({counts['nodes']} nodes, {counts['edges']} edges)")
    print("OK provenance keeps extracted, inferred, and confirmed relations distinct")
    print(f"OK associative boundary rejection cases ({len(vectors['must_reject'])})")
    print("NOTE The projection is a rebuildable cache, never memory or identity authority.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

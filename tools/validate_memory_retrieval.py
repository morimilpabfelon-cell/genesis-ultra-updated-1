#!/usr/bin/env python3
"""Validate deterministic, rebuildable memory retrieval without granting authority."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "memory_retrieval_vectors.json"

DOMAINS = {
    "memory_event": "genesis.memory.event.v0.1",
    "record": "genesis.memory.retrieval.record.v0.1",
    "frame": "genesis.memory.retrieval.frame.v0.1",
    "checkpoint": "genesis.memory.retrieval.checkpoint.v0.1",
    "query": "genesis.memory.retrieval.query.v0.1",
    "query_result": "genesis.memory.retrieval.query.result.v0.1",
    "projection_id": "genesis.memory.retrieval.projection.id.v0.1",
    "projection": "genesis.memory.retrieval.projection.v0.1",
}
PROFILE = "genesis.memory.retrieval.algorithm.v0.1"
EVENT_FIELDS = {
    "schema_version", "hash_profile", "event_id", "instance_id", "body_id", "sequence",
    "previous_event_hash", "event_type", "actor", "content_digest", "content_type",
    "observed_at", "provenance_digest", "privacy", "event_hash",
}
RECORD_FIELDS = {
    "record_id", "event_id", "gate_decision_ref", "content_digest", "normalized_text", "accepted_at"
}
PROJECTION_FIELDS = {
    "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
    "coverage_status", "source_first_sequence", "source_last_sequence", "source_event_count",
    "source_last_event_hash", "record_count", "frames", "lexicon", "checkpoints",
    "query_results", "projection_digest"
}
FRAME_FIELDS = {
    "frame_id", "event_id", "sequence", "observed_at", "content_digest", "content_type",
    "token_count", "terms"
}
TERM_FIELDS = {"term", "frequency"}
LEXICON_FIELDS = {"term", "document_frequency", "event_refs"}
CHECKPOINT_FIELDS = {"sequence", "frame_count", "frames_digest"}
QUERY_RESULT_SET_FIELDS = {
    "query_id", "query_digest", "normalized_terms", "as_of_sequence", "top_k",
    "candidate_count", "results", "result_digest"
}
RESULT_FIELDS = {
    "rank", "event_id", "frame_id", "sequence", "score", "lexical_score", "graph_score",
    "temporal_score", "matched_terms", "reason_codes"
}
IDENTITY_AUTHORITY_FIELDS = {
    "companion_name", "guardian_id", "seed_id", "seed_root_hash", "identity_digest",
    "active_writer", "authority_epoch", "write_memory"
}
RAW_PLATFORM_FIELDS = {
    "raw_content", "payload", "embedding", "absolute_path", "platform_handle",
    "platform_account", "vendor", "token", "credential", "normalized_text"
}
TOKEN_PATTERN = re.compile(r"^[a-z0-9]+$")


class ConformanceError(ValueError):
    """Stable error shared by the independent conformance implementations."""


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
    preimage = frame(domain) + b"".join(frame(value) for value in fields)
    return prefix + hashlib.sha256(preimage).hexdigest()


def exact_fields(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    extra = actual - expected
    if extra & IDENTITY_AUTHORITY_FIELDS:
        raise ConformanceError("retrieval_contains_identity_authority")
    if extra & RAW_PLATFORM_FIELDS:
        raise ConformanceError("retrieval_contains_raw_or_platform_data")
    if actual != expected:
        raise ConformanceError(f"{label}_fields_invalid")


def normalize_terms(text: str) -> list[str]:
    if not isinstance(text, str):
        raise ConformanceError("retrieval_text_invalid")
    if unicodedata.normalize("NFC", text) != text:
        raise ConformanceError("retrieval_text_not_nfc")
    folded = unicodedata.normalize("NFKD", text.casefold())
    asciiish = "".join(char for char in folded if not unicodedata.category(char).startswith("M"))
    return re.findall(r"[a-z0-9]+", asciiish)


def compute_memory_event_hash(event: dict) -> str:
    return hash_fields(DOMAINS["memory_event"], [
        event["schema_version"], event["event_id"], event["instance_id"], event["body_id"],
        str(event["sequence"]), event["previous_event_hash"], event["event_type"], event["actor"],
        event["content_digest"], event["content_type"], event["observed_at"],
        event["provenance_digest"], event["privacy"],
    ], "evsha256:")


def compute_record_id(record: dict) -> str:
    return hash_fields(DOMAINS["record"], [
        record["event_id"], record["gate_decision_ref"], record["content_digest"], record["accepted_at"]
    ], "rrsha256:")


def term_frequencies(text: str) -> tuple[list[dict], int]:
    tokens = normalize_terms(text)
    counts: dict[str, int] = {}
    for token in tokens:
        counts[token] = counts.get(token, 0) + 1
    return ([{"term": term, "frequency": counts[term]} for term in utf8_sorted(list(counts))], len(tokens))


def compute_frame_id(frame_record: dict) -> str:
    flattened = []
    for term in frame_record["terms"]:
        flattened.extend([term["term"], str(term["frequency"])])
    return hash_fields(DOMAINS["frame"], [
        frame_record["event_id"], str(frame_record["sequence"]), frame_record["observed_at"],
        frame_record["content_digest"], frame_record["content_type"], str(frame_record["token_count"]),
        str(len(frame_record["terms"])), *flattened,
    ], "rfsha256:")


def compute_checkpoint_digest(sequence: int, frames: list[dict]) -> str:
    ids = [item["frame_id"] for item in frames if item["sequence"] <= sequence]
    return hash_fields(DOMAINS["checkpoint"], [str(sequence), str(len(ids)), *ids])


def compute_query_digest(query: dict, normalized: list[str]) -> str:
    anchors = utf8_sorted(list(query.get("anchor_event_refs", [])))
    return hash_fields(DOMAINS["query"], [
        query["query_id"], str(query["as_of_sequence"]), str(query["top_k"]),
        str(len(normalized)), *normalized, str(len(anchors)), *anchors,
    ], "rqsha256:")


def build_adjacency(associative: dict) -> dict[str, set[str]]:
    nodes = associative.get("nodes", []) if isinstance(associative, dict) else []
    edges = associative.get("edges", []) if isinstance(associative, dict) else []
    refs_by_node = {
        node.get("node_id"): set(node.get("source_event_refs", []))
        for node in nodes if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        left = refs_by_node.get(edge.get("source_node_id"), set())
        right = refs_by_node.get(edge.get("target_node_id"), set())
        for source in left:
            for target in right:
                if source == target:
                    continue
                adjacency.setdefault(source, set()).add(target)
                adjacency.setdefault(target, set()).add(source)
    return adjacency


def compute_result_digest(result_set: dict) -> str:
    flattened: list[str] = []
    for result in result_set["results"]:
        flattened.extend([
            str(result["rank"]), result["event_id"], result["frame_id"], str(result["sequence"]),
            str(result["score"]), str(result["lexical_score"]), str(result["graph_score"]),
            str(result["temporal_score"]), str(len(result["matched_terms"])), *result["matched_terms"],
            str(len(result["reason_codes"])), *result["reason_codes"],
        ])
    return hash_fields(DOMAINS["query_result"], [
        result_set["query_digest"], str(result_set["candidate_count"]),
        str(len(result_set["results"])), *flattened,
    ])


def execute_query(query: dict, frames: list[dict], adjacency: dict[str, set[str]], latest_sequence: int) -> dict:
    normalized = utf8_sorted(list(set(normalize_terms(query["text"]))))
    as_of = query["as_of_sequence"]
    top_k = query["top_k"]
    if not isinstance(as_of, int) or as_of < 0 or as_of > latest_sequence:
        raise ConformanceError("query_as_of_sequence_invalid")
    if not isinstance(top_k, int) or top_k < 1 or top_k > 20:
        raise ConformanceError("query_top_k_invalid")
    candidates = [item for item in frames if item["sequence"] <= as_of]
    candidate_count = len(candidates)
    anchors = set(query.get("anchor_event_refs", []))
    known_events = {item["event_id"] for item in candidates}
    if not anchors.issubset(known_events):
        raise ConformanceError("query_anchor_event_unknown_or_future")
    document_frequency: dict[str, int] = {}
    for term in normalized:
        document_frequency[term] = sum(
            any(pair["term"] == term for pair in item["terms"]) for item in candidates
        )
    scored = []
    for item in candidates:
        frequencies = {pair["term"]: pair["frequency"] for pair in item["terms"]}
        matched = [term for term in normalized if term in frequencies]
        lexical = 0
        for term in matched:
            rarity = ((candidate_count + 1) * 100000) // (document_frequency[term] + 1)
            term_frequency = frequencies[term]
            tf_weight = (term_frequency * 1000) // (term_frequency + 1)
            lexical += (rarity * tf_weight) // 1000
        if item["event_id"] in anchors:
            graph = 300000
            graph_reason = "graph_anchor"
        elif any(item["event_id"] in adjacency.get(anchor, set()) for anchor in anchors):
            graph = 180000
            graph_reason = "graph_neighbor"
        else:
            graph = 0
            graph_reason = None
        temporal = ((item["sequence"] + 1) * 100000) // (as_of + 1)
        if lexical == 0 and graph == 0:
            continue
        reasons = []
        if lexical:
            reasons.append("lexical_match")
        if graph_reason:
            reasons.append(graph_reason)
        scored.append({
            "event_id": item["event_id"],
            "frame_id": item["frame_id"],
            "sequence": item["sequence"],
            "score": lexical * 7 + graph * 2 + temporal,
            "lexical_score": lexical,
            "graph_score": graph,
            "temporal_score": temporal,
            "matched_terms": matched,
            "reason_codes": reasons,
        })
    scored.sort(key=lambda item: (-item["score"], -item["sequence"], item["event_id"].encode("utf-8")))
    results = []
    for rank, item in enumerate(scored[:top_k], start=1):
        results.append({"rank": rank, **item})
    result_set = {
        "query_id": query["query_id"],
        "query_digest": compute_query_digest(query, normalized),
        "normalized_terms": normalized,
        "as_of_sequence": as_of,
        "top_k": top_k,
        "candidate_count": candidate_count,
        "results": results,
        "result_digest": "",
    }
    result_set["result_digest"] = compute_result_digest(result_set)
    return result_set


def compute_projection_id(projection: dict) -> str:
    return hash_fields(DOMAINS["projection_id"], [
        projection["schema_version"], projection["instance_id"], projection["projection_profile"],
        projection["coverage_status"], str(projection["source_first_sequence"]),
        str(projection["source_last_sequence"]), str(projection["source_event_count"]),
        projection["source_last_event_hash"],
    ], "rpsha256:")


def compute_projection_digest(projection: dict) -> str:
    lexicon_flat: list[str] = []
    for item in projection["lexicon"]:
        lexicon_flat.extend([
            item["term"], str(item["document_frequency"]),
            str(len(item["event_refs"])), *item["event_refs"]
        ])
    return hash_fields(DOMAINS["projection"], [
        projection["schema_version"], projection["hash_profile"], projection["projection_id"],
        projection["instance_id"], projection["projection_profile"], projection["coverage_status"],
        str(projection["source_first_sequence"]), str(projection["source_last_sequence"]),
        str(projection["source_event_count"]), projection["source_last_event_hash"],
        str(projection["record_count"]), str(len(projection["frames"])),
        *[item["frame_id"] for item in projection["frames"]],
        str(len(projection["lexicon"])), *lexicon_flat,
        str(len(projection["checkpoints"])), *[item["frames_digest"] for item in projection["checkpoints"]],
        str(len(projection["query_results"])), *[item["result_digest"] for item in projection["query_results"]],
    ])


def validate_inputs(document: dict) -> None:
    if document.get("profile") != "genesis.memory.retrieval.conformance.v0.1":
        raise ConformanceError("retrieval_conformance_profile_invalid")
    if document.get("domains") != DOMAINS:
        raise ConformanceError("retrieval_domains_invalid")
    events = document.get("source_memory_events")
    records = document.get("accepted_records")
    queries = document.get("queries")
    if not isinstance(events, list) or not events:
        raise ConformanceError("source_memory_events_invalid")
    if not isinstance(records, list) or len(records) != len(events):
        raise ConformanceError("accepted_record_coverage_invalid")
    if not isinstance(queries, list) or not queries:
        raise ConformanceError("retrieval_queries_invalid")
    instance = events[0].get("instance_id")
    event_ids = set()
    for index, event in enumerate(events):
        exact_fields(event, EVENT_FIELDS, "source_event")
        if event["instance_id"] != instance:
            raise ConformanceError("source_instance_id_mismatch")
        if event["sequence"] != index:
            raise ConformanceError("source_memory_sequence_invalid")
        expected_previous = "GENESIS" if index == 0 else events[index - 1]["event_hash"]
        if event["previous_event_hash"] != expected_previous:
            raise ConformanceError("source_memory_chain_broken")
        if event["event_hash"] != compute_memory_event_hash(event):
            raise ConformanceError("source_memory_event_hash_mismatch")
        if event["event_id"] in event_ids:
            raise ConformanceError("source_memory_event_duplicate")
        event_ids.add(event["event_id"])
    by_event = {event["event_id"]: event for event in events}
    record_events = set()
    for record in records:
        exact_fields(record, RECORD_FIELDS, "accepted_record")
        if record["event_id"] not in by_event:
            raise ConformanceError("accepted_record_event_unknown")
        if record["event_id"] in record_events:
            raise ConformanceError("accepted_record_duplicate")
        record_events.add(record["event_id"])
        event = by_event[record["event_id"]]
        if record["content_digest"] != event["content_digest"]:
            raise ConformanceError("accepted_record_content_digest_mismatch")
        if not isinstance(record["gate_decision_ref"], str) or not record["gate_decision_ref"].startswith("gate_"):
            raise ConformanceError("accepted_record_gate_decision_invalid")
        tokens = normalize_terms(record["normalized_text"])
        if not tokens:
            raise ConformanceError("accepted_record_text_empty")
        if len(record["normalized_text"].encode("utf-8")) > 4096:
            raise ConformanceError("accepted_record_text_too_large")
        if record["record_id"] != compute_record_id(record):
            raise ConformanceError("accepted_record_id_mismatch")
    query_ids = set()
    for query in queries:
        if set(query) != {"query_id", "text", "top_k", "as_of_sequence", "anchor_event_refs"}:
            raise ConformanceError("retrieval_query_fields_invalid")
        if query["query_id"] in query_ids:
            raise ConformanceError("retrieval_query_duplicate")
        query_ids.add(query["query_id"])
        normalize_terms(query["text"])
        if not isinstance(query["anchor_event_refs"], list) or len(query["anchor_event_refs"]) != len(set(query["anchor_event_refs"])):
            raise ConformanceError("query_anchor_event_refs_invalid")
        if not set(query["anchor_event_refs"]).issubset(event_ids):
            raise ConformanceError("query_anchor_event_unknown_or_future")


def build_projection(document: dict) -> dict:
    validate_inputs(document)
    events = document["source_memory_events"]
    records_by_event = {item["event_id"]: item for item in document["accepted_records"]}
    frames = []
    for event in events:
        record = records_by_event[event["event_id"]]
        terms, token_count = term_frequencies(record["normalized_text"])
        frame_record = {
            "frame_id": "",
            "event_id": event["event_id"],
            "sequence": event["sequence"],
            "observed_at": event["observed_at"],
            "content_digest": event["content_digest"],
            "content_type": event["content_type"],
            "token_count": token_count,
            "terms": terms,
        }
        frame_record["frame_id"] = compute_frame_id(frame_record)
        frames.append(frame_record)
    lexicon_map: dict[str, list[str]] = {}
    for item in frames:
        for pair in item["terms"]:
            lexicon_map.setdefault(pair["term"], []).append(item["event_id"])
    lexicon = [
        {"term": term, "document_frequency": len(lexicon_map[term]), "event_refs": lexicon_map[term]}
        for term in utf8_sorted(list(lexicon_map))
    ]
    checkpoints = [
        {
            "sequence": item["sequence"],
            "frame_count": item["sequence"] + 1,
            "frames_digest": compute_checkpoint_digest(item["sequence"], frames),
        }
        for item in frames
    ]
    adjacency = build_adjacency(document.get("associative_projection", {}))
    query_results = [
        execute_query(query, frames, adjacency, events[-1]["sequence"])
        for query in document["queries"]
    ]
    projection = {
        "schema_version": "genesis.memory.retrieval.projection.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "projection_id": "",
        "instance_id": events[0]["instance_id"],
        "projection_profile": PROFILE,
        "coverage_status": "complete",
        "source_first_sequence": events[0]["sequence"],
        "source_last_sequence": events[-1]["sequence"],
        "source_event_count": len(events),
        "source_last_event_hash": events[-1]["event_hash"],
        "record_count": len(document["accepted_records"]),
        "frames": frames,
        "lexicon": lexicon,
        "checkpoints": checkpoints,
        "query_results": query_results,
        "projection_digest": "",
    }
    projection["projection_id"] = compute_projection_id(projection)
    projection["projection_digest"] = compute_projection_digest(projection)
    return projection


def validate_projection(document: dict) -> dict:
    expected = build_projection(document)
    projection = document.get("projection")
    if not isinstance(projection, dict):
        raise ConformanceError("retrieval_projection_missing")
    exact_fields(projection, PROJECTION_FIELDS, "retrieval_projection")
    if projection["projection_profile"] != PROFILE:
        raise ConformanceError("retrieval_projection_profile_invalid")
    for item in projection["frames"]:
        exact_fields(item, FRAME_FIELDS, "retrieval_frame")
        for pair in item["terms"]:
            exact_fields(pair, TERM_FIELDS, "retrieval_term")
            if not TOKEN_PATTERN.fullmatch(pair["term"]):
                raise ConformanceError("retrieval_term_invalid")
    for item in projection["lexicon"]:
        exact_fields(item, LEXICON_FIELDS, "retrieval_lexicon")
    for item in projection["checkpoints"]:
        exact_fields(item, CHECKPOINT_FIELDS, "retrieval_checkpoint")
    for item in projection["query_results"]:
        exact_fields(item, QUERY_RESULT_SET_FIELDS, "retrieval_query_result_set")
        for result in item["results"]:
            exact_fields(result, RESULT_FIELDS, "retrieval_query_result")
    scalar_fields = [
        "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
        "coverage_status", "source_first_sequence", "source_last_sequence", "source_event_count",
        "source_last_event_hash", "record_count"
    ]
    for field in scalar_fields:
        if projection[field] != expected[field]:
            raise ConformanceError(f"retrieval_projection_{field}_mismatch")
    if projection["frames"] != expected["frames"]:
        raise ConformanceError("retrieval_frames_mismatch")
    if projection["lexicon"] != expected["lexicon"]:
        raise ConformanceError("retrieval_lexicon_mismatch")
    if projection["checkpoints"] != expected["checkpoints"]:
        raise ConformanceError("retrieval_checkpoints_mismatch")
    if projection["query_results"] != expected["query_results"]:
        raise ConformanceError("retrieval_query_results_mismatch")
    if projection["projection_digest"] != compute_projection_digest(projection):
        raise ConformanceError("retrieval_projection_digest_mismatch")
    return expected


def apply_mutation(document: dict, mutation: dict) -> None:
    operation = mutation["operation"]
    if operation in {"projection_add_field", "projection_set"}:
        document["projection"][mutation["field"]] = mutation["value"]
    elif operation in {"frame_add_field", "frame_set"}:
        document["projection"]["frames"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "lexicon_set":
        document["projection"]["lexicon"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "checkpoint_set":
        document["projection"]["checkpoints"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif operation == "query_result_set":
        document["projection"]["query_results"][mutation["query_index"]]["results"][mutation["result_index"]][mutation["field"]] = mutation["value"]
    elif operation == "source_event_set":
        document["source_memory_events"][mutation["index"]][mutation["field"]] = mutation["value"]
        if mutation.get("recompute_event_hash"):
            document["source_memory_events"][mutation["index"]]["event_hash"] = compute_memory_event_hash(
                document["source_memory_events"][mutation["index"]]
            )
    elif operation == "record_set":
        document["accepted_records"][mutation["index"]][mutation["field"]] = mutation["value"]
        if mutation.get("recompute_record_id"):
            document["accepted_records"][mutation["index"]]["record_id"] = compute_record_id(
                document["accepted_records"][mutation["index"]]
            )
    elif operation == "record_duplicate":
        document["accepted_records"].append(deepcopy(document["accepted_records"][mutation["index"]]))
    elif operation == "query_set":
        document["queries"][mutation["index"]][mutation["field"]] = mutation["value"]
    else:
        raise AssertionError(f"unknown mutation: {operation}")


def validate_negative_cases(document: dict) -> int:
    count = 0
    for case in document.get("must_reject", []):
        mutated = deepcopy(document)
        apply_mutation(mutated, case["mutation"])
        try:
            validate_projection(mutated)
        except ConformanceError as error:
            if str(error) != case["expected_error"]:
                raise AssertionError(
                    f"{case['case_id']}: expected {case['expected_error']}, got {error}"
                ) from error
            count += 1
            continue
        raise AssertionError(f"{case['case_id']}: mutation accepted")
    return count


def main() -> int:
    vector_path = Path(sys.argv[1]) if len(sys.argv) > 1 else VECTORS
    document = json.loads(vector_path.read_text(encoding="utf-8"))
    expected = validate_projection(document)
    rejected = validate_negative_cases(document)
    print(f"OK deterministic retrieval projection ({len(expected['frames'])} frames, {len(expected['lexicon'])} terms)")
    print(f"OK lexical, graph-aware and temporal queries ({len(expected['query_results'])})")
    print(f"OK replay checkpoints ({len(expected['checkpoints'])})")
    print(f"OK retrieval boundary rejection cases ({rejected})")
    print("NOTE Retrieval remains a rebuildable read model; append-only memory remains authoritative.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

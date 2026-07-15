#!/usr/bin/env python3
"""Validate neutral hybrid retrieval without granting memory or authority."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

from validate_memory_retrieval import (
    ConformanceError as BaseConformanceError,
    DOMAINS as BASE_DOMAINS,
    build_projection as build_base_projection,
    normalize_terms,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "hybrid_memory_retrieval_vectors.json"
PROFILE = "genesis.memory.hybrid_retrieval.conformance.v0.1"
ALGORITHM = "genesis.memory.hybrid_retrieval.algorithm.v0.1"
SCHEMA = "genesis.memory.hybrid_retrieval.projection.v0.1"
HASH_PROFILE = "genesis.hash.fields.v0.1"
SEMANTIC_PROFILE_SCHEMA = "genesis.memory.semantic.profile.v0.1"
SEMANTIC_ADAPTER = "genesis.memory.semantic.simplex_u16.v0.1"
SEMANTIC_SIMILARITY = "genesis.memory.semantic.dot_product.v0.1"
DOMAINS = {
    "semantic_profile": "genesis.memory.semantic.profile.v0.1",
    "semantic_frame": "genesis.memory.semantic.frame.v0.1",
    "semantic_query_text": "genesis.memory.semantic.query.text.v0.1",
    "semantic_query": "genesis.memory.semantic.query.v0.1",
    "hybrid_query": "genesis.memory.hybrid_retrieval.query.v0.1",
    "hybrid_result": "genesis.memory.hybrid_retrieval.query.result.v0.1",
    "hybrid_projection_id": "genesis.memory.hybrid_retrieval.projection.id.v0.1",
    "hybrid_projection": "genesis.memory.hybrid_retrieval.projection.v0.1",
}
PROFILE_FIELDS = {
    "schema_version", "hash_profile", "adapter_profile", "model_digest", "dimensions",
    "vector_scale", "similarity_profile", "profile_digest",
}
SEMANTIC_FRAME_FIELDS = {"event_id", "content_digest", "vector", "vector_digest"}
SEMANTIC_QUERY_FIELDS = {"query_id", "query_text_digest", "vector", "vector_digest"}
PROJECTION_FIELDS = {
    "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
    "base_projection_digest", "semantic_profile_digest", "semantic_coverage_status",
    "source_event_count", "source_last_sequence", "semantic_frame_count", "semantic_frames",
    "query_results", "projection_digest",
}
SEMANTIC_REF_FIELDS = {"event_id", "vector_digest"}
QUERY_RESULT_FIELDS = {
    "query_id", "base_query_digest", "semantic_query_digest", "hybrid_query_digest", "mode",
    "normalized_terms", "as_of_sequence", "top_k", "candidate_count", "results", "result_digest",
}
RESULT_FIELDS = {
    "rank", "event_id", "frame_id", "sequence", "score", "lexical_score", "semantic_score",
    "graph_score", "temporal_score", "matched_terms", "reason_codes",
}
IDENTITY_AUTHORITY_FIELDS = {
    "companion_name", "guardian_id", "seed_id", "seed_root_hash", "identity_digest",
    "active_writer", "authority_epoch", "write_memory",
}
RAW_PLATFORM_FIELDS = {
    "raw_content", "payload", "embedding", "absolute_path", "platform_handle",
    "platform_account", "vendor", "token", "credential", "normalized_text",
}


class HybridConformanceError(ValueError):
    """Stable hybrid retrieval error."""


def utf8_sorted(values: list[str] | set[str]) -> list[str]:
    return sorted(values, key=lambda value: value.encode("utf-8"))


def frame(value: str) -> bytes:
    if not isinstance(value, str):
        raise HybridConformanceError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise HybridConformanceError("text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def hash_fields(domain: str, fields: list[object], prefix: str = "sha256:") -> str:
    preimage = frame(domain) + b"".join(frame(str(value)) for value in fields)
    return prefix + hashlib.sha256(preimage).hexdigest()


def exact_fields(value: object, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise HybridConformanceError(f"{label}_invalid")
    actual = set(value)
    extra = actual - expected
    if extra & IDENTITY_AUTHORITY_FIELDS:
        raise HybridConformanceError("hybrid_contains_identity_authority")
    if extra & RAW_PLATFORM_FIELDS:
        raise HybridConformanceError("hybrid_contains_raw_or_platform_data")
    if actual != expected:
        raise HybridConformanceError(f"{label}_fields_invalid")


def semantic_profile_digest(profile: dict) -> str:
    return hash_fields(DOMAINS["semantic_profile"], [
        profile["schema_version"], profile["hash_profile"], profile["adapter_profile"],
        profile["model_digest"], profile["dimensions"], profile["vector_scale"],
        profile["similarity_profile"],
    ])


def semantic_frame_digest(profile_digest: str, item: dict) -> str:
    return hash_fields(DOMAINS["semantic_frame"], [
        profile_digest, item["event_id"], item["content_digest"], len(item["vector"]),
        *item["vector"],
    ], "sfsha256:")


def semantic_text_digest(text: str) -> str:
    return hash_fields(DOMAINS["semantic_query_text"], [text])


def semantic_query_digest(profile_digest: str, item: dict) -> str:
    return hash_fields(DOMAINS["semantic_query"], [
        profile_digest, item["query_id"], item["query_text_digest"], len(item["vector"]),
        *item["vector"],
    ], "sqsha256:")


def validate_vector(vector: object, profile: dict) -> None:
    if not isinstance(vector, list) or len(vector) != profile["dimensions"]:
        raise HybridConformanceError("semantic_vector_dimensions_invalid")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > profile["vector_scale"] for value in vector):
        raise HybridConformanceError("semantic_vector_component_invalid")
    if sum(vector) != profile["vector_scale"]:
        raise HybridConformanceError("semantic_vector_scale_mismatch")


def validate_semantic_layer(document: dict, base_projection: dict) -> tuple[dict | None, dict, dict]:
    profile = document.get("semantic_profile")
    frames = document.get("semantic_frames")
    queries = document.get("semantic_queries")
    if not isinstance(frames, list) or not isinstance(queries, list):
        raise HybridConformanceError("semantic_collections_invalid")
    if profile is None:
        if frames or queries:
            raise HybridConformanceError("semantic_disabled_data_forbidden")
        return None, {}, {}
    exact_fields(profile, PROFILE_FIELDS, "semantic_profile")
    if profile["schema_version"] != SEMANTIC_PROFILE_SCHEMA or profile["hash_profile"] != HASH_PROFILE:
        raise HybridConformanceError("semantic_profile_version_invalid")
    if profile["adapter_profile"] != SEMANTIC_ADAPTER:
        raise HybridConformanceError("semantic_adapter_profile_invalid")
    if profile["similarity_profile"] != SEMANTIC_SIMILARITY:
        raise HybridConformanceError("semantic_similarity_profile_invalid")
    if not isinstance(profile["dimensions"], int) or isinstance(profile["dimensions"], bool) or not 2 <= profile["dimensions"] <= 1024:
        raise HybridConformanceError("semantic_dimensions_invalid")
    if not isinstance(profile["vector_scale"], int) or isinstance(profile["vector_scale"], bool) or not 1 <= profile["vector_scale"] <= 32767:
        raise HybridConformanceError("semantic_vector_scale_invalid")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", profile["model_digest"]):
        raise HybridConformanceError("semantic_model_digest_invalid")
    if profile["profile_digest"] != semantic_profile_digest(profile):
        raise HybridConformanceError("semantic_profile_digest_mismatch")
    events = {event["event_id"]: event for event in document["source_memory_events"]}
    frame_map: dict[str, dict] = {}
    for item in frames:
        exact_fields(item, SEMANTIC_FRAME_FIELDS, "semantic_frame")
        event = events.get(item["event_id"])
        if event is None:
            raise HybridConformanceError("semantic_frame_event_unknown")
        if item["event_id"] in frame_map:
            raise HybridConformanceError("semantic_frame_duplicate")
        if item["content_digest"] != event["content_digest"]:
            raise HybridConformanceError("semantic_frame_content_digest_mismatch")
        validate_vector(item["vector"], profile)
        if item["vector_digest"] != semantic_frame_digest(profile["profile_digest"], item):
            raise HybridConformanceError("semantic_frame_digest_mismatch")
        frame_map[item["event_id"]] = item
    if len(frame_map) != len(events):
        raise HybridConformanceError("semantic_frame_coverage_invalid")
    base_queries = {query["query_id"]: query for query in document["queries"]}
    query_map: dict[str, dict] = {}
    for item in queries:
        exact_fields(item, SEMANTIC_QUERY_FIELDS, "semantic_query")
        query = base_queries.get(item["query_id"])
        if query is None:
            raise HybridConformanceError("semantic_query_unknown")
        if item["query_id"] in query_map:
            raise HybridConformanceError("semantic_query_duplicate")
        if item["query_text_digest"] != semantic_text_digest(query["text"]):
            raise HybridConformanceError("semantic_query_text_digest_mismatch")
        validate_vector(item["vector"], profile)
        if item["vector_digest"] != semantic_query_digest(profile["profile_digest"], item):
            raise HybridConformanceError("semantic_query_digest_mismatch")
        query_map[item["query_id"]] = item
    if len(base_projection["frames"]) != len(frame_map):
        raise HybridConformanceError("semantic_frame_coverage_invalid")
    return profile, frame_map, query_map


def build_adjacency(associative: dict) -> dict[str, set[str]]:
    nodes = associative.get("nodes", []) if isinstance(associative, dict) else []
    edges = associative.get("edges", []) if isinstance(associative, dict) else []
    refs = {node.get("node_id"): set(node.get("source_event_refs", [])) for node in nodes if isinstance(node, dict)}
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        for left in refs.get(edge.get("source_node_id"), set()):
            for right in refs.get(edge.get("target_node_id"), set()):
                if left == right:
                    continue
                adjacency.setdefault(left, set()).add(right)
                adjacency.setdefault(right, set()).add(left)
    return adjacency


def lexical_evidence(query: dict, candidates: list[dict]) -> tuple[list[str], dict[str, tuple[int, list[str]]]]:
    normalized = utf8_sorted(set(normalize_terms(query["text"])))
    document_frequency = {
        term: sum(any(pair["term"] == term for pair in item["terms"]) for item in candidates)
        for term in normalized
    }
    scores: dict[str, tuple[int, list[str]]] = {}
    for item in candidates:
        frequencies = {pair["term"]: pair["frequency"] for pair in item["terms"]}
        matched = [term for term in normalized if term in frequencies]
        lexical = 0
        for term in matched:
            rarity = ((len(candidates) + 1) * 100000) // (document_frequency[term] + 1)
            tf_weight = (frequencies[term] * 1000) // (frequencies[term] + 1)
            lexical += (rarity * tf_weight) // 1000
        scores[item["event_id"]] = lexical, matched
    return normalized, scores


def compute_hybrid_result_digest(result_set: dict) -> str:
    flattened: list[object] = []
    for result in result_set["results"]:
        flattened.extend([
            result["rank"], result["event_id"], result["frame_id"], result["sequence"], result["score"],
            result["lexical_score"], result["semantic_score"], result["graph_score"], result["temporal_score"],
            len(result["matched_terms"]), *result["matched_terms"], len(result["reason_codes"]),
            *result["reason_codes"],
        ])
    return hash_fields(DOMAINS["hybrid_result"], [
        result_set["hybrid_query_digest"], result_set["candidate_count"], len(result_set["results"]),
        *flattened,
    ])


def execute_hybrid_query(query: dict, base_result: dict, base_projection: dict, semantic: tuple, adjacency: dict) -> dict:
    profile, frame_map, query_map = semantic
    candidates = [item for item in base_projection["frames"] if item["sequence"] <= query["as_of_sequence"]]
    normalized, scores = lexical_evidence(query, candidates)
    if normalized != base_result["normalized_terms"]:
        raise HybridConformanceError("hybrid_base_query_terms_mismatch")
    anchors = set(query.get("anchor_event_refs", []))
    semantic_query = query_map.get(query["query_id"])
    mode = "hybrid" if semantic_query else "lexical_fallback"
    scale_squared = profile["vector_scale"] ** 2 if profile else 1
    scored = []
    for item in candidates:
        lexical, matched = scores[item["event_id"]]
        semantic_score = 0
        if semantic_query:
            vector = frame_map[item["event_id"]]["vector"]
            dot = sum(left * right for left, right in zip(semantic_query["vector"], vector))
            semantic_score = (dot * 100000) // scale_squared
        graph_score = 0
        graph_reason = None
        if item["event_id"] in anchors:
            graph_score = 300000
            graph_reason = "graph_anchor"
        elif any(item["event_id"] in adjacency.get(anchor, set()) for anchor in anchors):
            graph_score = 180000
            graph_reason = "graph_neighbor"
        temporal_score = ((item["sequence"] + 1) * 100000) // (query["as_of_sequence"] + 1)
        if lexical == 0 and semantic_score == 0 and graph_score == 0:
            continue
        reasons = []
        if lexical:
            reasons.append("lexical_match")
        if semantic_score:
            reasons.append("semantic_match")
        if graph_reason:
            reasons.append(graph_reason)
        scored.append({
            "event_id": item["event_id"],
            "frame_id": item["frame_id"],
            "sequence": item["sequence"],
            "score": lexical * 7 + semantic_score * 6 + graph_score * 2 + temporal_score,
            "lexical_score": lexical,
            "semantic_score": semantic_score,
            "graph_score": graph_score,
            "temporal_score": temporal_score,
            "matched_terms": matched,
            "reason_codes": reasons,
        })
    scored.sort(key=lambda item: (-item["score"], -item["sequence"], item["event_id"].encode("utf-8")))
    semantic_digest = semantic_query["vector_digest"] if semantic_query else None
    hybrid_query_digest = hash_fields(DOMAINS["hybrid_query"], [
        base_result["query_digest"], semantic_digest or "", mode,
    ], "hqsha256:")
    result_set = {
        "query_id": query["query_id"],
        "base_query_digest": base_result["query_digest"],
        "semantic_query_digest": semantic_digest,
        "hybrid_query_digest": hybrid_query_digest,
        "mode": mode,
        "normalized_terms": normalized,
        "as_of_sequence": query["as_of_sequence"],
        "top_k": query["top_k"],
        "candidate_count": len(candidates),
        "results": [{"rank": index + 1, **item} for index, item in enumerate(scored[:query["top_k"]])],
        "result_digest": "",
    }
    result_set["result_digest"] = compute_hybrid_result_digest(result_set)
    return result_set


def compute_projection_id(projection: dict) -> str:
    return hash_fields(DOMAINS["hybrid_projection_id"], [
        projection["schema_version"], projection["instance_id"], projection["projection_profile"],
        projection["base_projection_digest"], projection["semantic_profile_digest"] or "",
        projection["semantic_coverage_status"], projection["source_event_count"],
        projection["source_last_sequence"], projection["semantic_frame_count"],
    ], "hrpsha256:")


def compute_projection_digest(projection: dict) -> str:
    semantic_flat: list[object] = []
    for item in projection["semantic_frames"]:
        semantic_flat.extend([item["event_id"], item["vector_digest"]])
    return hash_fields(DOMAINS["hybrid_projection"], [
        projection["schema_version"], projection["hash_profile"], projection["projection_id"],
        projection["instance_id"], projection["projection_profile"], projection["base_projection_digest"],
        projection["semantic_profile_digest"] or "", projection["semantic_coverage_status"],
        projection["source_event_count"], projection["source_last_sequence"], projection["semantic_frame_count"],
        len(projection["semantic_frames"]), *semantic_flat, len(projection["query_results"]),
        *[item["result_digest"] for item in projection["query_results"]],
    ])


def base_document(document: dict) -> dict:
    return {
        "profile": "genesis.memory.retrieval.conformance.v0.1",
        "status": document.get("status", "runtime-derived"),
        "domains": BASE_DOMAINS,
        "source_memory_events": deepcopy(document["source_memory_events"]),
        "accepted_records": deepcopy(document["accepted_records"]),
        "associative_projection": deepcopy(document.get("associative_projection", {})),
        "queries": deepcopy(document["queries"]),
    }


def build_hybrid_projection(document: dict) -> dict:
    if document.get("profile") != PROFILE:
        raise HybridConformanceError("hybrid_conformance_profile_invalid")
    if document.get("domains") != DOMAINS:
        raise HybridConformanceError("hybrid_domains_invalid")
    if not isinstance(document.get("queries"), list) or not document["queries"]:
        raise HybridConformanceError("hybrid_queries_invalid")
    try:
        base_projection = build_base_projection(base_document(document))
    except BaseConformanceError as error:
        raise HybridConformanceError(str(error)) from error
    semantic = validate_semantic_layer(document, base_projection)
    base_results = {item["query_id"]: item for item in base_projection["query_results"]}
    adjacency = build_adjacency(document.get("associative_projection", {}))
    query_results = [
        execute_hybrid_query(query, base_results[query["query_id"]], base_projection, semantic, adjacency)
        for query in document["queries"]
    ]
    profile, _, _ = semantic
    semantic_refs = [
        {"event_id": item["event_id"], "vector_digest": item["vector_digest"]}
        for item in document["semantic_frames"]
    ] if profile else []
    projection = {
        "schema_version": SCHEMA,
        "hash_profile": HASH_PROFILE,
        "projection_id": "",
        "instance_id": base_projection["instance_id"],
        "projection_profile": ALGORITHM,
        "base_projection_digest": base_projection["projection_digest"],
        "semantic_profile_digest": profile["profile_digest"] if profile else None,
        "semantic_coverage_status": "complete" if profile else "disabled",
        "source_event_count": base_projection["source_event_count"],
        "source_last_sequence": base_projection["source_last_sequence"],
        "semantic_frame_count": len(semantic_refs),
        "semantic_frames": semantic_refs,
        "query_results": query_results,
        "projection_digest": "",
    }
    projection["projection_id"] = compute_projection_id(projection)
    projection["projection_digest"] = compute_projection_digest(projection)
    return projection


def validate_projection(document: dict) -> dict:
    expected = build_hybrid_projection(document)
    projection = document.get("projection")
    exact_fields(projection, PROJECTION_FIELDS, "hybrid_projection")
    if projection["projection_profile"] != ALGORITHM:
        raise HybridConformanceError("hybrid_projection_profile_invalid")
    for item in projection["semantic_frames"]:
        exact_fields(item, SEMANTIC_REF_FIELDS, "hybrid_semantic_ref")
    for item in projection["query_results"]:
        exact_fields(item, QUERY_RESULT_FIELDS, "hybrid_query_result_set")
        for result in item["results"]:
            exact_fields(result, RESULT_FIELDS, "hybrid_query_result")
    scalar_fields = [
        "schema_version", "hash_profile", "projection_id", "instance_id", "projection_profile",
        "base_projection_digest", "semantic_profile_digest", "semantic_coverage_status",
        "source_event_count", "source_last_sequence", "semantic_frame_count",
    ]
    for field in scalar_fields:
        if projection[field] != expected[field]:
            raise HybridConformanceError(f"hybrid_projection_{field}_mismatch")
    if projection["semantic_frames"] != expected["semantic_frames"]:
        raise HybridConformanceError("hybrid_semantic_frames_mismatch")
    if projection["query_results"] != expected["query_results"]:
        raise HybridConformanceError("hybrid_query_results_mismatch")
    if projection["projection_digest"] != compute_projection_digest(projection):
        raise HybridConformanceError("hybrid_projection_digest_mismatch")
    return expected


def get_path(target: object, parts: list) -> object:
    cursor = target
    for part in parts:
        cursor = cursor[part]
    return cursor


def set_path(target: object, parts: list, value: object) -> None:
    cursor = target
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = value


def apply_mutation(document: dict, mutation: dict) -> None:
    operation = mutation["operation"]
    if operation == "set":
        set_path(document, mutation["path"], mutation["value"])
    elif operation == "delete":
        cursor = document
        for part in mutation["path"][:-1]:
            cursor = cursor[part]
        final = mutation["path"][-1]
        if isinstance(cursor, list):
            cursor.pop(int(final))
        else:
            del cursor[final]
    elif operation == "duplicate":
        get_path(document, mutation["target"]).append(deepcopy(get_path(document, mutation["path"])))
    elif operation == "append":
        get_path(document, mutation["path"]).append(deepcopy(mutation["value"]))
    else:
        raise ValueError(f"unknown_hybrid_mutation:{operation}")
    index = mutation.get("recompute_event_hash_index")
    if isinstance(index, int) and not isinstance(index, bool):
        event = document["source_memory_events"][index]
        event["event_hash"] = hash_fields(BASE_DOMAINS["memory_event"], [
            event["schema_version"], event["event_id"], event["instance_id"], event["body_id"],
            event["sequence"], event["previous_event_hash"], event["event_type"], event["actor"],
            event["content_digest"], event["content_type"], event["observed_at"],
            event["provenance_digest"], event["privacy"],
        ], "evsha256:")


def validate_negative_cases(document: dict) -> int:
    count = 0
    for test_case in document.get("must_reject", []):
        mutated = deepcopy(document)
        apply_mutation(mutated, test_case["mutation"])
        try:
            validate_projection(mutated)
        except HybridConformanceError as error:
            if str(error) != test_case["expected_error"]:
                raise AssertionError(
                    f"{test_case['case_id']}: expected {test_case['expected_error']}, got {error}"
                ) from error
            count += 1
            continue
        raise AssertionError(f"{test_case['case_id']}: mutation accepted")
    return count


def validate_conformance(document: dict) -> tuple[dict, dict, int]:
    projection = validate_projection(document)
    expected = document.get("expected", {})
    if projection["projection_digest"] != expected.get("projection_digest"):
        raise HybridConformanceError("hybrid_expected_projection_digest_mismatch")
    result_digests = {item["query_id"]: item["result_digest"] for item in projection["query_results"]}
    if result_digests != expected.get("query_result_digests"):
        raise HybridConformanceError("hybrid_expected_query_digests_mismatch")
    fallback_document = deepcopy(document)
    fallback_document["semantic_profile"] = None
    fallback_document["semantic_frames"] = []
    fallback_document["semantic_queries"] = []
    fallback_document.pop("projection", None)
    fallback_document.pop("expected", None)
    fallback_document.pop("must_reject", None)
    fallback = build_hybrid_projection(fallback_document)
    if fallback["projection_digest"] != expected.get("fallback_projection_digest"):
        raise HybridConformanceError("hybrid_expected_fallback_digest_mismatch")
    if any(
        item["mode"] != "lexical_fallback" or any(result["semantic_score"] != 0 for result in item["results"])
        for item in fallback["query_results"]
    ):
        raise HybridConformanceError("hybrid_fallback_behavior_invalid")
    return projection, fallback, validate_negative_cases(document)


def main() -> int:
    vector_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_VECTOR
    document = json.loads(vector_path.read_text(encoding="utf-8"))
    projection, fallback, rejected = validate_conformance(document)
    print(f"OK neutral hybrid retrieval ({len(projection['query_results'])} queries)")
    print(f"OK hybrid projection {projection['projection_digest']}")
    print(f"OK lexical fallback {fallback['projection_digest']}")
    print(f"OK hybrid boundary rejection cases ({rejected})")
    print("NOTE Semantic evidence is optional and derived; append-only memory remains authoritative.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

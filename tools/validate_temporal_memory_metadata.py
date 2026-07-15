#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "conformance" / "temporal_memory_metadata_vectors.json"

CANONICAL_TIME = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
MENTION_KINDS = {"instant", "interval", "none"}
PRECISIONS = {"second", "day", "month", "unknown"}
RELATIONS = {"before", "after", "during", "overlaps", "same_time", "none"}
SOURCE_KINDS = {"explicit_text", "relative_text", "guardian_confirmed", "no_temporal_claim"}
QUERY_TYPES = {"captured_between", "stored_between", "mentioned_between", "before_event", "after_event", "active_at"}
AUTHORITY_FIELDS = {"active_writer", "write_memory", "authority_grant", "guardian_key", "seed_root_hash"}

class TemporalError(Exception):
    pass

def frame(value: str) -> bytes:
    if not isinstance(value, str) or value != value.encode("utf-8").decode("utf-8") or value != __import__("unicodedata").normalize("NFC", value):
        raise TemporalError("temporal_text_invalid")
    data = value.encode("utf-8")
    return str(len(data)).encode("ascii") + b":" + data + b"\n"

def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    digest = hashlib.sha256(b"".join([frame(domain), *[frame(v) for v in fields]])).hexdigest()
    return prefix + digest

def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not CANONICAL_TIME.fullmatch(value):
        raise TemporalError("temporal_timestamp_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TemporalError("temporal_timestamp_invalid") from exc

def nullable(value) -> str:
    return "" if value is None else str(value)

def exact_fields(obj, expected: set[str], label: str):
    if not isinstance(obj, dict):
        raise TemporalError(f"{label}_invalid")
    if any(key in AUTHORITY_FIELDS for key in obj):
        raise TemporalError("temporal_contains_authority")
    if set(obj) != expected:
        raise TemporalError(f"{label}_fields_invalid")

def sorted_utf8(values):
    return sorted(values, key=lambda x: x.encode("utf-8"))

def compute_annotation_digest(annotation: dict) -> str:
    return hash_fields("genesis.memory.temporal.annotation.v0.1", [
        annotation["event_id"],
        annotation["content_digest"],
        annotation["capture_time"],
        annotation["storage_time"],
        annotation["mention_kind"],
        nullable(annotation["mentioned_start"]),
        nullable(annotation["mentioned_end"]),
        annotation["precision"],
        annotation["relation"],
        nullable(annotation["related_event_ref"]),
        annotation["source_kind"],
        str(annotation["confidence_milli"]),
        annotation["extractor_digest"],
        annotation["evidence_digest"],
    ], "tmsha256:")

def compute_access_digest(decision: dict) -> str:
    refs = sorted_utf8(decision["allowed_event_refs"])
    return hash_fields("genesis.memory.temporal.access.v0.1", [
        decision["decision_id"],
        str(decision["as_of_sequence"]),
        str(len(refs)),
        *refs,
    ], "tasha256:")

def compute_query_result_digest(result: dict) -> str:
    denial_flat = []
    for key in sorted_utf8(result["denial_counts"].keys()):
        denial_flat.extend([key, str(result["denial_counts"][key])])
    return hash_fields("genesis.memory.temporal.query.result.v0.1", [
        result["query_id"],
        result["access_decision_ref"],
        result["query_type"],
        str(result["as_of_sequence"]),
        str(result["candidate_count"]),
        str(len(result["matched_event_refs"])),
        *result["matched_event_refs"],
        str(len(denial_flat) // 2),
        *denial_flat,
    ])

def compute_projection_id(document: dict) -> str:
    return hash_fields("genesis.memory.temporal.projection.id.v0.1", [
        document["instance_id"],
        document["extraction_profile"],
        str(len(document["events"])),
        str(document["events"][-1]["sequence"]),
    ], "tpsha256:")

def compute_projection_digest(projection: dict) -> str:
    fields = [
        projection["schema_version"],
        projection["hash_profile"],
        projection["projection_id"],
        projection["instance_id"],
        projection["extraction_profile"],
        str(projection["source_event_count"]),
        str(projection["source_last_sequence"]),
        str(projection["annotation_count"]),
    ]
    for annotation in projection["annotations"]:
        fields.extend([
            annotation["event_id"], annotation["annotation_digest"],
            annotation["mention_kind"], nullable(annotation["mentioned_start"]),
            nullable(annotation["mentioned_end"]), annotation["relation"],
            nullable(annotation["related_event_ref"]),
        ])
    fields.append(str(len(projection["query_results"])))
    for result in projection["query_results"]:
        fields.extend([result["query_id"], result["result_digest"]])
    return hash_fields("genesis.memory.temporal.projection.v0.1", fields)

def range_for(annotation: dict):
    if annotation["mention_kind"] == "none":
        return None
    return (parse_time(annotation["mentioned_start"]), parse_time(annotation["mentioned_end"]))

def validate_document(document: dict):
    exact_fields(document, {"profile", "status", "instance_id", "extraction_profile", "events", "accepted_records", "annotations", "access_decisions", "queries", "expected", "must_reject"}, "temporal_document")
    if document.get("profile") != "genesis.memory.temporal_metadata.conformance.v0.1":
        raise TemporalError("temporal_profile_invalid")
    if document.get("status") != "draft":
        raise TemporalError("temporal_status_invalid")
    if not isinstance(document.get("instance_id"), str) or not document["instance_id"]:
        raise TemporalError("temporal_instance_invalid")
    if document.get("extraction_profile") != "genesis.memory.temporal.explicit_adapter.v0.1":
        raise TemporalError("temporal_extraction_profile_invalid")
    events = document.get("events")
    if not isinstance(events, list) or not events:
        raise TemporalError("temporal_events_invalid")
    event_ids = set()
    for index, event in enumerate(events):
        exact_fields(event, {"event_id", "sequence", "content_digest", "observed_at"}, "temporal_event")
        if event["sequence"] != index:
            raise TemporalError("temporal_event_sequence_invalid")
        if event["event_id"] in event_ids:
            raise TemporalError("temporal_event_duplicate")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", event["content_digest"]):
            raise TemporalError("temporal_content_digest_invalid")
        parse_time(event["observed_at"])
        event_ids.add(event["event_id"])

    records = document.get("accepted_records")
    if not isinstance(records, list) or len(records) != len(events):
        raise TemporalError("temporal_record_coverage_invalid")
    record_map = {}
    for record in records:
        exact_fields(record, {"event_id", "content_digest", "accepted_at", "text_digest"}, "temporal_record")
        if record["event_id"] not in event_ids:
            raise TemporalError("temporal_record_event_unknown")
        if record["event_id"] in record_map:
            raise TemporalError("temporal_record_duplicate")
        event = events[next(i for i, item in enumerate(events) if item["event_id"] == record["event_id"])]
        if record["content_digest"] != event["content_digest"]:
            raise TemporalError("temporal_record_content_mismatch")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", record["text_digest"]):
            raise TemporalError("temporal_text_digest_invalid")
        if parse_time(record["accepted_at"]) < parse_time(event["observed_at"]):
            raise TemporalError("temporal_storage_before_capture")
        record_map[record["event_id"]] = record

    annotations = document.get("annotations")
    if not isinstance(annotations, list):
        raise TemporalError("temporal_annotations_invalid")
    annotation_map = {}
    fields = {
        "event_id", "content_digest", "capture_time", "storage_time", "mention_kind",
        "mentioned_start", "mentioned_end", "precision", "relation", "related_event_ref",
        "source_kind", "confidence_milli", "extractor_digest", "evidence_digest", "annotation_digest"
    }
    for annotation in annotations:
        exact_fields(annotation, fields, "temporal_annotation")
        event_id = annotation["event_id"]
        if event_id not in event_ids:
            raise TemporalError("temporal_annotation_event_unknown")
        if event_id in annotation_map:
            raise TemporalError("temporal_annotation_duplicate")
        event = events[next(i for i, item in enumerate(events) if item["event_id"] == event_id)]
        record = record_map[event_id]
        if annotation["content_digest"] != event["content_digest"]:
            raise TemporalError("temporal_annotation_content_mismatch")
        if annotation["capture_time"] != event["observed_at"]:
            raise TemporalError("temporal_capture_time_mismatch")
        if annotation["storage_time"] != record["accepted_at"]:
            raise TemporalError("temporal_storage_time_mismatch")
        if annotation["mention_kind"] not in MENTION_KINDS:
            raise TemporalError("temporal_mention_kind_invalid")
        if annotation["precision"] not in PRECISIONS:
            raise TemporalError("temporal_precision_invalid")
        if annotation["relation"] not in RELATIONS:
            raise TemporalError("temporal_relation_invalid")
        if annotation["source_kind"] not in SOURCE_KINDS:
            raise TemporalError("temporal_source_kind_invalid")
        confidence = annotation["confidence_milli"]
        if not isinstance(confidence, int) or isinstance(confidence, bool) or not 0 <= confidence <= 1000:
            raise TemporalError("temporal_confidence_invalid")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", annotation["extractor_digest"]) or not re.fullmatch(r"sha256:[a-f0-9]{64}", annotation["evidence_digest"]):
            raise TemporalError("temporal_provenance_digest_invalid")
        if annotation["mention_kind"] == "none":
            if annotation["mentioned_start"] is not None or annotation["mentioned_end"] is not None:
                raise TemporalError("temporal_none_has_interval")
            if annotation["relation"] != "none" or annotation["related_event_ref"] is not None:
                raise TemporalError("temporal_none_has_relation")
            if annotation["precision"] != "unknown" or annotation["source_kind"] != "no_temporal_claim" or confidence != 0:
                raise TemporalError("temporal_none_metadata_invalid")
        else:
            start = parse_time(annotation["mentioned_start"])
            end = parse_time(annotation["mentioned_end"])
            if annotation["mention_kind"] == "instant" and start != end:
                raise TemporalError("temporal_instant_range_invalid")
            if annotation["mention_kind"] == "interval" and start >= end:
                raise TemporalError("temporal_interval_order_invalid")
            if annotation["source_kind"] == "no_temporal_claim":
                raise TemporalError("temporal_claim_source_invalid")
            if annotation["relation"] == "none" and annotation["related_event_ref"] is not None:
                raise TemporalError("temporal_relation_ref_unexpected")
            if annotation["relation"] != "none":
                if annotation["related_event_ref"] is None:
                    raise TemporalError("temporal_relation_ref_missing")
                if annotation["related_event_ref"] not in event_ids:
                    raise TemporalError("temporal_relation_target_unknown")
                if annotation["related_event_ref"] == event_id:
                    raise TemporalError("temporal_relation_self")
        if annotation["annotation_digest"] != compute_annotation_digest(annotation):
            raise TemporalError("temporal_annotation_digest_mismatch")
        annotation_map[event_id] = annotation

    if len(annotation_map) != len(events):
        raise TemporalError("temporal_annotation_coverage_invalid")

    for annotation in annotations:
        if annotation["relation"] == "none":
            continue
        source_range = range_for(annotation)
        target = annotation_map[annotation["related_event_ref"]]
        target_range = range_for(target)
        if source_range is None or target_range is None:
            raise TemporalError("temporal_relation_range_missing")
        s0, s1 = source_range
        t0, t1 = target_range
        relation = annotation["relation"]
        valid = {
            "before": s1 <= t0,
            "after": s0 >= t1,
            "during": s0 >= t0 and s1 <= t1,
            "overlaps": s0 <= t1 and s1 >= t0 and not (s0 >= t0 and s1 <= t1) and not (t0 >= s0 and t1 <= s1),
            "same_time": s0 == t0 and s1 == t1,
        }[relation]
        if not valid:
            raise TemporalError("temporal_relation_contradiction")

    decisions = document.get("access_decisions")
    if not isinstance(decisions, list) or not decisions:
        raise TemporalError("temporal_access_decisions_invalid")
    decision_map = {}
    for decision in decisions:
        exact_fields(decision, {"decision_id", "as_of_sequence", "allowed_event_refs", "decision_digest"}, "temporal_access")
        if decision["decision_id"] in decision_map:
            raise TemporalError("temporal_access_duplicate")
        if not isinstance(decision["as_of_sequence"], int) or not 0 <= decision["as_of_sequence"] < len(events):
            raise TemporalError("temporal_access_sequence_invalid")
        refs = decision["allowed_event_refs"]
        if not isinstance(refs, list) or len(refs) != len(set(refs)) or any(ref not in event_ids for ref in refs):
            raise TemporalError("temporal_access_refs_invalid")
        if any(events[next(i for i, item in enumerate(events) if item["event_id"] == ref)]["sequence"] > decision["as_of_sequence"] for ref in refs):
            raise TemporalError("temporal_access_future_ref")
        if decision["decision_digest"] != compute_access_digest(decision):
            raise TemporalError("temporal_access_digest_mismatch")
        decision_map[decision["decision_id"]] = decision

    queries = document.get("queries")
    if not isinstance(queries, list) or not queries:
        raise TemporalError("temporal_queries_invalid")
    query_ids = set()
    query_fields = {"query_id", "access_decision_ref", "query_type", "start", "end", "at", "anchor_event_ref", "expected_event_refs", "expected_denials", "expected_result_digest"}
    for query in queries:
        exact_fields(query, query_fields, "temporal_query")
        if query["query_id"] in query_ids:
            raise TemporalError("temporal_query_duplicate")
        if query["access_decision_ref"] not in decision_map:
            raise TemporalError("temporal_query_access_unknown")
        if query["query_type"] not in QUERY_TYPES:
            raise TemporalError("temporal_query_type_invalid")
        if query["start"] is not None:
            parse_time(query["start"])
        if query["end"] is not None:
            parse_time(query["end"])
        if query["at"] is not None:
            parse_time(query["at"])
        if query["start"] is not None and query["end"] is not None and parse_time(query["start"]) > parse_time(query["end"]):
            raise TemporalError("temporal_query_range_invalid")
        qtype = query["query_type"]
        if qtype in {"captured_between", "stored_between", "mentioned_between"}:
            if query["start"] is None or query["end"] is None or query["at"] is not None or query["anchor_event_ref"] is not None:
                raise TemporalError("temporal_query_shape_invalid")
        elif qtype == "active_at":
            if query["at"] is None or query["start"] is not None or query["end"] is not None or query["anchor_event_ref"] is not None:
                raise TemporalError("temporal_query_shape_invalid")
        else:
            if query["anchor_event_ref"] not in event_ids or query["start"] is not None or query["end"] is not None or query["at"] is not None:
                raise TemporalError("temporal_query_shape_invalid")
        if not isinstance(query["expected_event_refs"], list) or len(query["expected_event_refs"]) != len(set(query["expected_event_refs"])):
            raise TemporalError("temporal_query_expected_refs_invalid")
        if not isinstance(query["expected_denials"], dict):
            raise TemporalError("temporal_query_expected_denials_invalid")
        query_ids.add(query["query_id"])
    return {"events": events, "event_ids": event_ids, "record_map": record_map, "annotation_map": annotation_map, "decision_map": decision_map}

def temporal_match(query: dict, annotation: dict, anchor: dict | None) -> bool:
    qtype = query["query_type"]
    if qtype == "captured_between":
        value = parse_time(annotation["capture_time"])
        return parse_time(query["start"]) <= value <= parse_time(query["end"])
    if qtype == "stored_between":
        value = parse_time(annotation["storage_time"])
        return parse_time(query["start"]) <= value <= parse_time(query["end"])
    current = range_for(annotation)
    if current is None:
        return False
    start, end = current
    if qtype == "mentioned_between":
        return start <= parse_time(query["end"]) and end >= parse_time(query["start"])
    if qtype == "active_at":
        value = parse_time(query["at"])
        return start <= value <= end
    anchor_range = range_for(anchor)
    if anchor_range is None:
        raise TemporalError("temporal_anchor_range_missing")
    a0, a1 = anchor_range
    if qtype == "before_event":
        return annotation["event_id"] != anchor["event_id"] and end <= a0
    if qtype == "after_event":
        return annotation["event_id"] != anchor["event_id"] and start >= a1
    raise TemporalError("temporal_query_type_invalid")

def evaluate_query(document: dict, query: dict, state=None) -> dict:
    state = state or validate_document(document)
    decision = state["decision_map"][query["access_decision_ref"]]
    allowed = set(decision["allowed_event_refs"])
    anchor = None
    if query["anchor_event_ref"] is not None:
        if query["anchor_event_ref"] not in allowed:
            raise TemporalError("temporal_anchor_not_authorized")
        anchor_event = next(item for item in state["events"] if item["event_id"] == query["anchor_event_ref"])
        if anchor_event["sequence"] > decision["as_of_sequence"]:
            raise TemporalError("temporal_anchor_future")
        anchor = state["annotation_map"][query["anchor_event_ref"]]
    matched = []
    denial = {}
    candidate_count = 0
    def deny(reason):
        denial[reason] = denial.get(reason, 0) + 1
    for event in state["events"]:
        if event["sequence"] > decision["as_of_sequence"]:
            deny("future_event")
            continue
        if event["event_id"] not in allowed:
            deny("acl_denied")
            continue
        candidate_count += 1
        annotation = state["annotation_map"][event["event_id"]]
        if temporal_match(query, annotation, anchor):
            matched.append(event["event_id"])
        else:
            deny("no_temporal_match")
    result = {
        "query_id": query["query_id"],
        "access_decision_ref": decision["decision_id"],
        "query_type": query["query_type"],
        "as_of_sequence": decision["as_of_sequence"],
        "candidate_count": candidate_count,
        "matched_event_refs": matched,
        "denial_counts": denial,
        "result_digest": "",
    }
    result["result_digest"] = compute_query_result_digest(result)
    return result

def build_projection(document: dict) -> dict:
    state = validate_document(document)
    results = [evaluate_query(document, query, state) for query in document["queries"]]
    annotations = [{
        "event_id": item["event_id"],
        "annotation_digest": item["annotation_digest"],
        "mention_kind": item["mention_kind"],
        "mentioned_start": item["mentioned_start"],
        "mentioned_end": item["mentioned_end"],
        "relation": item["relation"],
        "related_event_ref": item["related_event_ref"],
    } for item in document["annotations"]]
    projection = {
        "schema_version": "genesis.memory.temporal.projection.v0.1",
        "hash_profile": "genesis.hash.fields.v0.1",
        "projection_id": compute_projection_id(document),
        "instance_id": document["instance_id"],
        "extraction_profile": document["extraction_profile"],
        "source_event_count": len(document["events"]),
        "source_last_sequence": document["events"][-1]["sequence"],
        "annotation_count": len(annotations),
        "annotations": annotations,
        "query_results": results,
        "projection_digest": "",
    }
    projection["projection_digest"] = compute_projection_digest(projection)
    return projection

def apply_mutation(document: dict, mutation: dict):
    target = mutation["target"]
    if target == "event":
        document["events"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "record":
        document["accepted_records"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "annotation":
        document["annotations"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "annotation_rehash":
        annotation = document["annotations"][mutation["index"]]
        annotation[mutation["field"]] = mutation["value"]
        annotation["annotation_digest"] = compute_annotation_digest(annotation)
    elif target == "annotation_remove":
        document["annotations"].pop(mutation["index"])
    elif target == "annotation_duplicate":
        document["annotations"].append(copy.deepcopy(document["annotations"][mutation["index"]]))
    elif target == "access":
        document["access_decisions"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "access_rehash":
        decision = document["access_decisions"][mutation["index"]]
        decision[mutation["field"]] = mutation["value"]
        decision["decision_digest"] = compute_access_digest(decision)
    elif target == "query":
        document["queries"][mutation["index"]][mutation["field"]] = mutation["value"]
    elif target == "top":
        document[mutation["field"]] = mutation["value"]
    else:
        raise RuntimeError(f"unknown_mutation:{target}")

def validate_vector(document: dict):
    projection = build_projection(document)
    expected = document["expected"]
    if projection["projection_id"] != expected["projection_id"]:
        raise RuntimeError("temporal_expected_projection_id_mismatch")
    if projection["projection_digest"] != expected["projection_digest"]:
        raise RuntimeError("temporal_expected_projection_digest_mismatch")
    for query, actual in zip(document["queries"], projection["query_results"]):
        if actual["matched_event_refs"] != query["expected_event_refs"] or actual["denial_counts"] != query["expected_denials"] or actual["result_digest"] != query["expected_result_digest"]:
            raise RuntimeError(f"temporal_expected_query_mismatch:{query['query_id']}")
    rejected = 0
    for case in document.get("must_reject", []):
        mutated = copy.deepcopy(document)
        apply_mutation(mutated, case["mutation"])
        try:
            build_projection(mutated)
        except TemporalError as exc:
            if str(exc) != case["expected_error"]:
                raise RuntimeError(f"{case['case_id']}:expected:{case['expected_error']}:got:{exc}") from exc
            rejected += 1
            continue
        raise RuntimeError(f"{case['case_id']}:mutation_accepted")
    return projection, rejected

def atomic_write(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)

def main():
    args = sys.argv[1:]
    command = args[0] if args else "validate"
    input_path = Path(args[1]) if len(args) > 1 else DEFAULT_VECTOR
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if command == "validate":
        projection, rejected = validate_vector(document)
        print(f"OK temporal memory metadata ({len(projection['annotations'])} annotations, {len(projection['query_results'])} queries)")
        print(f"OK temporal projection {projection['projection_digest']}")
        print(f"OK temporal boundary rejection cases ({rejected})")
        print("NOTE temporal metadata is derived evidence and never rewrites canonical event timestamps.")
    elif command in {"build", "sync"}:
        if len(args) < 3:
            raise TemporalError("temporal_output_path_required")
        projection = build_projection(document)
        atomic_write(Path(args[2]), projection)
        print(projection["projection_digest"])
    elif command == "query":
        if len(args) < 3:
            raise TemporalError("temporal_query_id_required")
        state = validate_document(document)
        query = next((item for item in document["queries"] if item["query_id"] == args[2]), None)
        if query is None:
            raise TemporalError("temporal_query_not_found")
        print(json.dumps(evaluate_query(document, query, state), ensure_ascii=False, indent=2))
    else:
        raise TemporalError("temporal_command_invalid")

if __name__ == "__main__":
    try:
        main()
    except (TemporalError, RuntimeError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

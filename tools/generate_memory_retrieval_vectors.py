#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_memory_retrieval import (  # noqa: E402
    DOMAINS,
    build_projection,
    compute_memory_event_hash,
    compute_record_id,
)

EVENT_TEXTS = [
    (
        "sense.vision.observation",
        "body",
        "private_local",
        "Genesis observed the blue workshop door and registered the local environment.",
    ),
    (
        "guardian.transfer.authorized",
        "guardian",
        "guardian_shared",
        "The guardian authorized memory transfer from body alpha to body beta.",
    ),
    (
        "knowledge.requirement.recorded",
        "instance",
        "private_local",
        "Project Aurora needs a portable offline memory index with deterministic recovery.",
    ),
    (
        "knowledge.relation.confirmed",
        "guardian",
        "guardian_shared",
        "The associative graph connected Aurora memory with the transfer decision.",
    ),
    (
        "recovery.continuity.verified",
        "body",
        "private_local",
        "After recovery body gamma verified the Aurora index and preserved continuity.",
    ),
]


def repeated_hex(value: int) -> str:
    return f"{value:02x}" * 32


def build_document() -> dict:
    instance_id = "inst_01HRETRIEVAL00000000001"
    body_id = "body_01HRETRIEVAL00000000001"
    events = []
    records = []
    previous = "GENESIS"
    for sequence, (event_type, actor, privacy, text) in enumerate(EVENT_TEXTS):
        event_id = f"evt_01HRETRIEVAL0000000000{sequence + 1}"
        event = {
            "schema_version": "genesis.memory.event.v0.1",
            "hash_profile": "genesis.hash.fields.v0.1",
            "event_id": event_id,
            "instance_id": instance_id,
            "body_id": body_id,
            "sequence": sequence,
            "previous_event_hash": previous,
            "event_type": event_type,
            "actor": actor,
            "content_digest": f"sha256:{repeated_hex(0x11 + sequence)}",
            "content_type": "text/plain; charset=utf-8",
            "observed_at": f"2026-07-15T12:00:0{sequence}Z",
            "provenance_digest": f"sha256:{repeated_hex(0x71 + sequence)}",
            "privacy": privacy,
            "event_hash": "",
        }
        event["event_hash"] = compute_memory_event_hash(event)
        previous = event["event_hash"]
        events.append(event)
        record = {
            "record_id": "",
            "event_id": event_id,
            "gate_decision_ref": f"gate_01HRETRIEVAL0000000000{sequence + 1}",
            "content_digest": event["content_digest"],
            "normalized_text": text,
            "accepted_at": f"2026-07-15T12:00:1{sequence}Z",
        }
        record["record_id"] = compute_record_id(record)
        records.append(record)

    document = {
        "profile": "genesis.memory.retrieval.conformance.v0.1",
        "status": "draft",
        "domains": DOMAINS,
        "source_memory_events": events,
        "accepted_records": records,
        "associative_projection": {
            "nodes": [
                {"node_id": "node_aurora", "source_event_refs": [events[2]["event_id"]]},
                {"node_id": "node_relation", "source_event_refs": [events[3]["event_id"]]},
                {"node_id": "node_recovery", "source_event_refs": [events[4]["event_id"]]},
            ],
            "edges": [
                {"source_node_id": "node_aurora", "target_node_id": "node_relation"},
                {"source_node_id": "node_relation", "target_node_id": "node_recovery"},
            ],
        },
        "queries": [
            {"query_id": "query_aurora_memory", "text": "Aurora portable memory", "top_k": 3, "as_of_sequence": 4, "anchor_event_refs": []},
            {"query_id": "query_guardian_transfer", "text": "guardian transfer", "top_k": 3, "as_of_sequence": 2, "anchor_event_refs": []},
            {"query_id": "query_graph_neighbors", "text": "", "top_k": 3, "as_of_sequence": 4, "anchor_event_refs": [events[2]["event_id"]]},
            {"query_id": "query_replay_before_future", "text": "Aurora index", "top_k": 5, "as_of_sequence": 2, "anchor_event_refs": []},
        ],
    }
    document["projection"] = build_projection(document)
    document["must_reject"] = negative_cases(events)
    return document


def negative_cases(events: list[dict]) -> list[dict]:
    zero_sha = "sha256:" + "0" * 64
    zero_event = "evsha256:" + "2" * 64
    zero_frame = "rfsha256:" + "0" * 64
    return [
        case("retrieval-identity-authority-forbidden-001", "projection_add_field", "retrieval_contains_identity_authority", field="companion_name", value="Altered"),
        case("retrieval-raw-output-forbidden-001", "frame_add_field", "retrieval_contains_raw_or_platform_data", index=0, field="normalized_text", value="plaintext"),
        case("retrieval-embedding-forbidden-001", "frame_add_field", "retrieval_contains_raw_or_platform_data", index=0, field="embedding", value=[0.1]),
        case("retrieval-vendor-profile-forbidden-001", "projection_set", "retrieval_projection_profile_invalid", field="projection_profile", value="memvid-2.0.140"),
        case("retrieval-source-chain-broken-001", "source_event_set", "source_memory_chain_broken", index=1, field="previous_event_hash", value="evsha256:" + "1" * 64, recompute_event_hash=True),
        case("retrieval-source-hash-corrupt-001", "source_event_set", "source_memory_event_hash_mismatch", index=2, field="event_hash", value=zero_event),
        case("retrieval-source-instance-changed-001", "source_event_set", "source_instance_id_mismatch", index=2, field="instance_id", value="inst_other", recompute_event_hash=True),
        case("retrieval-record-unknown-event-001", "record_set", "accepted_record_event_unknown", index=0, field="event_id", value="evt_unknown", recompute_record_id=True),
        case("retrieval-record-digest-mismatch-001", "record_set", "accepted_record_content_digest_mismatch", index=0, field="content_digest", value="sha256:" + "f" * 64, recompute_record_id=True),
        case("retrieval-record-id-corrupt-001", "record_set", "accepted_record_id_mismatch", index=0, field="record_id", value="rrsha256:" + "0" * 64),
        case("retrieval-record-duplicate-001", "record_duplicate", "accepted_record_coverage_invalid", index=0),
        case("retrieval-record-non-nfc-001", "record_set", "retrieval_text_not_nfc", index=0, field="normalized_text", value="Cafe\u0301 memory"),
        case("retrieval-query-topk-invalid-001", "query_set", "query_top_k_invalid", index=0, field="top_k", value=0),
        case("retrieval-query-asof-invalid-001", "query_set", "query_as_of_sequence_invalid", index=0, field="as_of_sequence", value=99),
        case("retrieval-query-anchor-future-001", "query_set", "query_anchor_event_unknown_or_future", index=1, field="anchor_event_refs", value=[events[4]["event_id"]]),
        case("retrieval-frame-id-corrupt-001", "frame_set", "retrieval_frames_mismatch", index=0, field="frame_id", value=zero_frame),
        case("retrieval-frame-frequency-changed-001", "frame_set", "retrieval_frames_mismatch", index=0, field="token_count", value=999),
        case("retrieval-lexicon-df-changed-001", "lexicon_set", "retrieval_lexicon_mismatch", index=0, field="document_frequency", value=99),
        case("retrieval-checkpoint-changed-001", "checkpoint_set", "retrieval_checkpoints_mismatch", index=0, field="frames_digest", value=zero_sha),
        case("retrieval-query-ranking-changed-001", "query_result_set", "retrieval_query_results_mismatch", query_index=0, result_index=0, field="score", value=1),
        case("retrieval-query-future-leak-001", "query_result_set", "retrieval_query_results_mismatch", query_index=3, result_index=0, field="sequence", value=4),
        case("retrieval-projection-digest-corrupt-001", "projection_set", "retrieval_projection_digest_mismatch", field="projection_digest", value=zero_sha),
    ]


def case(case_id: str, operation: str, expected: str, **mutation) -> dict:
    return {
        "case_id": case_id,
        "mutation": {"operation": operation, **mutation},
        "expected_error": expected,
    }


def main() -> int:
    target = ROOT / "conformance" / "memory_retrieval_vectors.json"
    target.write_text(json.dumps(build_document(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

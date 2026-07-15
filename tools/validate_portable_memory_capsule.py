#!/usr/bin/env python3
from __future__ import annotations
import copy, json, pathlib, sys
from portable_capsule_common import CapsuleError, DEFAULT_VECTOR
from portable_capsule_builder import build_capsule
from portable_capsule_verify import verify_capsule

def apply_mutation(document, mutation):
    target, index = mutation["target"], mutation.get("index", 0)
    field, value = mutation.get("field"), mutation.get("value")
    if target in {"event", "event_add"}:
        document["source_events"][index][field] = value
    elif target == "event_duplicate":
        document["source_events"].append(copy.deepcopy(document["source_events"][index]))
    elif target == "acl":
        document["acl_decisions"][index][field] = value
    elif target == "acl_add_ref":
        document["acl_decisions"][index]["allowed_event_refs"].append(value)
    elif target == "request":
        document["export_requests"][index][field] = value
    elif target == "request_add_ref":
        document["export_requests"][index]["requested_event_refs"].append(value)
    elif target == "request_add_part":
        document["export_requests"][index]["include_parts"].append(value)
    elif target == "retrieval":
        document["derived_sources"]["retrieval"][field] = value
    elif target == "retrieval_record":
        document["derived_sources"]["retrieval"]["records"][index][field] = value
    elif target == "temporal":
        document["derived_sources"]["temporal"][field] = value
    elif target == "temporal_annotation":
        document["derived_sources"]["temporal"]["annotations"][index][field] = value
    else:
        raise RuntimeError(f"unknown mutation target:{target}")

def apply_capsule_mutation(capsule, mutation):
    target, index = mutation["target"], mutation.get("index", 0)
    if target == "capsule":
        capsule[mutation["field"]] = mutation["value"]
    elif target == "entry":
        capsule["entries"][index][mutation["field"]] = mutation["value"]
    elif target == "component":
        capsule["components"][index][mutation["field"]] = mutation["value"]
    elif target == "component_payload":
        capsule["components"][index]["payload"][mutation["field"]] = mutation["value"]
    elif target == "manifest":
        capsule["manifest"][mutation["field"]] = mutation["value"]
    elif target == "receipt":
        capsule["export_receipt"][mutation["field"]] = mutation["value"]
    else:
        raise RuntimeError(f"unknown capsule mutation target:{target}")

def validate_vector(document):
    capsules = [build_capsule(document, request["request_id"]) for request in document["export_requests"]]
    for request, capsule in zip(document["export_requests"], capsules):
        if capsule["capsule_digest"] != request["expected_capsule_digest"]:
            raise RuntimeError(f"capsule_expected_digest_mismatch:{request['request_id']}")
        if capsule["manifest"]["root_digest"] != request["expected_manifest_root"]:
            raise RuntimeError(f"capsule_expected_manifest_mismatch:{request['request_id']}")
    rejected = 0
    for test in document.get("must_reject", []):
        candidate = copy.deepcopy(document)
        apply_mutation(candidate, test["mutation"])
        try:
            build_capsule(candidate, candidate["export_requests"][0]["request_id"])
        except CapsuleError as error:
            if str(error) != test["expected_error"]:
                raise RuntimeError(f"{test['case_id']}:expected:{test['expected_error']}:got:{error}") from error
            rejected += 1
            continue
        raise RuntimeError(f"{test['case_id']}:mutation_accepted")
    tampered = 0
    for test in document.get("must_reject_capsule", []):
        candidate = copy.deepcopy(capsules[0])
        apply_capsule_mutation(candidate, test["mutation"])
        try:
            verify_capsule(candidate)
        except CapsuleError as error:
            if str(error) != test["expected_error"]:
                raise RuntimeError(f"{test['case_id']}:expected:{test['expected_error']}:got:{error}") from error
            tampered += 1
            continue
        raise RuntimeError(f"{test['case_id']}:tampered_capsule_accepted")
    return capsules, rejected, tampered

def main(argv):
    source = pathlib.Path(argv[0]).resolve() if argv else DEFAULT_VECTOR
    document = json.loads(source.read_text(encoding="utf-8"))
    capsules, rejected, tampered = validate_vector(document)
    print(f"OK portable memory capsules ({len(capsules)} exports)")
    print(f"OK capsule digest {capsules[0]['capsule_digest']}")
    print(f"OK source boundary rejection cases ({rejected})")
    print(f"OK capsule tamper rejection cases ({tampered})")
    print("NOTE capsules carry authorized subsets and never grant identity, write, or authority.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)

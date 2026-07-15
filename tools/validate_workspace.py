#!/usr/bin/env python3
"""Reference validator for the Genesis Ultra draft workspace.

This program is an auxiliary implementation, not the normative protocol.
It uses only the Python standard library so it can be run locally before a commit.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

WORKSPACE_MANIFEST = json.loads(
    (ROOT / "conformance" / "required_artifacts.json").read_text(encoding="utf-8")
)
REQUIRED_FILES = WORKSPACE_MANIFEST["required"]
FORBIDDEN_FILES = WORKSPACE_MANIFEST["forbidden"]
MARKDOWN_LINK = re.compile(r'\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)')


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def hash_fields(domain: str, fields: list[str], prefix: str = "sha256:") -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return prefix + hashlib.sha256(preimage).hexdigest()


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def safe_relative_path(value: str) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if unicodedata.normalize("NFC", value) != value:
        return False
    if value.startswith("/") or "\\" in value:
        return False
    if re.match(r"^[A-Za-z]:", value):
        return False
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        return False
    return True


def validate_workspace_hygiene() -> list[str]:
    failures: list[str] = []

    for label, paths in (("required", REQUIRED_FILES), ("forbidden", FORBIDDEN_FILES)):
        if len(paths) != len(set(paths)):
            failures.append(f"duplicate_{label}_workspace_path")
        for relative in paths:
            if not safe_relative_path(relative):
                failures.append(f"unsafe_{label}_workspace_path:{relative}")

    overlap = sorted(set(REQUIRED_FILES) & set(FORBIDDEN_FILES))
    for relative in overlap:
        failures.append(f"required_and_forbidden_workspace_path:{relative}")

    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"missing_file:{relative}")

    for relative in FORBIDDEN_FILES:
        if (ROOT / relative).exists():
            failures.append(f"forbidden_legacy_file:{relative}")

    if (ROOT / ".git").exists():
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            failures.append("tracked_file_inventory_unavailable")
        else:
            tracked = {
                entry.decode("utf-8")
                for entry in result.stdout.split(b"\0")
                if entry and (ROOT / entry.decode("utf-8")).is_file()
            }
            for relative in sorted(tracked - set(REQUIRED_FILES)):
                failures.append(f"unlisted_tracked_file:{relative}")

    root_resolved = ROOT.resolve()
    for markdown in ROOT.rglob("*.md"):
        if any(part in {".git", "node_modules"} for part in markdown.parts):
            continue
        content = markdown.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(content):
            target = match.group(1)
            if target.startswith("#") or re.match(r"^(?:https?|mailto):", target, re.IGNORECASE):
                continue
            local_target = unquote(target.split("#", 1)[0])
            if not local_target:
                continue
            resolved = (markdown.parent / local_target).resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                failures.append(
                    f"markdown_link_outside_workspace:{markdown.relative_to(ROOT)}:{target}"
                )
                continue
            if not resolved.exists():
                failures.append(f"broken_markdown_link:{markdown.relative_to(ROOT)}:{target}")

    return failures


def compute_seed_root(vector: dict) -> str:
    data = vector["input"]
    files = data["files"]
    paths = [record["path"] for record in files]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate_manifest_path")
    if any(not safe_relative_path(path) for path in paths):
        raise ValueError("invalid_relative_path")

    fields = [
        data["protocol_version"],
        data["seed_id"],
        data["identity_digest"],
        data["doctrine_digest"],
        str(len(files)),
    ]
    for record in sorted(files, key=lambda item: item["path"].encode("utf-8")):
        fields.extend(
            [
                record["path"],
                record["kind"],
                bool_text(record["required"]),
                record["digest"],
            ]
        )
    return hash_fields(vector["domain"], fields)


def compute_memory_event(vector: dict) -> str:
    event = vector["input"]
    fields = [
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
    ]
    return hash_fields(vector["domain"], fields, prefix="evsha256:")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate_invalid_case(case: dict) -> str | None:
    category = case["category"]
    data = case["input"]

    if category == "seed_path":
        return None if safe_relative_path(data) else "invalid_relative_path"

    if category == "canonical_text":
        return None if unicodedata.normalize("NFC", data) == data else "text_not_nfc"

    if category == "seed_manifest":
        return "duplicate_manifest_path" if len(data) != len(set(data)) else None

    if category == "body_registry":
        active = sum(1 for body in data if body.get("status") == "active_writer")
        return "multiple_active_writers" if active > 1 else None

    if category == "memory_append":
        return "body_not_authorized" if data.get("body_status") != "active_writer" else None

    if category == "memory_chain":
        children = data.get("children", [])
        return "fork_detected" if len(set(children)) > 1 else None

    if category == "transfer":
        return "instance_id_mismatch" if data.get("package_instance_id") != data.get("destination_instance_id") else None

    if category == "recovery":
        has_gap = data.get("last_backup_sequence") < data.get("last_known_sequence")
        return "undeclared_memory_gap" if has_gap and data.get("continuity_status") == "complete" else None

    if category == "guardian_authorization":
        if data.get("revocation_event_present"):
            return "authorization_revoked"
        if "evaluated_at" in data and "expires_at" in data:
            if parse_utc(data["evaluated_at"]) >= parse_utc(data["expires_at"]):
                return "authorization_expired"
        if (
            data.get("mode") == "one_time"
            and data.get("consumed_events", 0) >= data.get("use_limit", 1)
        ):
            return "authorization_use_limit_reached"
        return None

    raise ValueError(f"unknown_invalid_case_category:{category}")


def load_json(relative: str) -> dict:
    with (ROOT / relative).open("r", encoding="utf-8") as handle:
        return json.load(handle)



def run_behavior_cases() -> list[str]:
    """Toda implementacion debe RECHAZAR estos casos (paridad de comportamiento)."""
    failures: list[str] = []
    cases = json.loads((ROOT / "conformance" / "behavior_cases.json").read_text(encoding="utf-8"))
    for case in cases["must_reject_encoding"]:
        try:
            encode_field(case["value"])
            failures.append(f"encoding_no_rechazado:{case['case_id']}")
        except ValueError:
            pass
    for case in cases["must_reject_paths"]:
        if safe_relative_path(case["value"]):
            failures.append(f"ruta_no_rechazada:{case['case_id']}")
    return failures

def main() -> int:
    failures = validate_workspace_hygiene()

    for path in ROOT.rglob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as handle:
                json.load(handle)
        except Exception as error:
            failures.append(f"invalid_json:{path.relative_to(ROOT)}:{error}")

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1

    vectors = load_json("conformance/golden_vectors.json")

    for case in vectors["field_encoding"]:
        actual = encode_field(case["value"]).hex()
        if actual != case["expected_hex"]:
            failures.append(f"field_vector_mismatch:{case['case_id']}")

    actual_seed = compute_seed_root(vectors["seed_root"])
    if actual_seed != vectors["seed_root"]["expected_root_hash"]:
        failures.append("seed_root_vector_mismatch")

    actual_event = compute_memory_event(vectors["memory_event"])
    if actual_event != vectors["memory_event"]["expected_event_hash"]:
        failures.append("memory_event_vector_mismatch")

    invalid = load_json("conformance/invalid_cases.json")
    for case in invalid["invalid_cases"]:
        try:
            actual_error = evaluate_invalid_case(case)
        except Exception as error:
            failures.append(f"invalid_case_exception:{case['case_id']}:{error}")
            continue
        if actual_error != case["expected_error"]:
            failures.append(
                f"invalid_case_mismatch:{case['case_id']}:expected={case['expected_error']}:actual={actual_error}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1

    behavior_failures = run_behavior_cases()
    if behavior_failures:
        for item in behavior_failures:
            print(f"FAIL behavior: {item}")
        return 1
    print("OK behavior parity cases")
    print("OK workspace structure")
    print("OK workspace hygiene and Markdown links")
    print("OK JSON syntax")
    print("OK hashing vectors")
    print("OK invalid-case reference checks")
    print("NOTE This is a reference check, not a production security certification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

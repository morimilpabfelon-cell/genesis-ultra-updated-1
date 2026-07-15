#!/usr/bin/env python3
"""Genera o comprueba el manifiesto reproducible de integridad del borrador."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = "conformance/required_artifacts.json"
MANIFEST_PATH = "conformance/draft_manifest.json"
ROOT_DOMAIN = "genesis.draft.integrity.root.v0.1"


def frame(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("manifest_field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("manifest_text_not_nfc")
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded + b"\n"


def safe_relative_path(value: str) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if unicodedata.normalize("NFC", value) != value:
        return False
    if value.startswith("/") or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return False
    return all(segment not in {"", ".", ".."} for segment in value.split("/"))


def root_digest(manifest: dict) -> str:
    fields = [
        manifest["schema_version"],
        manifest["protocol_version"],
        manifest["root_hash_profile"],
        manifest["file_digest_algorithm"],
        manifest["inventory_path"],
        manifest["manifest_path"],
        "true" if manifest["self_excluded"] else "false",
        str(manifest["file_count"]),
    ]
    for record in manifest["files"]:
        fields.extend([record["path"], str(record["size_bytes"]), record["digest"]])
    preimage = frame(ROOT_DOMAIN) + b"".join(frame(value) for value in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def build_manifest() -> dict:
    inventory = json.loads((ROOT / INVENTORY_PATH).read_text(encoding="utf-8"))
    required = inventory["required"]
    forbidden = inventory["forbidden"]
    if len(required) != len(set(required)):
        raise ValueError("duplicate_required_workspace_path")
    if required != sorted(required, key=lambda value: value.encode("utf-8")):
        raise ValueError("required_workspace_paths_not_sorted")
    if forbidden != sorted(forbidden, key=lambda value: value.encode("utf-8")):
        raise ValueError("forbidden_workspace_paths_not_sorted")
    if any(not safe_relative_path(path) for path in required + forbidden):
        raise ValueError("unsafe_workspace_inventory_path")
    if required.count(MANIFEST_PATH) != 1:
        raise ValueError("manifest_path_must_be_required_once")
    if set(required) & set(forbidden):
        raise ValueError("required_forbidden_workspace_overlap")
    if any((ROOT / path).exists() for path in forbidden):
        raise ValueError("forbidden_workspace_path_exists")

    paths = sorted(
        (path for path in required if path != MANIFEST_PATH),
        key=lambda value: value.encode("utf-8"),
    )
    records = []
    for relative in paths:
        file_path = ROOT / relative
        if not file_path.is_file():
            raise FileNotFoundError(f"missing_manifest_source:{relative}")
        payload = file_path.read_bytes()
        records.append(
            {
                "path": relative,
                "size_bytes": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
        )

    manifest = {
        "schema_version": "genesis.draft.manifest.v0.1",
        "protocol_version": "genesis.protocol.v0.1",
        "root_hash_profile": "genesis.hash.fields.v0.1",
        "file_digest_algorithm": "sha256",
        "inventory_path": INVENTORY_PATH,
        "manifest_path": MANIFEST_PATH,
        "self_excluded": True,
        "file_count": len(records),
        "files": records,
    }
    manifest["root_digest"] = root_digest(manifest)
    return manifest


def serialized_manifest() -> str:
    return json.dumps(build_manifest(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Comprueba el archivo existente.")
    mode.add_argument("--write", action="store_true", help="Actualiza el archivo existente.")
    args = parser.parse_args()

    expected = serialized_manifest()
    manifest_path = ROOT / MANIFEST_PATH
    if args.check:
        if not manifest_path.is_file():
            print(f"FAIL draft manifest missing: {MANIFEST_PATH}")
            return 1
        if manifest_path.read_text(encoding="utf-8") != expected:
            print("FAIL draft manifest is stale; run tools/generate_draft_manifest.py --write")
            return 1
        manifest = json.loads(expected)
        print(
            f"OK draft manifest: {manifest['file_count']} files, "
            f"root={manifest['root_digest']}"
        )
        return 0

    if args.write:
        manifest_path.write_text(expected, encoding="utf-8", newline="\n")
        print(f"Updated {MANIFEST_PATH}")
        return 0

    sys.stdout.write(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

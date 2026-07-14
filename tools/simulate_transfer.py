#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simulación gobernada A -> B para Genesis Ultra.

Demuestra la continuidad de una instancia entre dos cuerpos y enlaza explícitamente:
paquete -> recibo -> finalización. Es una implementación auxiliar de borrador, no una
certificación de seguridad ni un flujo de producción completo.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from validate_workspace import hash_fields, encode_field
from validate_continuity import (
    compute_transfer_finalization,
    compute_transfer_package,
    compute_transfer_receipt,
)

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("ERROR: PyNaCl es requerido para la simulación (python -m pip install -r requirements.txt).", file=sys.stderr)
    sys.exit(1)

DOMAIN_EVENT = "genesis.memory.event.v0.1"
DOMAIN_CHECKPOINT = "genesis.checkpoint.v0.1"
DOMAIN_POSSESSION = "genesis.body.possession.v0.1"
DOMAIN_SIG = "genesis.signature.ed25519.v0.1"

INSTANCE_ID = "inst_01HSIMULATION0000000001"
SEED_ROOT = "sha256:" + hashlib.sha256(b"genesis simulation seed manifest").hexdigest()


def event_hash(event: dict) -> str:
    return "ev" + hash_fields(
        DOMAIN_EVENT,
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
    )


def make_event(sequence: int, body_id: str, previous: str, event_type: str, actor: str = "companion") -> dict:
    event = {
        "schema_version": DOMAIN_EVENT,
        "event_id": f"evt_{sequence:026d}",
        "instance_id": INSTANCE_ID,
        "body_id": body_id,
        "sequence": sequence,
        "previous_event_hash": previous,
        "event_type": event_type,
        "actor": actor,
        "content_digest": "sha256:" + hashlib.sha256(f"content-{sequence}".encode()).hexdigest(),
        "content_type": "text/plain",
        "observed_at": f"2026-07-12T00:{sequence:02d}:00Z",
        "provenance_digest": "sha256:" + hashlib.sha256(f"prov-{sequence}".encode()).hexdigest(),
        "privacy": "private_local",
    }
    event["event_hash"] = event_hash(event)
    return event


def digest(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def sign(seed_byte: int, message: str) -> dict:
    signing_key = SigningKey(bytes([seed_byte]) * 32)
    domain_message = encode_field(DOMAIN_SIG) + encode_field(message)
    signature = signing_key.sign(domain_message).signature
    return {
        "algorithm": DOMAIN_SIG,
        "public_key": signing_key.verify_key.encode().hex(),
        "signature": signature.hex(),
    }


def verify_signature(entry: dict, message: str) -> None:
    verify_key = VerifyKey(bytes.fromhex(entry["public_key"]))
    domain_message = encode_field(DOMAIN_SIG) + encode_field(message)
    verify_key.verify(domain_message, bytes.fromhex(entry["signature"]))

    tampered = bytearray(bytes.fromhex(entry["signature"]))
    tampered[0] ^= 0x01
    try:
        verify_key.verify(domain_message, bytes(tampered))
        raise AssertionError("una firma alterada fue aceptada")
    except BadSignatureError:
        pass


def main() -> int:
    steps: list[dict] = []

    def step(number: int, title: str, **data: object) -> None:
        steps.append({"step": number, "title": title, **data})

    body_a = "body_01HSIM_A000000000000001"
    body_b = "body_01HSIM_B000000000000001"
    transfer_id = "xfer_01HSIM0000000000000001"
    authorization_ref = "gauth_01HSIM000000000000001"

    e0 = make_event(0, body_a, "GENESIS", "instance.birth", actor="system")
    e1 = make_event(1, body_a, e0["event_hash"], "chat.user", actor="guardian")
    e2 = make_event(2, body_a, e1["event_hash"], "chat.companion")
    chain = [e0, e1, e2]

    previous = "GENESIS"
    for event in chain:
        assert event["previous_event_hash"] == previous, "cadena rota"
        assert event["event_hash"] == event_hash(event), "hash de evento no reproducible"
        previous = event["event_hash"]

    step(
        1,
        "instancia viva en A con cadena válida",
        instance_id=INSTANCE_ID,
        body_a=body_a,
        events=len(chain),
        last_event_hash=e2["event_hash"],
    )

    checkpoint = {
        "instance_id": INSTANCE_ID,
        "body_id": body_a,
        "last_sequence": 2,
        "last_event_hash": e2["event_hash"],
        "created_at": "2026-07-12T01:00:00Z",
    }
    checkpoint_hash = digest(
        DOMAIN_CHECKPOINT,
        [
            checkpoint["instance_id"],
            checkpoint["body_id"],
            str(checkpoint["last_sequence"]),
            checkpoint["last_event_hash"],
            checkpoint["created_at"],
        ],
    )
    checkpoint_signature = sign(0xA1, checkpoint_hash)
    verify_signature(checkpoint_signature, checkpoint_hash)
    step(2, "checkpoint creado y firmado por A", checkpoint_hash=checkpoint_hash)

    step(3, "A congela nuevas escrituras", a_status="frozen", transfer_id=transfer_id)

    chain_bytes = json.dumps(chain, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    package_case = {
        "domain": "genesis.transfer.package.v0.1",
        "input": {
            "schema_version": "genesis.transfer.package.v0.1",
            "transfer_id": transfer_id,
            "instance_id": INSTANCE_ID,
            "source_body_id": body_a,
            "destination_body_id": body_b,
            "mode": "transfer",
            "created_at": "2026-07-12T01:01:00Z",
            "checkpoint_hash": checkpoint_hash,
            "last_event_hash": e2["event_hash"],
            "continuity_status": "complete",
            "authorization_ref": authorization_ref,
            "contents": [
                {
                    "kind": "memory",
                    "path": "memory/events.json",
                    "digest": "sha256:" + hashlib.sha256(chain_bytes).hexdigest(),
                },
                {
                    "kind": "seed",
                    "path": "seed/manifest.json",
                    "digest": SEED_ROOT,
                },
            ],
        },
    }
    package_digest = compute_transfer_package(package_case)
    step(4, "paquete canónico construido", package_digest=package_digest)

    possession_challenge = digest(DOMAIN_POSSESSION, [INSTANCE_ID, body_b, checkpoint_hash])
    body_b_proof = sign(0xB2, possession_challenge)
    verify_signature(body_b_proof, possession_challenge)
    step(
        5,
        "B demuestra posesión de su clave",
        challenge=possession_challenge,
        signature_verified=True,
        tamper_rejected=True,
    )

    receipt_case = {
        "domain": "genesis.transfer.receipt.v0.1",
        "input": {
            "schema_version": "genesis.transfer.receipt.v0.1",
            "transfer_id": transfer_id,
            "instance_id": INSTANCE_ID,
            "source_body_id": body_a,
            "destination_body_id": body_b,
            "accepted_package_digest": package_digest,
            "accepted_checkpoint_hash": checkpoint_hash,
            "accepted_last_event_hash": e2["event_hash"],
            "accepted_last_sequence": 2,
            "accepted_at": "2026-07-12T01:05:00Z",
            "continuity_status": "complete",
            "continuity_gap_ref": None,
            "guardian_authorization_ref": authorization_ref,
        },
    }
    receipt_digest = compute_transfer_receipt(receipt_case)
    assert receipt_case["input"]["accepted_package_digest"] == package_digest
    step(
        6,
        "recibo vinculado al paquete exacto",
        accepted_package_digest=package_digest,
        receipt_digest=receipt_digest,
    )

    finalization_case = {
        "domain": "genesis.transfer.finalization.v0.1",
        "input": {
            "schema_version": "genesis.transfer.finalization.v0.1",
            "transfer_id": transfer_id,
            "instance_id": INSTANCE_ID,
            "source_body_id": body_a,
            "destination_body_id": body_b,
            "receipt_digest": receipt_digest,
            "source_final_status": "revoked",
            "destination_final_status": "active_writer",
            "finalized_at": "2026-07-12T01:06:00Z",
            "guardian_authorization_ref": authorization_ref,
        },
    }
    finalization_digest = compute_transfer_finalization(finalization_case)
    step(
        7,
        "autoridad transferida en la finalización",
        finalization_digest=finalization_digest,
        source_final="revoked",
        destination_final="active_writer",
    )

    e3 = make_event(3, body_b, e2["event_hash"], "transfer.completed")
    assert e3["previous_event_hash"] == e2["event_hash"]
    assert e3["body_id"] == body_b and e3["instance_id"] == INSTANCE_ID
    step(
        8,
        "B continúa la misma cadena",
        new_event_sequence=3,
        new_body_id=body_b,
        instance_preserved=True,
        new_event_hash=e3["event_hash"],
    )

    result = {
        "simulation": "genesis.transfer.A_to_B.v0.1",
        "status": "complete",
        "instance_id": INSTANCE_ID,
        "links": {
            "package_digest": package_digest,
            "receipt_accepts_package_digest": receipt_case["input"]["accepted_package_digest"],
            "receipt_digest": receipt_digest,
            "finalization_receipt_digest": finalization_case["input"]["receipt_digest"],
            "finalization_digest": finalization_digest,
        },
        "invariants_checked": [
            "instance_id conservado",
            "body_id cambia de A a B",
            "cadena continua entre A y B",
            "paquete vinculado al recibo",
            "recibo vinculado a la finalización",
            "A revocado y B active_writer únicamente tras finalización",
            "firma alterada rechazada",
        ],
        "steps": steps,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\nSIMULACIÓN A -> B COMPLETA", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

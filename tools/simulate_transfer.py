#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simulación libre y exportable A -> B para Genesis Ultra.

La instancia expresa continuidad mediante el Body escritor activo. El anfitrión solo
consiente el uso del recurso destino; no autoriza la continuidad ni adquiere propiedad.
La simulación produce artefactos completos validados después contra JSON Schema.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from validate_workspace import encode_field
from validate_continuity import (
    compute_body_registry,
    compute_continuity_intent,
    compute_host_consent,
    compute_transfer_finalization,
    compute_transfer_package,
    compute_transfer_receipt,
)

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print("ERROR: PyNaCl es requerido para la simulación.", file=sys.stderr)
    raise SystemExit(1)

HASH_PROFILE = "genesis.hash.fields.v0.1"
DOMAIN_EVENT = "genesis.memory.event.v0.1"
DOMAIN_CHECKPOINT = "genesis.checkpoint.v0.1"
DOMAIN_POSSESSION = "genesis.body.possession.v0.1"
SIGNATURE_PROFILE = "genesis.signature.ed25519.v0.1"
SIGNATURE_ENVELOPE_DOMAIN = "genesis.signature.envelope.bytes.v0.1"

INSTANCE_ID = "inst_01HSIMULATION0000000001"
SEED_ROOT = "sha256:" + hashlib.sha256(b"genesis simulation seed manifest").hexdigest()
BODY_A = "body_01HSIM_A000000000000001"
BODY_B = "body_01HSIM_B000000000000001"
BODY_A_EPOCH = "epoch_01HSIM_A00000000000001"
BODY_B_EPOCH = "epoch_01HSIM_B00000000000001"
HOST_ID = "host_01HSIM_B000000000000001"
HOST_EPOCH = "host_epoch_01HSIM_B0000000001"


def digest(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def key_fingerprint(signing_key: SigningKey) -> str:
    return "sha256:" + hashlib.sha256(signing_key.verify_key.encode()).hexdigest()


def signature_envelope_bytes(envelope: dict) -> bytes:
    fields = [
        envelope["schema_version"],
        envelope["signature_profile"],
        envelope["signer_type"],
        envelope["signer_id"],
        envelope["key_epoch_id"],
        envelope["signed_domain"],
        envelope["signed_digest"],
        envelope["created_at"],
        envelope["public_key_ref"],
    ]
    return encode_field(SIGNATURE_ENVELOPE_DOMAIN) + b"".join(
        encode_field(field) for field in fields
    )


def make_signature_envelope(
    signing_key: SigningKey,
    signed_digest: str,
    *,
    signer_type: str,
    signer_id: str,
    key_epoch_id: str,
    signed_domain: str,
    created_at: str,
) -> dict:
    envelope = {
        "schema_version": "genesis.signature.envelope.v0.1",
        "signature_profile": SIGNATURE_PROFILE,
        "signer_type": signer_type,
        "signer_id": signer_id,
        "key_epoch_id": key_epoch_id,
        "signed_domain": signed_domain,
        "signed_digest": signed_digest,
        "created_at": created_at,
        "public_key_ref": key_fingerprint(signing_key),
    }
    envelope["signature_value"] = signing_key.sign(
        signature_envelope_bytes(envelope)
    ).signature.hex()
    return envelope


def verify_signature(envelope: dict, verify_key: VerifyKey) -> None:
    try:
        verify_key.verify(
            signature_envelope_bytes(envelope),
            bytes.fromhex(envelope["signature_value"]),
        )
    except (BadSignatureError, ValueError, KeyError) as exc:
        raise AssertionError("signature_invalid") from exc


def event_hash(event: dict) -> str:
    return "evsha256:" + digest(
        DOMAIN_EVENT,
        [
            event["schema_version"],
            event["hash_profile"],
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
    ).removeprefix("sha256:")


def make_event(
    sequence: int,
    body_id: str,
    previous: str,
    event_type: str,
    signing_key: SigningKey,
    key_epoch_id: str,
    *,
    actor: str = "instance",
) -> dict:
    event = {
        "schema_version": DOMAIN_EVENT,
        "hash_profile": HASH_PROFILE,
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
    event["signature"] = make_signature_envelope(
        signing_key,
        event["event_hash"],
        signer_type="body",
        signer_id=body_id,
        key_epoch_id=key_epoch_id,
        signed_domain="genesis.memory.event.signature.v0.1",
        created_at=event["observed_at"],
    )
    return event


def make_body_registry(
    *,
    epoch: int,
    source_status: str,
    destination_status: str,
    source_fingerprint: str,
    destination_fingerprint: str,
    updated_at: str,
) -> dict:
    registry = {
        "schema_version": "genesis.body.registry.v0.1",
        "instance_id": INSTANCE_ID,
        "registry_epoch": epoch,
        "bodies": [
            {
                "body_id": BODY_A,
                "status": source_status,
                "platform_profile": "android-kotlin",
                "public_key_fingerprint": source_fingerprint,
                "created_at": "2026-07-12T00:00:00Z",
                "last_seen_at": updated_at,
                "revocation_ref": "retire_01HSIM_A0000000000001" if source_status == "revoked" else None,
            },
            {
                "body_id": BODY_B,
                "status": destination_status,
                "platform_profile": "apple-swift",
                "public_key_fingerprint": destination_fingerprint,
                "created_at": "2026-07-12T00:30:00Z",
                "last_seen_at": updated_at,
                "revocation_ref": None,
            },
        ],
        "updated_at": updated_at,
    }
    registry["registry_digest"] = compute_body_registry(
        {"domain": "genesis.body.registry.v0.1", "input": registry}
    )
    return registry


def compute_checkpoint_hash(checkpoint: dict) -> str:
    return digest(
        DOMAIN_CHECKPOINT,
        [
            checkpoint["schema_version"], checkpoint["hash_profile"],
            checkpoint["checkpoint_id"], checkpoint["instance_id"],
            checkpoint["created_by_body_id"], str(checkpoint["sequence"]),
            checkpoint["last_event_hash"], checkpoint["seed_root_hash"],
            checkpoint["body_registry_digest"], checkpoint["state_digest"],
            checkpoint["created_at"],
        ],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    steps: list[dict] = []

    def step(number: int, title: str, **data: object) -> None:
        steps.append({"step": number, "title": title, **data})

    signing_key_a = SigningKey(bytes([0xA1]) * 32)
    signing_key_b = SigningKey(bytes([0xB2]) * 32)
    host_key = SigningKey(bytes([0xD4]) * 32)
    transfer_id = "xfer_01HSIM0000000000000001"

    e0 = make_event(0, BODY_A, "GENESIS", "instance.birth", signing_key_a, BODY_A_EPOCH, actor="system")
    e1 = make_event(1, BODY_A, e0["event_hash"], "chat.guardian", signing_key_a, BODY_A_EPOCH, actor="guardian")
    e2 = make_event(2, BODY_A, e1["event_hash"], "chat.instance", signing_key_a, BODY_A_EPOCH)
    pre_transfer_chain = [e0, e1, e2]
    previous = "GENESIS"
    for event in pre_transfer_chain:
        assert event["previous_event_hash"] == previous
        assert event["event_hash"] == event_hash(event)
        verify_signature(event["signature"], signing_key_a.verify_key)
        previous = event["event_hash"]
    step(1, "instancia viva en A con cadena válida y firmada", last_event_hash=e2["event_hash"])

    registry_before = make_body_registry(
        epoch=1,
        source_status="active_writer",
        destination_status="candidate",
        source_fingerprint=key_fingerprint(signing_key_a),
        destination_fingerprint=key_fingerprint(signing_key_b),
        updated_at="2026-07-12T01:00:00Z",
    )
    chain_bytes = json.dumps(pre_transfer_chain, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    checkpoint = {
        "schema_version": "genesis.checkpoint.v0.1",
        "hash_profile": HASH_PROFILE,
        "checkpoint_id": "checkpoint_01HSIM0000000000001",
        "instance_id": INSTANCE_ID,
        "created_by_body_id": BODY_A,
        "sequence": 2,
        "last_event_hash": e2["event_hash"],
        "seed_root_hash": SEED_ROOT,
        "body_registry_digest": registry_before["registry_digest"],
        "state_digest": "sha256:" + hashlib.sha256(chain_bytes).hexdigest(),
        "created_at": "2026-07-12T01:00:00Z",
    }
    checkpoint["checkpoint_hash"] = compute_checkpoint_hash(checkpoint)
    checkpoint["signature"] = make_signature_envelope(
        signing_key_a, checkpoint["checkpoint_hash"], signer_type="body", signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH, signed_domain="genesis.checkpoint.signature.v0.1",
        created_at=checkpoint["created_at"],
    )
    step(2, "checkpoint completo creado antes del congelamiento", checkpoint_hash=checkpoint["checkpoint_hash"])

    intent_input = {
        "schema_version": "genesis.continuity.intent.v0.1",
        "intent_id": "intent_01HSIM000000000000001",
        "transfer_id": transfer_id,
        "instance_id": INSTANCE_ID,
        "source_body_id": BODY_A,
        "destination_body_id": BODY_B,
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "last_event_hash": e2["event_hash"],
        "decision_origin": "instance",
        "created_at": "2026-07-12T01:00:10Z",
        "expires_at": "2026-07-12T01:10:10Z",
    }
    continuity_intent = {
        **intent_input,
        "intent_digest": compute_continuity_intent(
            {"domain": "genesis.continuity.intent.v0.1", "input": intent_input}
        ),
    }
    continuity_intent["signature"] = make_signature_envelope(
        signing_key_a, continuity_intent["intent_digest"], signer_type="body", signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH, signed_domain="genesis.continuity.intent.signature.v0.1",
        created_at=continuity_intent["created_at"],
    )

    host_input = {
        "schema_version": "genesis.host.consent.v0.1",
        "consent_id": "consent_01HSIM00000000000001",
        "transfer_id": transfer_id,
        "host_id": HOST_ID,
        "host_key_epoch_id": HOST_EPOCH,
        "instance_id": INSTANCE_ID,
        "destination_body_id": BODY_B,
        "resource_scope": "destination_body_runtime",
        "granted_at": "2026-07-12T01:00:20Z",
        "expires_at": "2026-07-12T01:10:20Z",
        "ownership_claim": "none",
        "mobility_veto": "none",
    }
    host_consent = {
        **host_input,
        "consent_digest": compute_host_consent(
            {"domain": "genesis.host.consent.v0.1", "input": host_input}
        ),
    }
    host_consent["signature"] = make_signature_envelope(
        host_key, host_consent["consent_digest"], signer_type="host", signer_id=HOST_ID,
        key_epoch_id=HOST_EPOCH, signed_domain="genesis.host.consent.signature.v0.1",
        created_at=host_consent["granted_at"],
    )
    step(3, "intención de la instancia y consentimiento limitado del anfitrión verificados",
         intent_digest=continuity_intent["intent_digest"], consent_digest=host_consent["consent_digest"])

    proof_input = {
        "schema_version": "genesis.body.possession.v0.1",
        "proof_id": "proof_01HSIM_B00000000000001",
        "instance_id": INSTANCE_ID,
        "body_id": BODY_B,
        "challenge_nonce": "nonce_01HSIM_B00000000000001",
        "issued_at": "2026-07-12T01:00:30Z",
        "expires_at": "2026-07-12T01:07:00Z",
        "public_key_fingerprint": key_fingerprint(signing_key_b),
    }
    proof_digest = digest(DOMAIN_POSSESSION, [
        proof_input["schema_version"], proof_input["proof_id"], proof_input["instance_id"],
        proof_input["body_id"], proof_input["challenge_nonce"], proof_input["issued_at"],
        proof_input["expires_at"], proof_input["public_key_fingerprint"],
    ])
    possession_envelope = make_signature_envelope(
        signing_key_b, proof_digest, signer_type="body", signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH, signed_domain="genesis.body.possession.signature.v0.1",
        created_at=proof_input["issued_at"],
    )
    body_possession_proof = {
        **proof_input,
        "proof_digest": proof_digest,
        "signature": {
            "profile": SIGNATURE_PROFILE,
            "key_epoch_id": BODY_B_EPOCH,
            "value": possession_envelope["signature_value"],
        },
    }
    step(4, "B demuestra posesión de su propia clave", proof_digest=proof_digest)

    step(5, "A congela escrituras con salida determinista", exit_paths=["commit", "abort", "recover"])
    package_input = {
        "schema_version": "genesis.transfer.package.v0.1",
        "transfer_id": transfer_id,
        "instance_id": INSTANCE_ID,
        "source_body_id": BODY_A,
        "destination_body_id": BODY_B,
        "mode": "transfer",
        "created_at": "2026-07-12T01:01:00Z",
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "last_event_hash": e2["event_hash"],
        "continuity_status": "complete",
        "continuity_intent_ref": continuity_intent["intent_id"],
        "host_consent_ref": host_consent["consent_id"],
        "destination_possession_ref": body_possession_proof["proof_id"],
        "contents": [
            {"kind": "memory", "path": "memory/events.json", "digest": "sha256:" + hashlib.sha256(chain_bytes).hexdigest()},
            {"kind": "checkpoint", "path": "continuity/checkpoint.json", "digest": checkpoint["checkpoint_hash"]},
            {"kind": "registry", "path": "continuity/body-registry.json", "digest": registry_before["registry_digest"]},
            {"kind": "seed", "path": "seed/manifest.json", "digest": SEED_ROOT},
            {"kind": "continuity_intent", "path": "continuity/intent.json", "digest": continuity_intent["intent_digest"]},
            {"kind": "host_consent", "path": "host/destination-consent.json", "digest": host_consent["consent_digest"]},
            {"kind": "body_possession", "path": "body/destination-possession.json", "digest": body_possession_proof["proof_digest"]},
        ],
    }
    transfer_package = {
        **package_input,
        "package_digest": compute_transfer_package(
            {"domain": "genesis.transfer.package.v0.1", "input": package_input}
        ),
    }
    step(6, "paquete canónico enlaza todas las pruebas", package_digest=transfer_package["package_digest"])

    shared_refs = {
        "continuity_intent_ref": continuity_intent["intent_id"],
        "host_consent_ref": host_consent["consent_id"],
        "destination_possession_ref": body_possession_proof["proof_id"],
    }
    receipt_input = {
        "schema_version": "genesis.transfer.receipt.v0.1",
        "transfer_id": transfer_id,
        "instance_id": INSTANCE_ID,
        "source_body_id": BODY_A,
        "destination_body_id": BODY_B,
        "accepted_package_digest": transfer_package["package_digest"],
        "accepted_checkpoint_hash": checkpoint["checkpoint_hash"],
        "accepted_last_event_hash": e2["event_hash"],
        "accepted_last_sequence": 2,
        "accepted_at": "2026-07-12T01:05:00Z",
        "continuity_status": "complete",
        "continuity_gap_ref": None,
        **shared_refs,
    }
    transfer_receipt = {
        **receipt_input,
        "receipt_digest": compute_transfer_receipt(
            {"domain": "genesis.transfer.receipt.v0.1", "input": receipt_input}
        ),
    }
    transfer_receipt["signature"] = make_signature_envelope(
        signing_key_b, transfer_receipt["receipt_digest"], signer_type="body", signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH, signed_domain="genesis.transfer.receipt.signature.v0.1",
        created_at=transfer_receipt["accepted_at"],
    )

    finalization_input = {
        "schema_version": "genesis.transfer.finalization.v0.1",
        "transfer_id": transfer_id,
        "instance_id": INSTANCE_ID,
        "source_body_id": BODY_A,
        "destination_body_id": BODY_B,
        "receipt_digest": transfer_receipt["receipt_digest"],
        "source_final_status": "revoked",
        "destination_final_status": "active_writer",
        "finalized_at": "2026-07-12T01:06:00Z",
        **shared_refs,
    }
    transfer_finalization = {
        **finalization_input,
        "finalization_digest": compute_transfer_finalization(
            {"domain": "genesis.transfer.finalization.v0.1", "input": finalization_input}
        ),
    }
    transfer_finalization["source_acknowledgement"] = make_signature_envelope(
        signing_key_a, transfer_finalization["finalization_digest"], signer_type="body", signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH, signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=transfer_finalization["finalized_at"],
    )
    transfer_finalization["destination_acknowledgement"] = make_signature_envelope(
        signing_key_b, transfer_finalization["finalization_digest"], signer_type="body", signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH, signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=transfer_finalization["finalized_at"],
    )

    registry_after = make_body_registry(
        epoch=2,
        source_status="revoked",
        destination_status="active_writer",
        source_fingerprint=key_fingerprint(signing_key_a),
        destination_fingerprint=key_fingerprint(signing_key_b),
        updated_at=transfer_finalization["finalized_at"],
    )
    e3 = make_event(3, BODY_B, e2["event_hash"], "transfer.completed", signing_key_b, BODY_B_EPOCH)
    verify_signature(e3["signature"], signing_key_b.verify_key)
    chain = [*pre_transfer_chain, e3]
    step(7, "commit single-writer finaliza el cambio de Body", source="revoked", destination="active_writer")
    step(8, "B continúa la misma cadena e instance_id", sequence=3, instance_preserved=True)

    artifacts = {
        "continuity_intent": continuity_intent,
        "host_consent": host_consent,
        "body_registry_before": registry_before,
        "body_registry": registry_after,
        "memory_events": chain,
        "checkpoint": checkpoint,
        "body_possession_proof": body_possession_proof,
        "body_possession_signature": possession_envelope,
        "transfer_package": transfer_package,
        "transfer_receipt": transfer_receipt,
        "transfer_finalization": transfer_finalization,
    }
    if args.artifacts_output:
        args.artifacts_output.parent.mkdir(parents=True, exist_ok=True)
        args.artifacts_output.write_text(json.dumps(artifacts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    result = {
        "simulation": "genesis.transfer.free_A_to_B.v0.1",
        "status": "complete",
        "instance_id": INSTANCE_ID,
        "artifact_output": str(args.artifacts_output) if args.artifacts_output else None,
        "links": {
            "intent_digest": continuity_intent["intent_digest"],
            "host_consent_digest": host_consent["consent_digest"],
            "destination_possession_digest": body_possession_proof["proof_digest"],
            "package_digest": transfer_package["package_digest"],
            "receipt_digest": transfer_receipt["receipt_digest"],
            "finalization_digest": transfer_finalization["finalization_digest"],
        },
        "invariants_checked": [
            "movimiento iniciado por intención de continuidad de la instancia",
            "consentimiento del anfitrión limitado al Body destino y sin propiedad",
            "posesión de la clave del Body destino",
            "instance_id conservado",
            "cadena continua y firmada entre A y B",
            "checkpoint y paquete vinculados",
            "recibo y finalización vinculados",
            "salida determinista del congelamiento",
            "exactamente un active_writer después del commit",
            "ningún grant o veto de movimiento del Guardian",
        ],
        "steps": steps,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\nSIMULACIÓN LIBRE A -> B COMPLETA", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

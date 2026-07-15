#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simulación gobernada y exportable A -> B para Genesis Ultra.

La simulación produce artefactos completos que después se validan contra los JSON
Schema normativos. Demuestra continuidad y enlaza paquete -> recibo -> finalización.
Sigue siendo una implementación auxiliar de borrador, no un flujo de producción.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from validate_workspace import encode_field, hash_fields
from validate_continuity import (
    compute_body_registry,
    compute_transfer_finalization,
    compute_transfer_package,
    compute_transfer_receipt,
)
from validate_authority import (
    compute_authority_event_hash,
    compute_authorization_digest,
    compute_authorization_use_digest,
    compute_device_registration_digest,
    evaluate_mobility_authorization,
    validate_authority_ledger,
)

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    print(
        "ERROR: PyNaCl es requerido para la simulación "
        "(python -m pip install -r requirements.txt).",
        file=sys.stderr,
    )
    sys.exit(1)

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
GUARDIAN_ID = "guardian_01HSIM_EIDON000000001"
GUARDIAN_KEY_EPOCH = "guardian_epoch_01HSIM000000001"
AUTHORITY_LEDGER_ID = "authority_ledger_01HSIM00000001"


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
    signed_bytes = signature_envelope_bytes(envelope)
    signature = bytes.fromhex(envelope["signature_value"])
    verify_key.verify(signed_bytes, signature)

    tampered = bytearray(signature)
    tampered[0] ^= 0x01
    try:
        verify_key.verify(signed_bytes, bytes(tampered))
        raise AssertionError("una firma alterada fue aceptada")
    except BadSignatureError:
        pass


def make_device_registration(
    *,
    registration_id: str,
    body_id: str,
    platform_profile: str,
    public_key_fingerprint: str,
    registered_at: str,
    guardian_key: SigningKey,
) -> dict:
    registration = {
        "schema_version": "genesis.guardian.device.registration.v0.1",
        "registration_id": registration_id,
        "guardian_id": GUARDIAN_ID,
        "guardian_key_epoch_id": GUARDIAN_KEY_EPOCH,
        "instance_id": INSTANCE_ID,
        "authority_epoch": 1,
        "body_id": body_id,
        "platform_profile": platform_profile,
        "public_key_fingerprint": public_key_fingerprint,
        "registered_at": registered_at,
    }
    registration["registration_digest"] = compute_device_registration_digest(registration)
    registration["signature"] = make_signature_envelope(
        guardian_key,
        registration["registration_digest"],
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
        signed_domain="genesis.guardian.device.registration.signature.v0.1",
        created_at=registered_at,
    )
    verify_signature(registration["signature"], guardian_key.verify_key)
    return registration


def make_standing_mobility_authorization(guardian_key: SigningKey) -> dict:
    authorization = {
        "schema_version": "genesis.guardian.authorization.v0.1",
        "authorization_id": "gauth_01HSIM000000000000001",
        "guardian_id": GUARDIAN_ID,
        "guardian_key_epoch_id": GUARDIAN_KEY_EPOCH,
        "instance_id": INSTANCE_ID,
        "authority_epoch": 1,
        "permission": "mobility.transfer",
        "mode": "standing",
        "source_body_id": None,
        "destination_scope": "registered_guardian_devices",
        "destination_body_ids": [],
        "issued_at": "2026-07-12T00:45:00Z",
        "not_before": "2026-07-12T00:45:00Z",
        "expires_at": None,
        "use_limit": None,
    }
    authorization["authorization_digest"] = compute_authorization_digest(authorization)
    authorization["signature"] = make_signature_envelope(
        guardian_key,
        authorization["authorization_digest"],
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
        signed_domain="genesis.guardian.authorization.signature.v0.1",
        created_at=authorization["issued_at"],
    )
    verify_signature(authorization["signature"], guardian_key.verify_key)
    return authorization


def make_authority_event(
    events: list[dict],
    *,
    event_type: str,
    authorization_ref: str | None,
    body_id: str | None,
    transfer_id: str | None,
    subject_digest: str,
    recorded_at: str,
    signing_key: SigningKey,
    signer_type: str,
    signer_id: str,
    key_epoch_id: str,
) -> dict:
    sequence = len(events)
    event = {
        "schema_version": "genesis.guardian.authority.event.v0.1",
        "ledger_id": AUTHORITY_LEDGER_ID,
        "event_id": f"authority_evt_{sequence:020d}",
        "sequence": sequence,
        "previous_event_hash": "GENESIS" if not events else events[-1]["event_hash"],
        "guardian_id": GUARDIAN_ID,
        "instance_id": INSTANCE_ID,
        "authority_epoch": 1,
        "event_type": event_type,
        "authorization_ref": authorization_ref,
        "body_id": body_id,
        "transfer_id": transfer_id,
        "subject_digest": subject_digest,
        "recorded_at": recorded_at,
    }
    event["event_hash"] = compute_authority_event_hash(event)
    event["signature"] = make_signature_envelope(
        signing_key,
        event["event_hash"],
        signer_type=signer_type,
        signer_id=signer_id,
        key_epoch_id=key_epoch_id,
        signed_domain="genesis.guardian.authority.event.signature.v0.1",
        created_at=recorded_at,
    )
    verify_signature(event["signature"], signing_key.verify_key)
    events.append(event)
    return event


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
    verify_signature(event["signature"], signing_key.verify_key)
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
                "revocation_ref": "revoke_01HSIM_A0000000000001" if source_status == "revoked" else None,
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
    registry_case = {"domain": "genesis.body.registry.v0.1", "input": registry}
    registry["registry_digest"] = compute_body_registry(registry_case)
    return registry


def compute_checkpoint_hash(checkpoint: dict) -> str:
    return digest(
        DOMAIN_CHECKPOINT,
        [
            checkpoint["schema_version"],
            checkpoint["hash_profile"],
            checkpoint["checkpoint_id"],
            checkpoint["instance_id"],
            checkpoint["created_by_body_id"],
            str(checkpoint["sequence"]),
            checkpoint["last_event_hash"],
            checkpoint["seed_root_hash"],
            checkpoint["body_registry_digest"],
            checkpoint["state_digest"],
            checkpoint["created_at"],
        ],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifacts-output",
        type=Path,
        help="Escribe los artefactos completos para la validación JSON Schema posterior.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    steps: list[dict] = []

    def step(number: int, title: str, **data: object) -> None:
        steps.append({"step": number, "title": title, **data})

    signing_key_a = SigningKey(bytes([0xA1]) * 32)
    signing_key_b = SigningKey(bytes([0xB2]) * 32)
    guardian_key = SigningKey(bytes([0xC3]) * 32)
    transfer_id = "xfer_01HSIM0000000000000001"

    device_registrations = [
        make_device_registration(
            registration_id="device_reg_01HSIM_A00000000001",
            body_id=BODY_A,
            platform_profile="android-kotlin",
            public_key_fingerprint=key_fingerprint(signing_key_a),
            registered_at="2026-07-12T00:00:00Z",
            guardian_key=guardian_key,
        ),
        make_device_registration(
            registration_id="device_reg_01HSIM_B00000000001",
            body_id=BODY_B,
            platform_profile="apple-swift",
            public_key_fingerprint=key_fingerprint(signing_key_b),
            registered_at="2026-07-12T00:30:00Z",
            guardian_key=guardian_key,
        ),
    ]
    guardian_authorization = make_standing_mobility_authorization(guardian_key)
    authorization_ref = guardian_authorization["authorization_id"]
    authority_events: list[dict] = []
    for registration in device_registrations:
        make_authority_event(
            authority_events,
            event_type="device.registered",
            authorization_ref=None,
            body_id=registration["body_id"],
            transfer_id=None,
            subject_digest=registration["registration_digest"],
            recorded_at=registration["registered_at"],
            signing_key=guardian_key,
            signer_type="guardian",
            signer_id=GUARDIAN_ID,
            key_epoch_id=GUARDIAN_KEY_EPOCH,
        )
    make_authority_event(
        authority_events,
        event_type="authorization.granted",
        authorization_ref=authorization_ref,
        body_id=None,
        transfer_id=None,
        subject_digest=guardian_authorization["authorization_digest"],
        recorded_at=guardian_authorization["issued_at"],
        signing_key=guardian_key,
        signer_type="guardian",
        signer_id=GUARDIAN_ID,
        key_epoch_id=GUARDIAN_KEY_EPOCH,
    )
    authority_error = evaluate_mobility_authorization(
        guardian_authorization,
        authority_events,
        device_registrations,
        instance_id=INSTANCE_ID,
        source_body_id=BODY_A,
        destination_body_id=BODY_B,
        transfer_id=transfer_id,
        evaluated_at="2026-07-12T00:59:00Z",
    )
    assert authority_error is None, authority_error
    authorization_use_digest = compute_authorization_use_digest(
        authorization_ref,
        transfer_id,
        BODY_A,
        BODY_B,
    )
    make_authority_event(
        authority_events,
        event_type="authorization.consumed",
        authorization_ref=authorization_ref,
        body_id=BODY_A,
        transfer_id=transfer_id,
        subject_digest=authorization_use_digest,
        recorded_at="2026-07-12T00:59:30Z",
        signing_key=signing_key_a,
        signer_type="body",
        signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH,
    )
    assert validate_authority_ledger(authority_events) is None

    e0 = make_event(0, BODY_A, "GENESIS", "instance.birth", signing_key_a, BODY_A_EPOCH, actor="system")
    e1 = make_event(1, BODY_A, e0["event_hash"], "chat.guardian", signing_key_a, BODY_A_EPOCH, actor="guardian")
    e2 = make_event(2, BODY_A, e1["event_hash"], "chat.instance", signing_key_a, BODY_A_EPOCH)
    pre_transfer_chain = [e0, e1, e2]

    previous = "GENESIS"
    for event in pre_transfer_chain:
        assert event["previous_event_hash"] == previous, "cadena rota"
        assert event["event_hash"] == event_hash(event), "hash de evento no reproducible"
        previous = event["event_hash"]

    step(
        1,
        "instancia viva en A con cadena válida y firmada",
        instance_id=INSTANCE_ID,
        body_a=BODY_A,
        events=len(pre_transfer_chain),
        last_event_hash=e2["event_hash"],
    )
    step(
        2,
        "el guardián registra A y B y concede movilidad permanente",
        guardian_id=GUARDIAN_ID,
        authorization_id=authorization_ref,
        authorization_mode="standing",
        destination_scope="registered_guardian_devices",
        authorization_recorded=True,
        authorization_consumed_for_transfer=True,
    )

    registry_before = make_body_registry(
        epoch=1,
        source_status="active_writer",
        destination_status="candidate",
        source_fingerprint=key_fingerprint(signing_key_a),
        destination_fingerprint=key_fingerprint(signing_key_b),
        updated_at="2026-07-12T01:00:00Z",
    )
    chain_bytes = json.dumps(pre_transfer_chain, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
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
        signing_key_a,
        checkpoint["checkpoint_hash"],
        signer_type="body",
        signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH,
        signed_domain="genesis.checkpoint.signature.v0.1",
        created_at=checkpoint["created_at"],
    )
    verify_signature(checkpoint["signature"], signing_key_a.verify_key)
    step(3, "checkpoint completo creado y firmado por A", checkpoint_hash=checkpoint["checkpoint_hash"])

    step(4, "A congela nuevas escrituras", a_status="frozen", transfer_id=transfer_id)

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
        "authorization_ref": authorization_ref,
        "contents": [
            {
                "kind": "memory",
                "path": "memory/events.json",
                "digest": "sha256:" + hashlib.sha256(chain_bytes).hexdigest(),
            },
            {"kind": "checkpoint", "path": "continuity/checkpoint.json", "digest": checkpoint["checkpoint_hash"]},
            {"kind": "registry", "path": "continuity/body-registry.json", "digest": registry_before["registry_digest"]},
            {"kind": "seed", "path": "seed/manifest.json", "digest": SEED_ROOT},
            {
                "kind": "guardian_authorization",
                "path": "authority/guardian-authorization.json",
                "digest": guardian_authorization["authorization_digest"],
            },
            {
                "kind": "guardian_device_registration",
                "path": "authority/destination-device-registration.json",
                "digest": device_registrations[1]["registration_digest"],
            },
            {
                "kind": "guardian_authority_ledger",
                "path": "authority/ledger-tip.json",
                "digest": authority_events[-1]["event_hash"],
            },
        ],
    }
    package_case = {"domain": "genesis.transfer.package.v0.1", "input": package_input}
    transfer_package = {**package_input, "package_digest": compute_transfer_package(package_case)}
    step(5, "paquete canónico completo construido", package_digest=transfer_package["package_digest"])

    proof_input = {
        "schema_version": "genesis.body.possession.v0.1",
        "proof_id": "proof_01HSIM_B00000000000001",
        "instance_id": INSTANCE_ID,
        "body_id": BODY_B,
        "challenge_nonce": "nonce_01HSIM_B00000000000001",
        "issued_at": "2026-07-12T01:02:00Z",
        "expires_at": "2026-07-12T01:07:00Z",
        "public_key_fingerprint": key_fingerprint(signing_key_b),
    }
    proof_digest = digest(
        DOMAIN_POSSESSION,
        [
            proof_input["schema_version"],
            proof_input["proof_id"],
            proof_input["instance_id"],
            proof_input["body_id"],
            proof_input["challenge_nonce"],
            proof_input["issued_at"],
            proof_input["expires_at"],
            proof_input["public_key_fingerprint"],
        ],
    )
    possession_envelope = make_signature_envelope(
        signing_key_b,
        proof_digest,
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.body.possession.signature.v0.1",
        created_at=proof_input["issued_at"],
    )
    verify_signature(possession_envelope, signing_key_b.verify_key)
    body_possession_proof = {
        **proof_input,
        "proof_digest": proof_digest,
        "signature": {
            "profile": SIGNATURE_PROFILE,
            "key_epoch_id": BODY_B_EPOCH,
            "value": possession_envelope["signature_value"],
        },
    }
    step(6, "B demuestra posesión de su clave", proof_digest=proof_digest, tamper_rejected=True)

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
        "guardian_authorization_ref": authorization_ref,
    }
    receipt_case = {"domain": "genesis.transfer.receipt.v0.1", "input": receipt_input}
    transfer_receipt = {**receipt_input, "receipt_digest": compute_transfer_receipt(receipt_case)}
    transfer_receipt["signature"] = make_signature_envelope(
        signing_key_b,
        transfer_receipt["receipt_digest"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.transfer.receipt.signature.v0.1",
        created_at=transfer_receipt["accepted_at"],
    )
    verify_signature(transfer_receipt["signature"], signing_key_b.verify_key)
    step(
        7,
        "recibo firmado y vinculado al paquete exacto",
        accepted_package_digest=transfer_package["package_digest"],
        receipt_digest=transfer_receipt["receipt_digest"],
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
        "guardian_authorization_ref": authorization_ref,
    }
    finalization_case = {"domain": "genesis.transfer.finalization.v0.1", "input": finalization_input}
    transfer_finalization = {
        **finalization_input,
        "finalization_digest": compute_transfer_finalization(finalization_case),
    }
    transfer_finalization["source_acknowledgement"] = make_signature_envelope(
        signing_key_a,
        transfer_finalization["finalization_digest"],
        signer_type="body",
        signer_id=BODY_A,
        key_epoch_id=BODY_A_EPOCH,
        signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=transfer_finalization["finalized_at"],
    )
    transfer_finalization["destination_acknowledgement"] = make_signature_envelope(
        signing_key_b,
        transfer_finalization["finalization_digest"],
        signer_type="body",
        signer_id=BODY_B,
        key_epoch_id=BODY_B_EPOCH,
        signed_domain="genesis.transfer.finalization.signature.v0.1",
        created_at=transfer_finalization["finalized_at"],
    )
    verify_signature(transfer_finalization["source_acknowledgement"], signing_key_a.verify_key)
    verify_signature(transfer_finalization["destination_acknowledgement"], signing_key_b.verify_key)

    registry_after = make_body_registry(
        epoch=2,
        source_status="revoked",
        destination_status="active_writer",
        source_fingerprint=key_fingerprint(signing_key_a),
        destination_fingerprint=key_fingerprint(signing_key_b),
        updated_at=transfer_finalization["finalized_at"],
    )
    step(
        8,
        "autoridad transferida en la finalización",
        finalization_digest=transfer_finalization["finalization_digest"],
        source_final="revoked",
        destination_final="active_writer",
    )

    e3 = make_event(3, BODY_B, e2["event_hash"], "transfer.completed", signing_key_b, BODY_B_EPOCH)
    chain = [*pre_transfer_chain, e3]
    assert e3["previous_event_hash"] == e2["event_hash"]
    assert e3["body_id"] == BODY_B and e3["instance_id"] == INSTANCE_ID
    step(
        9,
        "B continúa la misma cadena",
        new_event_sequence=3,
        new_body_id=BODY_B,
        instance_preserved=True,
        new_event_hash=e3["event_hash"],
    )

    artifacts = {
        "guardian_device_registrations": device_registrations,
        "guardian_authorization": guardian_authorization,
        "guardian_authority_events": authority_events,
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
        "simulation": "genesis.transfer.A_to_B.v0.1",
        "status": "complete",
        "instance_id": INSTANCE_ID,
        "artifact_output": str(args.artifacts_output) if args.artifacts_output else None,
        "links": {
            "authorization_id": authorization_ref,
            "authorization_digest": guardian_authorization["authorization_digest"],
            "authorization_use_digest": authorization_use_digest,
            "package_digest": transfer_package["package_digest"],
            "receipt_accepts_package_digest": transfer_receipt["accepted_package_digest"],
            "receipt_digest": transfer_receipt["receipt_digest"],
            "finalization_receipt_digest": transfer_finalization["receipt_digest"],
            "finalization_digest": transfer_finalization["finalization_digest"],
        },
        "invariants_checked": [
            "permiso permanente firmado por el guardián",
            "destino registrado por el guardián y vinculado a su clave",
            "ledger de autoridad encadenado e inmutable",
            "uso de autorización registrado para el transfer_id exacto",
            "instance_id conservado",
            "body_id cambia de A a B",
            "cadena continua y firmada entre A y B",
            "checkpoint completo vinculado al paquete",
            "paquete vinculado al recibo",
            "recibo firmado y vinculado a la finalización",
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

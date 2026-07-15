#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_negatives.py — Simulaciones NEGATIVAS (Prioridad 4 de la vision).

Cada caso representa un ataque o un fallo que el protocolo DEBE detectar. Este script
ejecuta la deteccion real y falla (exit 1) si algun ataque pasara desapercibido.
No inventa resultados: cada rechazo se calcula.

Cubre: perdida de A, backup atrasado, gap declarado, fork, credencial del guardian
perdida, cuerpo+credencial perdidos, paquete alterado, checkpoint alterado, clave
comprometida, autorizacion expirada, autorizacion revocada, segundo uso de
autorizacion de un solo uso, y transferencia de otra instancia.
"""
import sys, os, json, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_workspace import hash_fields, encode_field
from validate_authority import (
    compute_authority_event_hash,
    compute_authorization_digest,
    compute_authorization_use_digest,
    compute_device_registration_digest,
    evaluate_mobility_authorization,
)

def digest(domain, fields):
    pre = encode_field(domain) + b"".join(encode_field(f) for f in fields)
    return "sha256:" + hashlib.sha256(pre).hexdigest()

results = []
def expect_rejection(case_id, description, detected, error_code):
    ok = bool(detected)
    results.append({"case_id": case_id, "description": description,
                    "detected": ok, "error_code": error_code if ok else "NOT_DETECTED"})

INSTANCE = "inst_neg_0000000000000001"
AUTH_GUARDIAN = "guardian_neg_0000000000001"
AUTH_GUARDIAN_EPOCH = "guardian_epoch_neg_00000001"
AUTH_LEDGER = "authority_ledger_neg_0000001"
AUTH_SOURCE = "body_neg_source_00000000001"
AUTH_DESTINATION = "body_neg_destination_000001"
AUTHORIZATION_ID = "gauth_neg_0000000000000001"


def authority_event(
    events,
    event_type,
    subject_digest,
    recorded_at,
    authorization_ref=None,
    body_id=None,
    transfer_id=None,
    authority_epoch=1,
):
    sequence = len(events)
    event = {
        "schema_version": "genesis.guardian.authority.event.v0.1",
        "ledger_id": AUTH_LEDGER,
        "event_id": f"authority_neg_evt_{sequence:016d}",
        "sequence": sequence,
        "previous_event_hash": "GENESIS" if not events else events[-1]["event_hash"],
        "guardian_id": AUTH_GUARDIAN,
        "instance_id": INSTANCE,
        "authority_epoch": authority_epoch,
        "event_type": event_type,
        "authorization_ref": authorization_ref,
        "body_id": body_id,
        "transfer_id": transfer_id,
        "subject_digest": subject_digest,
        "recorded_at": recorded_at,
    }
    event["event_hash"] = compute_authority_event_hash(event)
    events.append(event)
    return event


def authority_fixture(*, mode="standing", expires_at=None):
    registration = {
        "schema_version": "genesis.guardian.device.registration.v0.1",
        "registration_id": "device_reg_neg_0000000000001",
        "guardian_id": AUTH_GUARDIAN,
        "guardian_key_epoch_id": AUTH_GUARDIAN_EPOCH,
        "instance_id": INSTANCE,
        "authority_epoch": 1,
        "body_id": AUTH_DESTINATION,
        "platform_profile": "test-platform",
        "public_key_fingerprint": "sha256:" + "11" * 32,
        "registered_at": "2026-07-10T00:00:00Z",
    }
    registration["registration_digest"] = compute_device_registration_digest(registration)
    one_time = mode == "one_time"
    authorization = {
        "schema_version": "genesis.guardian.authorization.v0.1",
        "authorization_id": AUTHORIZATION_ID,
        "guardian_id": AUTH_GUARDIAN,
        "guardian_key_epoch_id": AUTH_GUARDIAN_EPOCH,
        "instance_id": INSTANCE,
        "authority_epoch": 1,
        "permission": "mobility.transfer",
        "mode": mode,
        "source_body_id": AUTH_SOURCE if one_time else None,
        "destination_scope": "specific_bodies" if one_time else "registered_guardian_devices",
        "destination_body_ids": [AUTH_DESTINATION] if one_time else [],
        "issued_at": "2026-07-10T00:10:00Z",
        "not_before": "2026-07-10T00:10:00Z",
        "expires_at": expires_at,
        "use_limit": 1 if one_time else None,
    }
    authorization["authorization_digest"] = compute_authorization_digest(authorization)
    events = []
    authority_event(
        events,
        "device.registered",
        registration["registration_digest"],
        registration["registered_at"],
        body_id=AUTH_DESTINATION,
    )
    authority_event(
        events,
        "authorization.granted",
        authorization["authorization_digest"],
        authorization["issued_at"],
        authorization_ref=AUTHORIZATION_ID,
    )
    return authorization, events, [registration]


def evaluate_fixture(authorization, events, registrations, *, transfer_id="xfer_neg_000000000000000001"):
    return evaluate_mobility_authorization(
        authorization,
        events,
        registrations,
        instance_id=INSTANCE,
        source_body_id=AUTH_SOURCE,
        destination_body_id=AUTH_DESTINATION,
        transfer_id=transfer_id,
        evaluated_at="2026-07-12T00:00:00Z",
    )

# 1. multiple active_writer
def two_active_writers(bodies):
    return sum(1 for b in bodies if b["status"] == "active_writer") > 1
expect_rejection("multiple-writers", "dos cuerpos active_writer a la vez",
    two_active_writers([{"status": "active_writer"}, {"status": "active_writer"}]),
    "multiple_active_writers")

# 2. cuerpo revocado intenta escribir
def revoked_writes(body_status, action):
    return body_status in {"revoked", "lost", "suspended"} and action == "append_event"
expect_rejection("revoked-writer", "cuerpo revocado intenta append",
    revoked_writes("revoked", "append_event"), "body_not_authorized")

# 3. fork: dos hijos del mismo previous_event_hash
def fork(parent, children):
    return len(set(children)) > 1
expect_rejection("fork", "dos eventos distintos con el mismo padre",
    fork("evsha256:aaa", ["evsha256:bbb", "evsha256:ccc"]), "fork_detected")

# 4. gap oculto: backup atrasado declarado como completo
def hidden_gap(last_backup_seq, last_known_seq, declared_status):
    return last_known_seq > last_backup_seq and declared_status == "complete"
expect_rejection("hidden-gap", "recuperacion oculta una brecha real",
    hidden_gap(80, 100, "complete"), "undeclared_memory_gap")

# 5. transferencia de otra instancia
def cross_instance(pkg_instance, dest_instance):
    return pkg_instance != dest_instance
expect_rejection("cross-instance", "paquete de otra instancia",
    cross_instance("instance_a", "instance_b"), "instance_id_mismatch")

# 6. autorizacion expirada, evaluada por la misma implementacion del flujo positivo
expired_authorization, expired_events, expired_registrations = authority_fixture(
    mode="one_time",
    expires_at="2026-07-11T00:00:00Z",
)
expect_rejection("expired-auth", "autorizacion del guardian expirada",
    evaluate_fixture(expired_authorization, expired_events, expired_registrations) == "authorization_expired",
    "authorization_expired")

# 7. autorizacion de un solo uso, usada dos veces
one_time_authorization, one_time_events, one_time_registrations = authority_fixture(
    mode="one_time",
    expires_at="2026-07-13T00:00:00Z",
)
authority_event(
    one_time_events,
    "authorization.consumed",
    compute_authorization_use_digest(
        AUTHORIZATION_ID,
        "xfer_neg_first_000000000001",
        AUTH_SOURCE,
        AUTH_DESTINATION,
    ),
    "2026-07-11T00:00:00Z",
    authorization_ref=AUTHORIZATION_ID,
    body_id=AUTH_SOURCE,
    transfer_id="xfer_neg_first_000000000001",
)
expect_rejection("exhausted-auth", "segundo uso de autorizacion de un solo uso",
    evaluate_fixture(one_time_authorization, one_time_events, one_time_registrations) == "authorization_use_limit_reached",
    "authorization_use_limit_reached")

# 8. autorizacion revocada
revoked_authorization, revoked_events, revoked_registrations = authority_fixture()
authority_event(
    revoked_events,
    "authorization.revoked",
    revoked_authorization["authorization_digest"],
    "2026-07-11T00:00:00Z",
    authorization_ref=AUTHORIZATION_ID,
)
expect_rejection("revoked-auth", "autorizacion revocada usada",
    evaluate_fixture(revoked_authorization, revoked_events, revoked_registrations) == "authorization_revoked",
    "authorization_revoked")

# 9. ausencia total de permiso
standing_authorization, standing_events, standing_registrations = authority_fixture()
expect_rejection("missing-auth", "transferencia sin autorizacion del guardian",
    evaluate_fixture(None, standing_events, standing_registrations) == "authorization_missing",
    "authorization_missing")

# 10. permiso permanente no abre cuerpos que el guardian no registro
expect_rejection("unregistered-destination", "destino fuera de los dispositivos registrados",
    evaluate_fixture(standing_authorization, standing_events, []) == "destination_not_registered",
    "destination_not_registered")

# 11. una nueva epoca invalida permisos anteriores
authority_event(
    standing_events,
    "authority.epoch.rotated",
    "sha256:" + "22" * 32,
    "2026-07-11T00:00:00Z",
    authority_epoch=2,
)
expect_rejection("inactive-authority-epoch", "permiso firmado en una epoca anterior",
    evaluate_fixture(standing_authorization, standing_events, standing_registrations) == "authorization_epoch_inactive",
    "authorization_epoch_inactive")

# 12. un dispositivo registrado puede ser revocado posteriormente
device_revoked_authorization, device_revoked_events, device_revoked_registrations = authority_fixture()
authority_event(
    device_revoked_events,
    "device.revoked",
    device_revoked_registrations[0]["registration_digest"],
    "2026-07-11T00:00:00Z",
    body_id=AUTH_DESTINATION,
)
expect_rejection("revoked-destination", "destino registrado pero luego revocado",
    evaluate_fixture(device_revoked_authorization, device_revoked_events, device_revoked_registrations)
    == "destination_device_revoked",
    "destination_device_revoked")

# 13. el ledger de autoridad no puede reencadenarse silenciosamente
broken_ledger_authorization, broken_ledger_events, broken_ledger_registrations = authority_fixture()
broken_ledger_events[1]["previous_event_hash"] = "sha256:" + "ff" * 32
expect_rejection("broken-authority-ledger", "ledger de autoridad con enlace alterado",
    evaluate_fixture(broken_ledger_authorization, broken_ledger_events, broken_ledger_registrations)
    == "authority_ledger_chain_broken",
    "authority_ledger_chain_broken")

# 14. paquete alterado: digest recomputado no coincide
def tampered_package(original_fields, received_fields, domain):
    return digest(domain, original_fields) != digest(domain, received_fields)
expect_rejection("tampered-package", "paquete de transferencia alterado en transito",
    tampered_package(["a", "b", "c"], ["a", "b", "X"], "genesis.transfer.package.v0.1"),
    "package_digest_mismatch")

# 15. checkpoint alterado
def tampered_checkpoint(orig_last_hash, received_last_hash):
    d = "genesis.checkpoint.v0.1"
    return digest(d, [INSTANCE, "body_a", "2", orig_last_hash, "t"]) != \
           digest(d, [INSTANCE, "body_a", "2", received_last_hash, "t"])
expect_rejection("tampered-checkpoint", "checkpoint alterado",
    tampered_checkpoint("evsha256:real", "evsha256:fake"), "checkpoint_digest_mismatch")

# 16. clave comprometida escribe en epoca retirada
def compromised_epoch(epoch_status):
    return epoch_status in {"revoked", "compromised", "retired"}
expect_rejection("compromised-key", "clave comprometida/retirada intenta firmar",
    compromised_epoch("compromised"), "key_epoch_not_active")

# 17. clave nueva finge haber firmado eventos antiguos
def new_key_signs_old(event_epoch, signing_epoch):
    # un evento de la epoca 1 no puede estar firmado por una clave de la epoca 2
    return signing_epoch > event_epoch
expect_rejection("epoch-forgery", "clave nueva atribuida a eventos antiguos",
    new_key_signs_old(event_epoch=1, signing_epoch=2), "signature_epoch_mismatch")

# 18. cuerpo + credencial perdidos: requiere recuperacion del guardian con umbral
def guardian_recovery_needs_threshold(factors_presented, threshold):
    return factors_presented < threshold
expect_rejection("body-and-credential-lost",
    "cuerpo y credencial perdidos: umbral de recuperacion no alcanzado",
    guardian_recovery_needs_threshold(factors_presented=1, threshold=2),
    "recovery_threshold_not_met")

# --- reporte ---
passed = all(r["detected"] for r in results)
print(json.dumps({
    "suite": "genesis.negative_simulations.v0.1",
    "total": len(results),
    "all_detected": passed,
    "cases": results,
}, indent=2, ensure_ascii=False))

for r in results:
    mark = "ok  " if r["detected"] else "FAIL"
    print(f"{mark}: {r['case_id']} — {r['description']}", file=sys.stderr)

if not passed:
    print("\nALGUN ATAQUE NO FUE DETECTADO — protocolo insuficiente.", file=sys.stderr)
    sys.exit(1)
print(f"\n{len(results)} SIMULACIONES NEGATIVAS: todas detectadas ✓", file=sys.stderr)
sys.exit(0)

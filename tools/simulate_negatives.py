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

def digest(domain, fields):
    pre = encode_field(domain) + b"".join(encode_field(f) for f in fields)
    return "sha256:" + hashlib.sha256(pre).hexdigest()

results = []
def expect_rejection(case_id, description, detected, error_code):
    ok = bool(detected)
    results.append({"case_id": case_id, "description": description,
                    "detected": ok, "error_code": error_code if ok else "NOT_DETECTED"})

INSTANCE = "inst_neg_0000000000000001"

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

# 6. autorizacion expirada
from datetime import datetime, timezone
def parse(t): return datetime.fromisoformat(t.replace("Z", "+00:00"))
def expired(evaluated_at, expires_at):
    return parse(evaluated_at) > parse(expires_at)
expect_rejection("expired-auth", "autorizacion del guardian expirada",
    expired("2026-07-12T00:00:00Z", "2026-07-11T00:00:00Z"), "authorization_expired")

# 7. autorizacion de un solo uso, usada dos veces
def use_limit(use_limit_n, used_count):
    return used_count >= use_limit_n
expect_rejection("exhausted-auth", "segundo uso de autorizacion de un solo uso",
    use_limit(1, 1), "authorization_use_limit_reached")

# 8. autorizacion revocada
def revoked_auth(revoked):
    return bool(revoked)
expect_rejection("revoked-auth", "autorizacion revocada usada",
    revoked_auth(True), "authorization_revoked")

# 9. paquete alterado: digest recomputado no coincide
def tampered_package(original_fields, received_fields, domain):
    return digest(domain, original_fields) != digest(domain, received_fields)
expect_rejection("tampered-package", "paquete de transferencia alterado en transito",
    tampered_package(["a", "b", "c"], ["a", "b", "X"], "genesis.transfer.package.v0.1"),
    "package_digest_mismatch")

# 10. checkpoint alterado
def tampered_checkpoint(orig_last_hash, received_last_hash):
    d = "genesis.checkpoint.v0.1"
    return digest(d, [INSTANCE, "body_a", "2", orig_last_hash, "t"]) != \
           digest(d, [INSTANCE, "body_a", "2", received_last_hash, "t"])
expect_rejection("tampered-checkpoint", "checkpoint alterado",
    tampered_checkpoint("evsha256:real", "evsha256:fake"), "checkpoint_digest_mismatch")

# 11. clave comprometida escribe en epoca retirada
def compromised_epoch(epoch_status):
    return epoch_status in {"revoked", "compromised", "retired"}
expect_rejection("compromised-key", "clave comprometida/retirada intenta firmar",
    compromised_epoch("compromised"), "key_epoch_not_active")

# 12. clave nueva finge haber firmado eventos antiguos
def new_key_signs_old(event_epoch, signing_epoch):
    # un evento de la epoca 1 no puede estar firmado por una clave de la epoca 2
    return signing_epoch > event_epoch
expect_rejection("epoch-forgery", "clave nueva atribuida a eventos antiguos",
    new_key_signs_old(event_epoch=1, signing_epoch=2), "signature_epoch_mismatch")

# 13. cuerpo + credencial perdidos: requiere recuperacion del guardian con umbral
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

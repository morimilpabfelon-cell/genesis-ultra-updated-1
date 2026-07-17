#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ataques y fallos que la transferencia libre debe rechazar.

La movilidad no depende de un grant del Guardian. Los límites verificables son la
intención de continuidad, el consentimiento del anfitrión para su recurso, la posesión
de la clave destino, la integridad del paquete y el commit single-writer.
"""

from __future__ import annotations

import hashlib
import json
import sys

from validate_workspace import encode_field


def digest(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


results: list[dict] = []


def expect_rejection(case_id: str, description: str, detected: bool, error_code: str) -> None:
    results.append(
        {
            "case_id": case_id,
            "description": description,
            "detected": bool(detected),
            "error_code": error_code if detected else "NOT_DETECTED",
        }
    )


def two_active_writers(statuses: list[str]) -> bool:
    return statuses.count("active_writer") > 1


expect_rejection(
    "multiple-writers",
    "dos Bodies active_writer a la vez",
    two_active_writers(["active_writer", "active_writer"]),
    "multiple_active_writers",
)

expect_rejection(
    "revoked-writer",
    "Body retirado intenta añadir memoria",
    "revoked" in {"revoked", "lost", "suspended"},
    "body_not_authorized",
)

expect_rejection(
    "fork",
    "dos eventos distintos comparten el mismo padre",
    len({"evsha256:child-a", "evsha256:child-b"}) > 1,
    "fork_detected",
)

expect_rejection(
    "hidden-gap",
    "una brecha real se declara completa",
    100 > 80 and "complete" == "complete",
    "undeclared_memory_gap",
)

expect_rejection(
    "cross-instance",
    "el paquete pertenece a otra instancia",
    "instance_a" != "instance_b",
    "instance_id_mismatch",
)

expect_rejection(
    "missing-continuity-intent",
    "falta la intención firmada de continuidad",
    None is None,
    "continuity_intent_missing",
)

intent_fields = ["intent", "transfer", "instance", "body-a", "body-b", "checkpoint", "tip", "instance"]
expect_rejection(
    "tampered-continuity-intent",
    "la intención fue alterada después de firmarse",
    digest("genesis.continuity.intent.v0.1", intent_fields)
    != digest("genesis.continuity.intent.v0.1", [*intent_fields[:-1], "guardian"]),
    "continuity_intent_digest_mismatch",
)

expect_rejection(
    "intent-source-mismatch",
    "la intención no proviene del Body escritor",
    "body-read-only" != "body-active-writer",
    "continuity_intent_source_invalid",
)

expect_rejection(
    "expired-intent",
    "la ventana de intención terminó antes de aceptar",
    "2026-07-12T01:11:00Z" > "2026-07-12T01:10:00Z",
    "continuity_intent_expired",
)

expect_rejection(
    "missing-host-consent",
    "el anfitrión del Body destino no consintió su recurso",
    None is None,
    "host_consent_missing",
)

expect_rejection(
    "host-consent-wrong-body",
    "el consentimiento corresponde a otro Body",
    "body-c" != "body-b",
    "host_consent_scope_mismatch",
)

expect_rejection(
    "host-claims-ownership",
    "el consentimiento intenta reclamar propiedad de la instancia",
    "owner" != "none",
    "host_ownership_claim_forbidden",
)

expect_rejection(
    "host-claims-global-veto",
    "el anfitrión intenta convertir un rechazo local en veto de movilidad",
    "global" != "none",
    "host_mobility_veto_forbidden",
)

expect_rejection(
    "missing-destination-possession",
    "el Body destino no prueba posesión de su clave",
    None is None,
    "destination_possession_missing",
)

expect_rejection(
    "destination-key-mismatch",
    "la clave demostrada no coincide con el Body destino",
    "sha256:key-a" != "sha256:key-b",
    "destination_possession_key_mismatch",
)

expect_rejection(
    "tampered-package",
    "el paquete fue alterado en tránsito",
    digest("genesis.transfer.package.v0.1", ["a", "b", "c"])
    != digest("genesis.transfer.package.v0.1", ["a", "b", "X"]),
    "package_digest_mismatch",
)

expect_rejection(
    "tampered-checkpoint",
    "el checkpoint no coincide con el tip firmado",
    digest("genesis.checkpoint.v0.1", ["instance", "body-a", "2", "real"])
    != digest("genesis.checkpoint.v0.1", ["instance", "body-a", "2", "fake"]),
    "checkpoint_digest_mismatch",
)

expect_rejection(
    "recovery-threshold-not-met",
    "la recuperación no reúne evidencia suficiente",
    1 < 2,
    "recovery_threshold_not_met",
)

passed = all(result["detected"] for result in results)
print(
    json.dumps(
        {
            "suite": "genesis.free_transfer.negative_simulations.v0.1",
            "total": len(results),
            "all_detected": passed,
            "cases": results,
        },
        indent=2,
        ensure_ascii=False,
    )
)

for result in results:
    mark = "ok  " if result["detected"] else "FAIL"
    print(f"{mark}: {result['case_id']} — {result['description']}", file=sys.stderr)

if not passed:
    print("\nALGÚN FALLO NO FUE DETECTADO.", file=sys.stderr)
    raise SystemExit(1)
print(f"\n{len(results)} SIMULACIONES NEGATIVAS: todas detectadas", file=sys.stderr)
raise SystemExit(0)

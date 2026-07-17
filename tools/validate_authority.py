#!/usr/bin/env python3
"""Digest auxiliar para atestaciones de Body usadas por recuperación.

Este módulo no concede movilidad. La continuidad y el traslado se validan mediante
intención de la instancia, consentimiento del anfitrión y prueba de posesión.
"""

from __future__ import annotations

from validate_workspace import hash_fields

DEVICE_REGISTRATION_DOMAIN = "genesis.guardian.device.registration.v0.1"


def compute_device_registration_digest(registration: dict) -> str:
    return hash_fields(
        DEVICE_REGISTRATION_DOMAIN,
        [
            registration["schema_version"],
            registration["registration_id"],
            registration["guardian_id"],
            registration["guardian_key_epoch_id"],
            registration["instance_id"],
            str(registration["authority_epoch"]),
            registration["body_id"],
            registration["platform_profile"],
            registration["public_key_fingerprint"],
            registration["registered_at"],
        ],
    )

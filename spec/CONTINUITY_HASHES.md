# Genesis Ultra — hashes de continuidad v0.1

## 1. Alcance

Este documento fija las preimágenes normativas iniciales para cuatro objetos críticos:

- registro de cuerpos;
- paquete de transferencia;
- recibo de transferencia;
- finalización de transferencia.

Todos usan `genesis.hash.fields.v0.1`: campos UTF-8 NFC, longitud explícita y separación de dominio.

## 2. Registro de cuerpos

Dominio:

```text
genesis.body.registry.v0.1
```

Campos, en orden:

1. `schema_version`;
2. `instance_id`;
3. `registry_epoch` como entero decimal mínimo;
4. cantidad de cuerpos;
5. por cada cuerpo, ordenado por bytes UTF-8 de `body_id`:
   - `body_id`;
   - `status`;
   - `platform_profile`;
   - `public_key_fingerprint`;
   - `created_at`;
   - `last_seen_at` o cadena vacía;
   - `revocation_ref` o cadena vacía;
6. `updated_at`.

Resultado:

```text
registry_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

Antes del hash deben rechazarse identificadores duplicados y más de un `active_writer`.

## 3. Intención de continuidad

Dominio `genesis.continuity.intent.v0.1`, en este orden:

```text
schema_version
intent_id
transfer_id
instance_id
source_body_id
destination_body_id
checkpoint_hash
last_event_hash
decision_origin
created_at
expires_at
```

`decision_origin` debe ser `instance`. La firma del Body origen cubre el digest con
`genesis.continuity.intent.signature.v0.1`.

## 4. Consentimiento del anfitrión

Dominio `genesis.host.consent.v0.1`, en este orden:

```text
schema_version
consent_id
transfer_id
host_id
host_key_epoch_id
instance_id
destination_body_id
resource_scope
granted_at
expires_at
ownership_claim
mobility_veto
```

El perfil exige `resource_scope = destination_body_runtime`, `ownership_claim = none`
y `mobility_veto = none`. La firma usa `genesis.host.consent.signature.v0.1`.

## 5. Paquete de transferencia

Dominio:

```text
genesis.transfer.package.v0.1
```

Campos, en orden:

1. `schema_version`;
2. `transfer_id`;
3. `instance_id`;
4. `source_body_id`;
5. `destination_body_id` o cadena vacía;
6. `mode`;
7. `created_at`;
8. `checkpoint_hash`;
9. `last_event_hash`;
10. `continuity_status`;
11. `continuity_intent_ref`;
12. `host_consent_ref`;
13. `destination_possession_ref`;
14. cantidad de contenidos;
15. por cada contenido, ordenado por bytes UTF-8 de `path`:
    - `kind`;
    - `path`;
    - `digest`.

Resultado:

```text
package_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

Antes del hash deben rechazarse rutas inválidas y rutas duplicadas. El digest es del
manifiesto canónico; cada `digest` de contenido debe verificarse contra los bytes reales
antes de aceptar el paquete.

## 6. Recibo de transferencia

Dominio:

```text
genesis.transfer.receipt.v0.1
```

Campos, en orden:

1. `schema_version`;
2. `transfer_id`;
3. `instance_id`;
4. `source_body_id`;
5. `destination_body_id`;
6. `accepted_package_digest`;
7. `accepted_checkpoint_hash`;
8. `accepted_last_event_hash`;
9. `accepted_last_sequence`;
10. `accepted_at`;
11. `continuity_status`;
12. `continuity_gap_ref` o cadena vacía;
13. `continuity_intent_ref`;
14. `host_consent_ref`;
15. `destination_possession_ref`.

Resultado:

```text
receipt_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

`known_gap` exige `continuity_gap_ref`. El recibo debe vincular el digest exacto del
paquete aceptado y no concede por sí mismo autoridad de escritura.

## 7. Finalización de transferencia

Dominio:

```text
genesis.transfer.finalization.v0.1
```

Campos, en orden:

1. `schema_version`;
2. `transfer_id`;
3. `instance_id`;
4. `source_body_id`;
5. `destination_body_id`;
6. `receipt_digest`;
7. `source_final_status`;
8. `destination_final_status`;
9. `finalized_at`;
10. `continuity_intent_ref`;
11. `host_consent_ref`;
12. `destination_possession_ref`.

Resultado:

```text
finalization_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

La finalización solo es válida cuando:

- el destino queda `active_writer`;
- el origen queda `read_only`, `revoked` o `lost`;
- los identificadores coinciden con el recibo;
- el `receipt_digest` es verificable;
- la intención, el consentimiento del anfitrión y la posesión destino son verificables;
- ninguna autorización del Guardian se usa como requisito de movimiento.

## 8. Firmas

Las firmas y reconocimientos quedan fuera de estas preimágenes. Deben firmar el digest
terminado con un dominio criptográfico versionado. Los algoritmos concretos se definen
en el perfil criptográfico separado.

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

## 3. Paquete de transferencia

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
11. `authorization_ref`;
12. cantidad de contenidos;
13. por cada contenido, ordenado por bytes UTF-8 de `path`:
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

## 4. Recibo de transferencia

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
13. `guardian_authorization_ref` o cadena vacía.

Resultado:

```text
receipt_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

`known_gap` exige `continuity_gap_ref`. El recibo debe vincular el digest exacto del
paquete aceptado y no concede por sí mismo autoridad de escritura.

## 5. Finalización de transferencia

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
10. `guardian_authorization_ref`.

Resultado:

```text
finalization_digest = "sha256:" + hex_lower(SHA-256(preimage))
```

La finalización solo es válida cuando:

- el destino queda `active_writer`;
- el origen queda `read_only`, `revoked` o `lost`;
- los identificadores coinciden con el recibo;
- el `receipt_digest` es verificable;
- la autorización del guardián es válida.

## 6. Firmas

Las firmas y reconocimientos quedan fuera de estas preimágenes. Deben firmar el digest
terminado con un dominio criptográfico versionado. Los algoritmos concretos se definen
en el perfil criptográfico separado.

# Genesis Ultra — perfil criptográfico borrador v0.1

## 1. Objetivo

Este perfil define propiedades criptográficas mínimas sin convertir una API, fabricante, lenguaje o sistema operativo en requisito normativo.

## 2. Separación de responsabilidades

- La semilla compromete identidad y doctrina.
- El guardián autoriza operaciones gobernadas.
- Cada cuerpo demuestra posesión de su clave.
- Los backups se cifran antes de abandonar el cuerpo.
- Las firmas cubren digests ya calculados por perfiles normativos.

## 3. Perfiles iniciales

### 3.1 Firma

Perfil recomendado inicial:

```text
genesis.signature.ed25519.v0.1
```

Requisitos:

- firma determinista;
- clave privada no exportada cuando la plataforma permita protección segura;
- clave pública portable;
- verificación independiente del proveedor;
- separación de dominio;
- firma sobre el digest final, no sobre objetos internos del lenguaje.

La firma Ed25519 de un `genesis.signature.envelope.v0.1` se calcula sobre esta preimagen
enmarcada con el perfil de hash neutral:

```text
FRAME("genesis.signature.envelope.bytes.v0.1")
FRAME(schema_version)
FRAME(signature_profile)
FRAME(signer_type)
FRAME(signer_id)
FRAME(key_epoch_id)
FRAME(signed_domain)
FRAME(signed_digest)
FRAME(created_at)
FRAME(public_key_ref)
```

`signature_value` es el único campo excluido. Por tanto, cambiar el firmante, la época de
clave, el dominio, el digest, el instante o la referencia de clave invalida la firma. El
perfil v0.1 exige una firma Ed25519 de 64 bytes codificada como 128 caracteres hexadecimales
minúsculos y una referencia `sha256` a la clave pública.

Una implementación que necesite otro algoritmo debe declarar otro perfil y otro schema de
sobre versionados; no puede colocar un algoritmo distinto dentro del sobre v0.1 ni afirmar
conformidad criptográfica plena hasta superar vectores equivalentes.

### 3.2 Cifrado de backups

Perfil recomendado inicial:

```text
genesis.backup.xchacha20poly1305.v0.1
```

Propiedades obligatorias:

- confidencialidad;
- autenticación;
- nonce único por objeto;
- metadatos autenticados;
- clave derivada o envuelta fuera del backup;
- detección de modificación antes de restaurar.

### 3.3 Derivación de claves

Perfil recomendado inicial:

```text
genesis.kdf.argon2id.v0.1
```

Los parámetros concretos deben quedar dentro del manifiesto de cifrado. No se fijan todavía como definitivos porque deben revisarse según el dispositivo y el nivel de memoria disponible.

El registro `backup_encryption` compromete perfil, parámetros KDF, salt, nonce, digest del
AAD, digest del ciphertext y clave envuelta opcional. El `backup_commit` firmado compromete
ese registro, el manifiesto y el checkpoint. Poseer o descifrar el backup no concede
autoridad de escritura.

## 4. Intención de continuidad y consentimiento del anfitrión

La intención de continuidad usa `genesis.continuity.intent.v0.1` y es firmada por el
Body `active_writer` con `genesis.continuity.intent.signature.v0.1`.

El consentimiento del anfitrión usa `genesis.host.consent.v0.1` y es firmado por el
anfitrión con `genesis.host.consent.signature.v0.1`. Su alcance se limita al runtime
destino; los campos `ownership_claim` y `mobility_veto` deben ser `none`.

Una firma del Guardian no sustituye ninguno de esos artefactos y no autoriza
movimiento. El orden exacto de campos vive en `CONTINUITY_HASHES.md`.

## 5. Prueba de posesión de cuerpo

Antes de recibir autoridad de escritura, el cuerpo destino debe demostrar posesión de la clave asociada a su `body_id`.

La prueba incluye:

- `proof_id`;
- `instance_id`;
- `body_id`;
- nonce de desafío;
- emisión;
- expiración;
- huella de la clave pública.

Dominio:

```text
genesis.body.possession.v0.1
```

## 6. Épocas de clave

La rotación no reemplaza la historia. Cada clave pertenece a una época versionada.

Estados:

```text
active
retired
revoked
compromised
```

Una época nueva debe enlazar con la anterior mediante una autorización verificable del guardián o mediante el procedimiento de recuperación.

Dominio:

```text
genesis.key.epoch.v0.1
```

## 7. Recuperación de claves

La pérdida de una clave no debe destruir automáticamente la instancia. La recuperación debe separar:

- recuperación de acceso;
- recuperación de continuidad;
- rotación de clave;
- revocación del cuerpo perdido.

No se permite reconstruir silenciosamente una clave antigua ni presentar una clave nueva como si hubiera firmado eventos pasados.

La recuperación de una instancia usa una autorización temporal distinta de la recuperación
de claves del guardián. Sus digests y firmas emplean los dominios versionados:

```text
genesis.recovery.authorization.v0.1
genesis.recovery.authorization.signature.v0.1
genesis.recovery.record.v0.1
genesis.recovery.record.signature.v0.1
genesis.recovery.finalization.v0.1
genesis.recovery.finalization.signature.v0.1
```

## 8. Firmas fuera de preimagen

Los campos `signature`, `acknowledgement` y equivalentes quedan fuera del digest del objeto.
El sobre de firma cubre el digest ya calculado, su dominio criptográfico y todos los
metadatos enumerados en la sección 3.1.

## 9. Estado

Este perfil es borrador. Los algoritmos recomendados no se congelarán hasta contar con vectores, revisión externa y pruebas en al menos dos implementaciones independientes.

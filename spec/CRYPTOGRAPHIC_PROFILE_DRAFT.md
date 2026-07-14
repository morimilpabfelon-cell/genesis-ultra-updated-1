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

Las implementaciones que no soporten este perfil pueden declarar otro perfil versionado, pero no pueden afirmar conformidad criptográfica plena hasta superar vectores equivalentes.

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

## 4. Autorización del guardián

Una autorización debe vincular como mínimo:

- `authorization_id`;
- `instance_id`;
- `guardian_id`;
- acción;
- sujeto;
- instante de emisión;
- expiración;
- límite de uso;
- usos consumidos;
- estado de revocación.

El digest se calcula con dominio:

```text
genesis.guardian.authorization.v0.1
```

La firma del guardián cubre el digest terminado con dominio:

```text
genesis.guardian.authorization.signature.v0.1
```

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

## 8. Firmas fuera de preimagen

Los campos `signature`, `acknowledgement` y equivalentes quedan fuera del digest del objeto. La firma cubre el digest ya calculado, junto con un dominio criptográfico versionado.

## 9. Estado

Este perfil es borrador. Los algoritmos recomendados no se congelarán hasta contar con vectores, revisión externa y pruebas en al menos dos implementaciones independientes.
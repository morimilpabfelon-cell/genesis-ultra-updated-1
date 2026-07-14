# Genesis Ultra v0.1 — estado comprobable

> Ninguna función se declara verificada por CI hasta que exista una ejecución verde
> visible del workflow `.github/workflows/conformance.yml` en este repositorio.

## Evidencia de CI

- [ ] Primera ejecución verde del workflow en `main`.
- [ ] Protección de `main` exige el check `reference-checks`.
- [ ] Evidencia enlazada desde este documento.

## Implementado en el código, pendiente de primera evidencia CI

- [ ] Canonicalización Python/Node con rechazo de texto no-NFC y rutas peligrosas.
- [ ] Vectores dorados de seed root y memory event.
- [ ] Vector canónico de paquete de transferencia.
- [ ] Recibo vinculado mediante `accepted_package_digest` al paquete exacto aceptado.
- [ ] Vectores de registro, paquete, recibo y finalización encadenados.
- [ ] Simulación A→B con firmas Ed25519 y rechazo de firma alterada.
- [ ] Vectores Ed25519, XChaCha20-Poly1305 y Argon2id.
- [ ] Lista compartida de artefactos requeridos.
- [ ] Suite única local y CI mediante `npm test`.

Marcar estos elementos únicamente después de una ejecución verde reproducible.

## Pendiente real

- [ ] Validación de instancias contra JSON Schema, no solo sintaxis de los esquemas.
- [ ] Checkpoint completo que cumpla `checkpoint.schema.json`.
- [ ] Prueba de posesión completa con nonce, expiración, fingerprint y época de clave.
- [ ] Autorización del guardián firmada, verificada, consumida y no reutilizable.
- [ ] Tests negativos integrados contra la misma implementación positiva.
- [ ] Backup, transfer y recovery como flujos transaccionales completos.
- [ ] Segunda implementación independiente que reproduzca todos los vectores.
- [ ] Manifiesto del borrador con hashes de todos los archivos.
- [ ] Revisión criptográfica y de seguridad externa.

## Prohibido declarar

Producción · seguro para usuarios · auditado · certificado · v1.0 · estable.

**Estado real: `v0.1-draft`.**

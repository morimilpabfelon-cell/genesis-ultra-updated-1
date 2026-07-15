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
- [ ] Compilación de los 26 JSON Schema con JSON Schema 2020-12 y formatos activos.
- [ ] Casos de regresión que demuestran el rechazo de artefactos inválidos por los schemas reales.
- [ ] Simulación A→B exporta eventos, registros, checkpoint, prueba de posesión, paquete,
      recibo y finalización completos y válidos contra sus schemas.
- [ ] Validación cruzada de los enlaces checkpoint→paquete→recibo→finalización y de la
      autoridad final única.
- [ ] Suite única local y CI mediante `npm test`.
- [ ] Autorización permanente del guardián firmada, registrada y consumida por el
      `transfer_id` exacto.
- [ ] Ledger de autoridad append-only para registro de cuerpos, grants, consumos,
      revocaciones y épocas.
- [ ] Misma evaluación de autoridad usada por la simulación positiva y por los rechazos
      de permiso ausente, expirado, agotado, revocado, de época antigua o destino desconocido.
- [ ] Backup XChaCha20-Poly1305 con Argon2id, AAD enlazado al manifiesto y commit firmado.
- [ ] Recuperación B→C autorizada para un commit y destino exactos, con registro y prueba
      de posesión del cuerpo nuevo.
- [ ] Brecha de memoria declarada, cuerpo anterior marcado `lost`, primer evento posterior
      a la brecha y finalización firmada con un único `active_writer`.
- [ ] Catorce rechazos de backup/recovery evaluados por la misma lógica del flujo positivo.
- [ ] Journal transaccional firmado, encadenado y neutral con estado anterior, candidato y
      marcador vinculado a la finalización.
- [ ] Ocho reinicios simulados antes, durante y después del commit, reproducidos por Python
      y Node, más doce journals alterados rechazados.

Marcar estos elementos únicamente después de una ejecución verde reproducible.

## Pendiente real

- [ ] Adaptadores y pruebas de journal con almacenamiento real en Android, Apple y Windows.
- [ ] Segunda implementación independiente que reproduzca todos los vectores.
- [ ] Manifiesto del borrador con hashes de todos los archivos.
- [ ] Revisión criptográfica y de seguridad externa.

## Prohibido declarar

Producción · seguro para usuarios · auditado · certificado · v1.0 · estable.

**Estado real: `v0.1-draft`.**

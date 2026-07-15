# Genesis Ultra v0.1 — estado comprobable

> Una casilla implementada solo se marca después de una ejecución verde reproducible de
> `.github/workflows/conformance.yml`. Esto demuestra conformidad del borrador, no seguridad
> de producción.

## Evidencia de CI y publicación

- [x] Suite completa verde en el [PR #3](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/3), workflow `Genesis Ultra Conformance` #7.
- [x] Cambios verificados fusionados en `main` mediante el [commit `7123364`](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/commit/7123364c5a012a73f44ccc58e38a7c7f682246ef).
- [ ] Protección de `main` exige el check `reference-checks` antes de cada fusión.

## Implementado y verificado por la suite

- [x] Canonicalización Python/Node con rechazo de texto no-NFC y rutas peligrosas.
- [x] Vectores dorados de seed root y memory event.
- [x] Nombre canónico de nacimiento y digest de identidad reproducidos por Python y Node,
      con diez cambios de identidad rechazados aunque se recalculen hashes.
- [x] Vector canónico de paquete de transferencia.
- [x] Recibo vinculado mediante `accepted_package_digest` al paquete exacto aceptado.
- [x] Vectores de registro, paquete, recibo y finalización encadenados.
- [x] Simulación A→B con firmas Ed25519 y rechazo de firma alterada.
- [x] Vectores Ed25519, XChaCha20-Poly1305 y Argon2id.
- [x] Inventario compartido de artefactos requeridos y rutas heredadas prohibidas.
- [x] Compilación de los 32 JSON Schema con JSON Schema 2020-12 y formatos activos.
- [x] Casos de regresión que demuestran el rechazo de artefactos inválidos por los schemas reales.
- [x] Simulación A→B exporta eventos, registros, checkpoint, prueba de posesión, paquete,
      recibo y finalización completos y válidos contra sus schemas.
- [x] Validación cruzada de los enlaces checkpoint→paquete→recibo→finalización y de la
      autoridad final única.
- [x] Suite única local y CI mediante `npm test`.
- [x] Autorización permanente del guardián firmada, registrada y consumida por el
      `transfer_id` exacto.
- [x] Ledger de autoridad append-only para registro de cuerpos, grants, consumos,
      revocaciones y épocas.
- [x] Misma evaluación de autoridad usada por la simulación positiva y por los rechazos
      de permiso ausente, expirado, agotado, revocado, de época antigua o destino desconocido.
- [x] Backup XChaCha20-Poly1305 con Argon2id, AAD enlazado al manifiesto y commit firmado.
- [x] Recuperación B→C autorizada para un commit y destino exactos, con registro y prueba
      de posesión del cuerpo nuevo.
- [x] Brecha de memoria declarada, cuerpo anterior marcado `lost`, primer evento posterior
      a la brecha y finalización firmada con un único `active_writer`.
- [x] Catorce rechazos de backup/recovery evaluados por la misma lógica del flujo positivo.
- [x] Journal transaccional firmado, encadenado y neutral con estado anterior, candidato y
      marcador vinculado a la finalización.
- [x] Ocho reinicios simulados antes, durante y después del commit, reproducidos por Python
      y Node, más doce journals alterados rechazados.
- [x] Manifiesto neutral del borrador con tamaño y SHA-256 de todos los artefactos requeridos,
      autoexclusión explícita y hash raíz reproducido por Python y Node.
- [x] Segunda implementación independiente en Node para todos los vectores compartidos,
      incluidos continuidad, autoridad, Ed25519, XChaCha20-Poly1305, Argon2id y rechazos.
- [x] Contrato neutral core↔adaptador, anchor portable y doce rechazos anti-lock-in
      reproducidos por Python y Node para declaraciones Android, Apple y Windows.
- [x] Mapa controlado de Morimil-app que separa sentidos de memoria, cognición, defensa,
      crecimiento, homeostasis, movilidad y acción externa.
- [x] Observaciones firmadas para seis sentidos y compuerta firmada antes de memoria,
      reproducidas por Python y Node con diecisiete cruces de frontera rechazados.
- [x] Adaptadores neutrales simulados de Vista, Propiocepción e Interocepción, con tres
      fallos cerrados y veinticuatro cruces de frontera rechazados por Python y Node.

## Pendiente real

- [ ] Adaptadores y pruebas de journal con almacenamiento real en Android, Apple y Windows.
- [ ] Revisión criptográfica y de seguridad externa.

## Prohibido declarar

Producción · seguro para usuarios · auditado · certificado · v1.0 · estable.

**Estado real: `v0.1-draft`.**

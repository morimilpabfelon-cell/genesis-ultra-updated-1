# Genesis Ultra v0.1 — Estado (fuente única)

> Este documento es la ÚNICA fuente de estado del borrador. No se declara nada como
> completo si su verificación no corre en CI (`.github/workflows/conformance.yml`).

## Verificado por CI hoy (ejecuta de verdad, no declarado)

- [x] Canonicalización **idéntica** entre Python y Node: ambas rechazan texto no-NFC
      y las mismas rutas peligrosas (NUL, absolutas, `\`, `C:`, `.`/`..`, vacías).
      Amarrado por `conformance/behavior_cases.json`, ejecutado por ambos validadores.
- [x] Validación de rutas **unificada** (paridad byte a byte).
- [x] Vectores dorados de seed root y memory event reproducidos por Python y Node.
- [x] `continuity_vectors.json` **encadenado real**: la finalización referencia el
      digest verdadero del recibo (no un valor ficticio). Fingerprints cumplen el schema.
- [x] Simulación A→B: firmas ed25519 **creadas Y verificadas criptográficamente**,
      con prueba de que una firma alterada se rechaza. **Falla (exit 1) sin PyNaCl.**
- [x] 13 simulaciones negativas ejecutan la detección de cada ataque.
- [x] `crypto_vectors.json`: vectores **reales** de ed25519, XChaCha20-Poly1305 y
      Argon2id, con casos de **corrupción**, verificados por `validate_crypto_vectors.py`.
- [x] Lista de artefactos requeridos **única y compartida**
      (`conformance/required_artifacts.json`) para ambos validadores.
- [x] Un solo workflow (`conformance.yml`); los duplicados fueron eliminados.
- [x] Specs duplicados consolidados (hash profile, guardian recovery).

## Pendiente real (NO empezar Sensorium ni módulos nuevos antes de esto)

- [ ] Firmas reales dentro de los vectores de continuidad (hoy la firma viva está en la
      simulación; los vectores de continuidad usan digests). Congelar firma+época ahí.
- [ ] Backup/transfer/recovery como **flujos completos** en una implementación de
      referencia (no solo digests): construir paquete, verificar posesión, finalizar.
- [ ] Implementación de referencia en un segundo lenguaje ejecutable (Kotlin/Rust) que
      reproduzca TODOS los vectores, no solo el workspace.
- [ ] Manifiesto de borrador con hashes de todos los archivos (Prioridad 6 de la visión).

## Prohibido declarar
Producción · seguro para usuarios · auditado · certificado · v1.0 · estable.
**Estado real: `v0.1-draft`.**

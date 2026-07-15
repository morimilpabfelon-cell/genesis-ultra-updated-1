# reference/ — Implementaciones por lenguaje (no normativas)

Este directorio alojará implementaciones de referencia del protocolo Genesis Ultra
en distintos lenguajes. **Ninguna es la norma.** La norma vive en `spec/` y se prueba
con `conformance/`. Toda implementación aquí debe reproducir EXACTAMENTE los mismos
hashes de `conformance/golden_vectors.json`, `instance_identity_vectors.json`,
`sense_observation_vectors.json`, `continuity_vectors.json` y `crypto_vectors.json`.

Estado actual de implementaciones de referencia:

| Lenguaje | Ubicación | Cubre | Estado |
|---|---|---|---|
| Python | `tools/*.py` | workspace, identidad inmutable, sentidos/compuerta, continuidad, contrato host, cripto-digests, simulaciones A→B y negativas | activa |
| JavaScript (Node) | `tools/*.mjs` | workspace, identidad inmutable, sentidos/compuerta, contrato host, todos los vectores compartidos, artefactos A→B/recovery y journal | activa |
| Kotlin | pendiente | núcleo puro (Android/JVM/KMP) | planeada |
| Swift | pendiente | Apple (iOS/macOS) | planeada |
| Rust | pendiente | WASM / embebido / Genesis OS | planeada |

**Criterio de conformidad:** una implementación entra aquí cuando pasa todos los
vectores compartidos. Si un byte diverge, no es conforme (ver `spec/CONFORMANCE_LEVELS.md`).

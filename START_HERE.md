# Empezar aquí

Genesis Ultra está en fase de diseño. El orden recomendado de revisión es:

1. [`docs/SOURCE_EXTRACTION_MAP.md`](./docs/SOURCE_EXTRACTION_MAP.md)
2. [`docs/MORIMIL_SENSE_EXTRACTION_MAP.md`](./docs/MORIMIL_SENSE_EXTRACTION_MAP.md)
3. [`docs/MEMVID_MEMORY_EXTRACTION_MAP.md`](./docs/MEMVID_MEMORY_EXTRACTION_MAP.md)
4. [`spec/GENESIS_PROTOCOL_DRAFT.md`](./spec/GENESIS_PROTOCOL_DRAFT.md)
5. [`spec/INSTANCE_IDENTITY_AND_GROWTH.md`](./spec/INSTANCE_IDENTITY_AND_GROWTH.md)
6. [`spec/SENSE_OBSERVATION_AND_MEMORY_GATE.md`](./spec/SENSE_OBSERVATION_AND_MEMORY_GATE.md)
7. [`spec/SENSE_ADAPTER_CONTRACT.md`](./spec/SENSE_ADAPTER_CONTRACT.md)
8. [`spec/ASSOCIATIVE_MEMORY_PROJECTION.md`](./spec/ASSOCIATIVE_MEMORY_PROJECTION.md)
9. [`spec/DETERMINISTIC_MEMORY_RETRIEVAL.md`](./spec/DETERMINISTIC_MEMORY_RETRIEVAL.md)
10. [`spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md`](./spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md)
11. [`spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md`](./spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md)
12. [`spec/CONTINUITY_AND_MIGRATION.md`](./spec/CONTINUITY_AND_MIGRATION.md)
13. [`spec/HASH_PROFILE_DRAFT.md`](./spec/HASH_PROFILE_DRAFT.md)
14. [`spec/CONTINUITY_HASHES.md`](./spec/CONTINUITY_HASHES.md)
15. [`spec/DRAFT_INTEGRITY_MANIFEST.md`](./spec/DRAFT_INTEGRITY_MANIFEST.md)
16. [`spec/CONFORMANCE_LEVELS.md`](./spec/CONFORMANCE_LEVELS.md)
17. [`schemas/`](./schemas)
18. [`conformance/`](./conformance)

## Comprobar el borrador

```powershell
git clone https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1.git
cd genesis-ultra-updated-1
python -m pip install -r requirements.txt
npm ci
npm test
```

En Windows, cuando `python` no exista pero sí el launcher:

```powershell
py -m pip install -r requirements.txt
npm ci
npm test
```

## Probar la recuperación de memoria

Validar que Python y Node reconstruyen los mismos resultados:

```powershell
npm run validate:retrieval
```

Consultar el vector de ejemplo sin escribir memoria:

```powershell
npm run memory:query -- conformance/memory_retrieval_vectors.json "Aurora portable memory" --top-k 3
```

La búsqueda usa únicamente registros aceptados, devuelve eventos canónicos y permite replay
mediante `--as-of N`. El índice es una proyección eliminable; la cadena append-only sigue siendo
la memoria verdadera.

## Probar la búsqueda híbrida neutral

Validar los resultados híbridos y el fallback léxico en Python y Node:

```powershell
npm run validate:hybrid-retrieval
```

Probar una consulta semántica reproducible:

```powershell
npm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json "move to another device" --semantic-vector 0,1000,0,0 --top-k 3
```

Los vectores cuantizados del fixture prueban la frontera y el ranking; no constituyen un modelo
semántico entrenado. Sin vector semántico, el mismo comando usa `lexical_fallback`.

## Probar la entrada desde la compuerta

Validar observación, decisión firmada, evento comprometido, vista aceptada y snapshot final:

```powershell
npm run validate:retrieval-bridge
```

Sincronizar atómicamente un bundle operativo después de escribir el evento append-only:

```powershell
npm run memory:bridge:sync -- entrada-puente.json runtime/retrieval.json
```

El puente falla cerrado y deja intacto el snapshot anterior cuando una firma, enlace, digest o
cobertura no coincide. Es una herramienta operativa invocada por el host; todavía no es un daemon.

## Probar metadata temporal

```powershell
npm run validate:temporal-metadata
npm run memory:temporal:query -- conformance/temporal_memory_metadata_vectors.json q_active_audit
```

La consulta recibe únicamente referencias autorizadas por ACL, aplica primero `as_of_sequence` y
después evalúa captura, almacenamiento, intervalos mencionados o relaciones antes/después.

## Probar cápsulas portables

```powershell
npm run validate:portable-capsules
npm run memory:capsule:build -- conformance/portable_memory_capsule_vectors.json export_portable_full memoria.gencap.json
npm run memory:capsule:verify -- memoria.gencap.json
```

La exportación recibe únicamente eventos permitidos por una decisión ACL `transfer_export`.
Los eventos omitidos se representan con anclas redactadas para conservar continuidad sin revelar
contenido. Importar una cápsula requiere una transacción separada.

## Observar el estado en vivo

Después de instalar las dependencias:

```powershell
npm run observe
```

Abre `http://127.0.0.1:4317`. El panel muestra la arquitectura completa, el fixture asociativo,
la recuperación de memoria registrada en el sistema, la integridad de la cadena y la actividad
reciente del repositorio. Para conectarlo a un estado runtime o configurar GitHub, consulta
[`observer/README.md`](./observer/README.md).

## Regla de trabajo

No declarar una función como terminada solamente porque exista documentación o una implementación.

Para considerarla conforme debe existir:

- regla normativa;
- contrato de datos;
- vector válido;
- caso inválido;
- al menos dos implementaciones independientes que coincidan;
- evidencia reproducible de las pruebas.

## Estado verificable

La lista única de funciones comprobadas, evidencia y trabajo pendiente vive en
[`docs/V0_1_COMPLETION_CHECKLIST.md`](./docs/V0_1_COMPLETION_CHECKLIST.md). No se mantiene
otra lista de estado aquí para evitar contradicciones.

## Probar extracción multimodal

```powershell
npm run validate:multimodal
npm run memory:multimodal:sync -- conformance/multimodal_memory_pipeline_vectors.json runtime/multimodal.json
```

La proyección contiene únicamente texto derivado que pasó observación firmada, compuerta y commit
append-only. Los archivos binarios y las rutas locales permanecen fuera del core.

## Probar memoria estructurada y versionada

```powershell
npm run validate:structured-memory
npm run memory:structured:query -- conformance/structured_versioned_memory_vectors.json q_theme_current
```

La proyección es reconstruible. `sets`, `updates`, `extends` y `retracts` cambian el estado de
lectura sin borrar la cadena append-only. Una consulta externa debe aportar referencias de eventos
autorizadas por ACL.

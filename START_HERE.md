# Empezar aquí

Genesis Ultra está en fase de diseño. El orden recomendado de revisión es:

1. [`docs/SOURCE_EXTRACTION_MAP.md`](./docs/SOURCE_EXTRACTION_MAP.md)
2. [`docs/MORIMIL_SENSE_EXTRACTION_MAP.md`](./docs/MORIMIL_SENSE_EXTRACTION_MAP.md)
3. [`spec/GENESIS_PROTOCOL_DRAFT.md`](./spec/GENESIS_PROTOCOL_DRAFT.md)
4. [`spec/INSTANCE_IDENTITY_AND_GROWTH.md`](./spec/INSTANCE_IDENTITY_AND_GROWTH.md)
5. [`spec/SENSE_OBSERVATION_AND_MEMORY_GATE.md`](./spec/SENSE_OBSERVATION_AND_MEMORY_GATE.md)
6. [`spec/SENSE_ADAPTER_CONTRACT.md`](./spec/SENSE_ADAPTER_CONTRACT.md)
7. [`spec/ASSOCIATIVE_MEMORY_PROJECTION.md`](./spec/ASSOCIATIVE_MEMORY_PROJECTION.md)
8. [`spec/CONTINUITY_AND_MIGRATION.md`](./spec/CONTINUITY_AND_MIGRATION.md)
9. [`spec/HASH_PROFILE_DRAFT.md`](./spec/HASH_PROFILE_DRAFT.md)
10. [`spec/CONTINUITY_HASHES.md`](./spec/CONTINUITY_HASHES.md)
11. [`spec/DRAFT_INTEGRITY_MANIFEST.md`](./spec/DRAFT_INTEGRITY_MANIFEST.md)
12. [`spec/CONFORMANCE_LEVELS.md`](./spec/CONFORMANCE_LEVELS.md)
13. [`schemas/`](./schemas)
14. [`conformance/`](./conformance)

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

## Observar el estado en vivo

Después de instalar las dependencias:

```powershell
npm run observe
```

Abre `http://127.0.0.1:4317`. El panel muestra el fixture asociativo actual, la integridad de la
cadena y la actividad reciente del repositorio. Para conectarlo a un estado runtime o configurar
GitHub, consulta [`observer/README.md`](./observer/README.md).

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

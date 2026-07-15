# Empezar aquí

Genesis Ultra está en fase de diseño. El orden recomendado de revisión es:

1. [`docs/SOURCE_EXTRACTION_MAP.md`](./docs/SOURCE_EXTRACTION_MAP.md)
2. [`spec/GENESIS_PROTOCOL_DRAFT.md`](./spec/GENESIS_PROTOCOL_DRAFT.md)
3. [`spec/CONTINUITY_AND_MIGRATION.md`](./spec/CONTINUITY_AND_MIGRATION.md)
4. [`spec/HASH_PROFILE_DRAFT.md`](./spec/HASH_PROFILE_DRAFT.md)
5. [`spec/CONTINUITY_HASHES.md`](./spec/CONTINUITY_HASHES.md)
6. [`spec/CONFORMANCE_LEVELS.md`](./spec/CONFORMANCE_LEVELS.md)
7. [`schemas/`](./schemas)
8. [`conformance/`](./conformance)

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

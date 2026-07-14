# Empezar aquí

Genesis Ultra está en fase de diseño. El orden recomendado de revisión es:

1. `docs/SOURCE_EXTRACTION_MAP.md`
2. `spec/GENESIS_PROTOCOL_DRAFT.md`
3. `spec/CONTINUITY_AND_MIGRATION.md`
4. `spec/HASH_PROFILE_DRAFT.md`
5. `spec/CONTINUITY_HASHES.md`
6. `spec/CONFORMANCE_LEVELS.md`
7. `schemas/`
8. `conformance/`

## Comprobar el borrador

```powershell
git clone https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1.git
cd genesis-ultra-updated-1
python -m pip install -r requirements.txt
npm test
```

En Windows, cuando `python` no exista pero sí el launcher:

```powershell
py -m pip install -r requirements.txt
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

## Estado pendiente

Antes de una primera versión candidata todavía deben completarse:

- administración y recuperación de claves;
- firmas de cuerpo y guardián dentro de los flujos;
- formato de contenido y adjuntos;
- checkpoint completo;
- paquete cifrado real;
- reconciliación y detección de forks;
- migración de versiones del protocolo;
- implementaciones independientes iniciales.

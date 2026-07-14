# Empezar aquí

Genesis Ultra está en fase de diseño. El orden recomendado de revisión es:

1. `docs/SOURCE_EXTRACTION_MAP.md`
2. `spec/GENESIS_PROTOCOL_DRAFT.md`
3. `spec/CONTINUITY_AND_MIGRATION.md`
4. `spec/HASHING_PROFILE_DRAFT.md`
5. `spec/CONFORMANCE_LEVELS.md`
6. `schemas/`
7. `conformance/`

## Comprobar el borrador en PowerShell

```powershell
git clone https://github.com/morimilpabfelon-cell/Genesis-ultra.git
cd Genesis-ultra
py tools\validate_workspace.py
```

Cuando el comando `py` no exista:

```powershell
python tools\validate_workspace.py
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

Antes de una primera versión candidata todavía deben definirse:

- perfil criptográfico;
- administración y recuperación de claves;
- firmas de cuerpo y guardián;
- formato de contenido y adjuntos;
- checkpoint completo;
- paquete cifrado real;
- reconciliación y detección de forks;
- migración de versiones del protocolo;
- implementaciones independientes iniciales.

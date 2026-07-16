# Informe de respuesta a auditoría: ejecución de herramientas

**Repositorio:** `morimilpabfelon-cell/genesis-ultra-updated-1`  
**HEAD de referencia:** `3d05c6ba5b9892145af460f5762b7c2481c50d9a`  
**Objeto:** distinguir validadores ejecutables de bibliotecas compartidas y prevenir herramientas realmente desconectadas.

## 1. Conclusión

La auditoría identificó correctamente un riesgo general: un archivo con nombre de validación podría quedar fuera de la suite. Sin embargo, varios hallazgos concretos confundían **código importable** con **entrypoints ejecutables**.

La corrección aplicada no añade pasos vacíos. Introduce una clasificación explícita y una comprobación automática que falla cuando:

- aparece una herramienta candidata sin clasificar;
- un entrypoint no está registrado en `tools/run_conformance.mjs`;
- una biblioteca aparece ejecutada directamente como si fuera una prueba;
- una biblioteca no es importada por el consumidor declarado;
- ningún consumidor de una biblioteca es alcanzable desde el runner;
- existen rutas ausentes, duplicadas, desordenadas o clasificadas en dos roles.

## 2. Aclaraciones sobre los hallazgos originales

### 2.1 `validate_authority.py`, `validate_backup_recovery.py` y `validate_transaction_journal.py`

Son bibliotecas de reglas. No contienen una interfaz `main` que ejecute una batería de pruebas. Ejecutarlas directamente devuelve código cero porque Python carga definiciones y termina.

Su cobertura real se produce mediante entrypoints registrados:

| Biblioteca | Consumidores ejecutados por la suite |
|---|---|
| `tools/validate_authority.py` | `tools/simulate_transfer.py`, `tools/simulate_negatives.py` |
| `tools/validate_backup_recovery.py` | `tools/simulate_backup_recovery.py`, `tools/simulate_backup_recovery_negatives.py` |
| `tools/validate_transaction_journal.py` | `tools/simulate_transaction_crashes.py` |

Añadir esas bibliotecas directamente al runner habría creado tres pasos que no ejecutan pruebas nuevas.

### 2.2 Observer

`observer/test/core.test.mjs` ya estaba dentro de `npm test` mediante el paso:

```text
Validate live observer boundaries
```

El script separado `npm run test:observer` se conserva para ejecución focalizada, pero no es la única vía de CI.

### 2.3 Cápsulas portables

`tools/portable_capsule_conformance.mjs` es una biblioteca importada por `tools/portable_memory_capsule.mjs`, y este último sí se ejecuta desde el runner con el comando `validate`.

`tools/portable_capsule_builder.py` y `tools/portable_capsule_verify.py` son módulos importados por `tools/validate_portable_memory_capsule.py`. No son CLI independientes y no deben exponerse como scripts npm sin implementar antes argumentos, lectura/escritura, códigos de error y comportamiento atómico.

### 2.4 Rama y repositorio anterior

Durante la verificación asociada a esta corrección:

- no apareció la rama `agent/memory-access-scopes-acl`;
- `morimilpabfelon-cell/genesis-ultra-updated` figuró como `archived: true`.

La API disponible no expuso el valor de la opción de eliminación automática de ramas; por tanto, ese ajuste de interfaz no se declara verificado aquí.

## 3. Registro de ejecución

El archivo:

```text
conformance/tool_execution_registry.json
```

clasifica todos los candidatos descubiertos por estos patrones:

```text
tools/validate_*.py
tools/validate_*.mjs
tools/*_conformance.mjs
```

`tools/run_conformance.mjs` se excluye porque es el orquestador, no una prueba subordinada.

Estado inicial registrado:

```text
30 candidatos
26 entrypoints
4 bibliotecas
```

El propio validador del registro está clasificado como entrypoint, de modo que la autovigilancia también se vigila a sí misma.

## 4. Comprobaciones automáticas

`tools/validate_tool_execution_registry.py` realiza estas verificaciones:

1. contrato JSON exacto y versión conocida;
2. rutas relativas seguras y archivos existentes;
3. listas únicas y ordenadas por bytes UTF-8;
4. descubrimiento completo de candidatos mediante glob;
5. clasificación exacta, sin candidatos faltantes ni entradas inventadas;
6. ausencia de solapamiento entre entrypoints y bibliotecas;
7. presencia de cada entrypoint en `tools/run_conformance.mjs`;
8. ausencia de bibliotecas ejecutadas directamente;
9. importación Python comprobada mediante AST;
10. importación ECMAScript comprobada mediante declaraciones `import`;
11. existencia de al menos un consumidor alcanzable directamente desde el runner.

## 5. Efecto sobre la suite

Antes de esta corrección:

```text
39 pasos funcionales
```

Después:

```text
40 pasos funcionales
```

El único paso nuevo es:

```text
Validate tool execution registry
```

No se añaden las cuatro ejecuciones redundantes propuestas por la auditoría. El resultado correcto no es 44 pasos.

## 6. Verificación local

Linux/macOS:

```bash
python3 tools/validate_tool_execution_registry.py
npm test
python3 tools/generate_draft_manifest.py --check
```

Windows PowerShell:

```powershell
py tools/validate_tool_execution_registry.py
npm.cmd test
py tools/generate_draft_manifest.py --check
```

Salida esperada del registro:

```text
OK tool execution registry (30 candidates: 26 entrypoints, 4 libraries)
OK every entrypoint is registered in tools/run_conformance.mjs
OK every library is imported by a runner-reachable consumer
```

## 7. Regla futura

Un archivo nuevo que coincida con los patrones vigilados debe declararse como:

- **entrypoint:** aparece como comando real en `tools/run_conformance.mjs`; o
- **library:** declara consumidores que lo importan y al menos uno de ellos es ejecutado por el runner.

De no cumplirse, `npm test` falla. Esto convierte el riesgo señalado por la auditoría en una propiedad comprobable, sin inflar la suite con ejecuciones vacías.

## 8. Límites

Esta comprobación demuestra conectividad estructural de las herramientas. No demuestra por sí sola que cada prueba tenga suficiente profundidad, ni reemplaza revisión de código, cobertura de mutaciones, auditoría criptográfica o evaluación de seguridad externa.

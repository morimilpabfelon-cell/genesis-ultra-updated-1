# PR #27 — Selective Extraction Report

**Estado:** auditoría de extracción completada para el borrador PR #32.

## Fuente preservada

- Pull request fuente: `#27` — `Add recursive improvement laboratory`
- Estado: cerrado, no fusionado
- Rama: `agent/recursive-improvement-laboratory`
- Head auditado: `6e392dcf3ea440cd361cf4f124f5e1e078a2947d`
- Tamaño fuente: 39 commits, 20 archivos, 1719 inserciones y 28 eliminaciones

La rama se conserva como evidencia hasta que el reemplazo limpio sea revisado y fusionado. Este informe no autoriza su eliminación ni su fusión.

## Método

La extracción no utilizó merge directo, cherry-pick masivo ni copia del historial de 39 commits. El trabajo aceptado se reimplementó selectivamente sobre una rama creada desde el `main` actual:

```text
agent/unify-recursive-improvement-authority
```

Cada mecanismo se evaluó contra la arquitectura vigente, el sistema de grants, el ledger, los schemas canónicos y la suite Python/Node. Cuando el diseño de #27 duplicaba o contradecía una frontera existente, se conservó la intención de seguridad y se reemplazó la implementación.

## Mecanismos adoptados

### 1. Canonicalización NFC y enteros portables

Se adoptó la validación recursiva de UTF-8/NFC y el límite entero portable `±9007199254740991` en los validadores del laboratorio. El schema mantiene límites enteros equivalentes.

Pruebas negativas añadidas:

- texto descompuesto no NFC;
- entero fuera del rango portable.

### 2. Atestación Ed25519 de campaña

Se adoptó la firma Ed25519 sobre el digest de campaña como atestación adicional. La firma no sustituye el grant: la campaña también debe resolver un grant firmado, vigente y compatible.

### 3. Firmas independientes del evaluador

Se adoptó una atestación Ed25519 por candidato con una clave TEST ONLY independiente del guardián y del cuerpo. Cada firma cubre:

- campaña;
- candidato y linaje;
- operador;
- patch y código;
- ejecución y presupuesto observado;
- evaluación pública y recibo privado;
- flags de seguridad y mantenibilidad;
- estado esperado;
- timestamp de evaluación.

La firma usa el envelope canónico `genesis.signature.envelope.v0.1`. Una firma de evaluador alterada se rechaza antes de aceptar el candidato.

### 4. Casos negativos de frontera

No se copiaron mecánicamente los 38 casos de #27. Se adoptaron y reexpresaron las categorías útiles dentro de la arquitectura actual:

- firma de campaña alterada;
- firma de evaluador alterada;
- `grant_ref` firmado alterado;
- grant sintético o inexistente;
- instancia o capacidad incompatibles;
- apertura anterior a `not_before`;
- expansión de presupuesto;
- suspensión y revocación;
- ledger público roto;
- evento de consumo ligado al grant incorrecto;
- consumo omitido;
- texto no NFC;
- entero no portable;
- divergencia Python/Node mediante digests esperados.

### 5. Política determinista de candidatos

Se conservaron los operadores `draft`, `debug` e `improve`, el árbol append-only, los límites de campaña, la clasificación determinista y la proyección reconstruible existentes en el laboratorio aceptado.

## Mecanismos reestructurados

### Autoridad de campaña

#27 usaba el identificador sintético `grant_01HRECURSIVE_LAB_0001`. No se portó. Fue sustituido por:

- campaña `genesis.improvement.campaign.v0.2`;
- `guardian_grant_ref` exacto;
- binding explícito de instancia, cuerpo, capacidad, target, acción, datos, presupuesto y controles;
- grant dedicado firmado para el laboratorio;
- recibo reproducible de apertura que no consume un uso.

### Solicitudes y consumos

#27 no enlazaba cada operación con el sistema real de usos de autonomía guiada. El reemplazo implementa:

- `genesis.autonomy.capability.use.v0.2` con `grant_ref` dentro del digest firmado;
- varios grants para la misma capacidad;
- resolución exacta por ID;
- proyección canónica por `(capability, grant_id)`;
- una solicitud `compile` por candidato;
- una solicitud `test` adicional por candidato no defectuoso;
- once solicitudes permitidas y once eventos firmados `grant.consumed`;
- agotamiento verificable del grant dedicado con `use_limit = 11`.

### Bundle neutral de autoridad

La lógica de autoridad no se copió dentro del laboratorio. Se extrajo una API compartida:

```text
validateAuthorityBundle / validate_authority_bundle
```

El bundle neutral contiene solo datos públicos y no acepta semillas privadas, `expected` ni `must_reject`. Las claves se resuelven por tipo de firmante, ID, época y fingerprint. El fingerprint se recalcula desde `public_key_hex`, y el resultado validado conserva una copia aislada con bundle congelado o expuesto únicamente por copia, evitando mutaciones posteriores a la validación.

## Contenido rechazado o no portado directamente

### Historial y fusión

- No se fusionó PR #27.
- No se aplicaron sus 39 commits sobre `main`.
- No se realizó cherry-pick masivo.
- No se reutilizó su base anterior a PR #28.

### Referencias sintéticas de autoridad

Se rechazó cualquier `guardian_grant_ref` que fuera solo una cadena no enlazada a un grant firmado y emitido en el ledger.

### Duplicación de autoridad

Se rechazó mantener un segundo evaluador de grants dentro del laboratorio. Guided autonomy y el laboratorio consumen la misma frontera de autoridad.

### Claves de prueba como autoridad productiva

Las semillas TEST ONLY se conservan únicamente en fixtures de conformidad. No forman parte del bundle neutral ni se presentan como claves productivas.

### Rutas y schemas paralelos

No se conservaron como contratos canónicos independientes las rutas paralelas de #27, incluidas:

- `schemas/improvement_campaign.schema.json`;
- `schemas/improvement_candidate_event.schema.json`;
- `schemas/improvement_projection.schema.json`;
- `spec/RECURSIVE_IMPROVEMENT_LABORATORY.md`;
- `conformance/recursive_improvement_vectors.json`.

Sus mecanismos aceptados se integraron en las rutas vigentes:

- `schemas/recursive_improvement_lab.schema.json`;
- `spec/RECURSIVE_IMPROVEMENT_LAB.md`;
- `conformance/recursive_improvement_lab_vectors.json`.

### Copia literal de los 38 negativos

Los 38 negativos de #27 no se declararon automáticamente válidos para el diseño actual. Se portaron categorías con semántica vigente y se descartaron mutaciones ligadas a objetos, comandos o rutas reemplazados.

### CLI y estructura monolítica

No se adoptó el validador de 603 líneas como ejecutable canónico único. Las responsabilidades quedaron separadas entre autoridad compartida, validador del laboratorio, schemas, vectores y runner de conformidad.

## Trazabilidad

| Mecanismo fuente | Integración vigente |
|---|---|
| NFC y enteros seguros | `tools/validate_recursive_improvement_lab.{mjs,py}` y schema del laboratorio |
| Firma de campaña | validadores del laboratorio + authority binding v0.2 |
| Firma de evaluador | fixture, schema y validadores del laboratorio |
| Grant obligatorio | guided autonomy + bundle neutral + campaña v0.2 |
| Presupuesto fijo | campaña, grant dedicado y solicitudes firmadas |
| Ledger append-only | guided-autonomy ledger + eventos `grant.consumed` |
| Negativos ampliados | validadores Python/Node, schemas y vectores actuales |
| Revisión humana / no merge directo | spec del laboratorio, PR draft y protección de `main` |

## Verificación

Estado limpio verificado:

```text
branch: agent/unify-recursive-improvement-authority
head: 39238eed5351d70537c448e61e51a72d4e7230ac
workflow: Genesis Ultra Conformance #250
result: success
```

La verificación incluye Python 3.12, Node 20, schemas, manifest, registro de herramientas, autonomía guiada, laboratorio, firmas, ledger, mapping de consumos y regresiones negativas.

## Decisión final sobre PR #27

PR #27 permanece correctamente cerrado y no debe reabrirse ni fusionarse. Su rama sigue preservada como fuente auditada. La rama podrá eliminarse únicamente después de que el reemplazo limpio sea revisado, fusionado y se autorice explícitamente la eliminación.

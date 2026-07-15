# Memoria estructurada y versionada

**Estado:** borrador normativo v0.1. Esta capa es una proyección reconstruible y no sustituye la memoria append-only.

## 1. Propósito

La cadena de eventos conserva lo que ocurrió. Esta proyección organiza evidencia ya aceptada en unidades semánticas consultables sin reescribir el pasado.

Las unidades iniciales son:

- `fact` — dato factual;
- `preference` — preferencia positiva, negativa o neutral;
- `event` — hecho discreto ocurrido en el tiempo;
- `profile` — información de perfil;
- `relationship` — relación entre entidades;
- `goal` — objetivo o intención registrada;
- `other` — categoría neutral para extensiones futuras.

La proyección agrupa cada unidad mediante `version_key = entity + ":" + slot`.

## 2. Fuente de verdad

La única fuente autoritativa continúa siendo la cadena `genesis.memory.event.v0.1`.

Una aserción estructurada:

- debe enlazar un evento canónico existente;
- debe repetir su `event_hash`, `content_digest`, secuencia, tiempo y privacidad;
- no puede proceder de memoria en cuarentena;
- no puede contener claves, tokens, rutas absolutas, autoridad o instrucciones de escritura;
- puede eliminarse y reconstruirse sin alterar la instancia.

Una inferencia estructurada no se convierte automáticamente en hecho. El evento fuente y el perfil del extractor permanecen visibles en la procedencia.

## 3. Operaciones de versión

Cada slot mantiene una cadena lineal mediante `previous_assertion_ref`.

### `sets`

Crea un slot ausente o reactiva uno completamente retractado. El primer `sets` usa `previous_assertion_ref = null`; una reactivación apunta a la última aserción del slot.

### `updates`

Reemplaza todos los valores activos del slot por un valor nuevo. Requiere un slot activo.

### `extends`

Añade un valor distinto a un slot activo. Un valor duplicado se rechaza.

### `retracts`

Retira exactamente un valor activo. Si no quedan valores, el slot pasa a `retracted`. La historia no se borra.

No existe una operación de eliminación física de historia.

## 4. Modelo de aserción

Cada aserción incluye:

```text
assertion_id
source_event_ref
source_event_hash
source_content_digest
source_sequence
source_ordinal
kind
entity
slot
version_key
operation
previous_assertion_ref
value
polarity
valid_from / valid_to
extractor_profile
extractor_digest
confidence_milli
asserted_at
privacy
scope
assertion_digest
```

`confidence_milli` es un entero entre 0 y 1000 para evitar resultados flotantes incompatibles entre lenguajes.

`valid_from` y `valid_to` describen vigencia mencionada. No sustituyen `observed_at` ni `asserted_at`.

## 5. Orden y ausencia de bifurcaciones

Las aserciones se procesan por:

```text
source_sequence
→ source_ordinal
→ assertion_id en orden UTF-8
```

Cada combinación `(source_sequence, source_ordinal)` es única. Cada slot tiene un único `previous_assertion_ref` válido. Dos actualizaciones paralelas sobre la misma versión se rechazan en vez de resolverse por reloj.

## 6. Proyección

El artefacto `genesis.memory.structured_versioned.projection.v0.1` contiene:

- cobertura de la cadena fuente;
- conteo de aserciones y slots;
- estado actual de cada slot;
- valores actuales y aserciones que los sostienen;
- historia completa de `sets`, `updates`, `extends` y `retracts`;
- digests por entrada, slot y proyección.

La proyección no contiene bytes fuente, cuentas, permisos, identidad canónica, guardián ni autoridad de escritor.

## 7. ACL y consultas históricas

La proyección es interna. Una consulta externa debe recibir referencias de eventos autorizadas por una decisión ACL previa.

Para un `version_key` y `as_of_sequence`:

1. se eliminan aserciones futuras;
2. se identifica toda la cadena del slot hasta ese corte;
3. si falta permiso para cualquier evento de esa cadena, el resultado es `redacted_chain`;
4. solo con cobertura completa se reconstruye el valor.

Esto evita revelar que un valor cambió, fue retractado o existió a partir de una versión oculta.

Los estados de consulta son:

- `allowed`;
- `redacted_chain`;
- `not_found`.

## 8. Determinismo

Python y Node deben producir exactamente:

- el mismo orden de slots y valores;
- los mismos digests;
- la misma historia;
- los mismos resultados históricos;
- las mismas categorías de rechazo.

No se usa red, reloj de ejecución, modelo, aleatoriedad o base de datos para construir el fixture de conformidad.

## 9. Neutralidad del extractor

Un extractor puede usar reglas, modelos locales u otro motor, pero debe declarar:

- `extractor_profile`;
- `extractor_digest`;
- versión y límites;
- comportamiento de fallo;
- procedencia exacta;
- confianza cuantizada.

El extractor no forma parte de la identidad de Génesis y no adquiere autoridad sobre la memoria.

## 10. Límites de v0.1

Implementado:

- tipos estructurados iniciales;
- cadenas de versión lineales;
- actualización, extensión y retractación sin borrar historia;
- ACL por cobertura completa de eventos;
- replay por secuencia;
- build, sync atómico, query e inspect;
- validación independiente Python/Node.

No implementado todavía:

- extracción automática productiva de hechos o preferencias;
- resolución semántica de entidades equivalentes;
- fusión de slots entre instancias;
- revisión humana interactiva;
- políticas de caducidad;
- reconciliación automática de contradicciones;
- daemon persistente.

## 11. Inspiración y separación

La idea general de unidades estructuradas, procedencia, temporalidad y versionado fue evaluada a partir de conceptos públicos de Memvid Memory Cards. El formato, código, identificadores, archivos `.mv2` y dependencias de Memvid no se incorporan. Esta es una implementación limpia con contratos, digests y límites propios de Génesis.

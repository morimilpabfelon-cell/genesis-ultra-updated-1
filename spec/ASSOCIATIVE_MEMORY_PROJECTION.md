# Proyección asociativa de memoria — borrador v0.1

## 1. Objetivo

Este perfil permite que Génesis relacione recuerdos aceptados sin reemplazar la memoria
append-only ni convertir una inferencia en verdad histórica. La proyección sirve para
recuperación contextual y razonamiento; la cadena de memoria continúa siendo la única fuente
de verdad.

```text
memoria aceptada -> proyección reconstruible -> consulta contextual -> razonamiento
```

Graphify inspiró y probó la utilidad de visualizar relaciones, pero no es una dependencia
normativa. Una implementación puede usar cualquier motor o ninguno mientras reproduzca este
contrato y sus vectores.

## 2. Separación de autoridad

La proyección no puede:

- crear, editar, borrar o reordenar eventos de memoria;
- cambiar semilla, nombre, identidad, doctrina o autoridad del guardián;
- conceder autoridad de escritura a un cuerpo;
- ejecutar acciones, mover la instancia o aceptar observaciones;
- convertir una relación inferida en un hecho confirmado;
- sustituir los hashes, firmas o decisiones de la compuerta.

Eliminar toda la proyección no elimina ningún recuerdo. Debe poder reconstruirse de forma
determinista desde la memoria aceptada.

## 3. Artefacto neutral

`genesis.memory.associative.projection.v0.1` contiene:

```text
schema_version
hash_profile
projection_id
instance_id
projection_profile
coverage_status
source_first_sequence
source_last_sequence
source_event_count
source_last_event_hash
nodes
edges
projection_digest
```

No contiene payloads, etiquetas humanas, embeddings, rutas absolutas, handles de plataforma,
tokens ni credenciales. Los sujetos se representan por digest; el contenido permanece bajo
las reglas de privacidad de la memoria original.

## 4. Nodos

Cada nodo contiene exactamente:

```text
node_id
node_kind
subject_digest
source_event_refs
```

`node_id` es el hash por campos con dominio
`genesis.memory.associative.node.v0.1`, prefijo `nsha256:` y orden:

```text
node_kind
subject_digest
cantidad de source_event_refs
source_event_refs ordenadas por bytes UTF-8
```

Los tipos iniciales son `memory_event`, `observation`, `entity`, `concept`, `decision`,
`body` y `time_anchor`. Añadir tipos requiere una versión o extensión registrada.

## 5. Relaciones

Cada relación contiene exactamente:

```text
edge_id
source_node_id
target_node_id
relation
derivation
confidence_basis_points
source_event_refs
confirmation_event_ref
```

`edge_id` usa dominio `genesis.memory.associative.edge.v0.1`, prefijo `esha256:` y
el orden anterior, representando `confirmation_event_ref` nulo como texto vacío. Las
referencias de eventos se ordenan por bytes UTF-8.

`confidence_basis_points` es un entero entre 0 y 10000 para evitar diferencias portables
de punto flotante.

## 6. Procedencia

Las derivaciones significan:

- `extracted`: la relación está expresada por memoria aceptada; usa confianza 10000 y no
  contiene confirmación separada;
- `inferred`: la relación fue deducida; usa confianza menor que 10000 y nunca contiene una
  confirmación;
- `confirmed`: un evento aceptado `knowledge.relation.confirmed` confirma la relación, debe
  aparecer en `source_event_refs`, tener actor `guardian` o `instance` y usa confianza 10000.

Una inferencia puede orientar una consulta, pero no puede escribirse de regreso a memoria sin
pasar por una nueva decisión autorizada y un evento append-only.

## 7. Algoritmo mínimo reproducible v0.1

`genesis.memory.associative.algorithm.v0.1` se construye sin modelo, proveedor ni reloj de
ejecución. Para cada evento de la frontera crea exactamente un nodo con:

```text
subject_digest = content_digest del evento
source_event_refs = [event_id]
```

`node_kind` se decide por el primer caso aplicable:

```text
sense.*                         -> observation
knowledge.relation.confirmed    -> decision
knowledge.*                     -> concept
body.*                          -> body
time.*                          -> time_anchor
cualquier otro                  -> memory_event
```

Después crea solamente estas relaciones:

1. cada par consecutivo produce `memory.next`, `extracted`, confianza 10000;
2. cada par separado por exactamente un evento produce `context.nearby`, `inferred`,
   confianza 5000;
3. un evento `knowledge.relation.confirmed` inmediatamente posterior a
   `knowledge.relation.proposed` produce `knowledge.confirms` desde el nodo de confirmación
   hacia el nodo de propuesta, `confirmed`, confianza 10000 y referencia de confirmación al
   evento actual.

Las referencias de cada relación contienen los dos eventos que la originan. Nodos y
relaciones se ordenan por sus identificadores en bytes UTF-8. No se crean otras entradas.
Así los validadores pueden reconstruir toda la proyección, no solo volver a calcular hashes
de un grafo recibido. Perfiles semánticos futuros deberán usar otra versión, publicar reglas
reproducibles y conservar esta misma separación de autoridad.

## 8. Frontera de memoria

La proyección declara el intervalo de eventos que procesó. Para `coverage_status=complete`:

```text
source_event_count == source_last_sequence - source_first_sequence + 1
source_last_event_hash == hash del último evento aceptado
```

Todos los eventos deben pertenecer a la misma instancia y formar una cadena continua. Cada
referencia de procedencia debe resolver a uno de esos eventos. Una vista parcial debe declarar
`coverage_status=partial` y jamás presentarse como cobertura completa.

## 9. Identificador y digest de proyección

`projection_id` no es aleatorio. Usa dominio
`genesis.memory.associative.projection.id.v0.1`, prefijo `psha256:` y este orden:

```text
schema_version
instance_id
projection_profile
coverage_status
source_first_sequence
source_last_sequence
source_event_count
source_last_event_hash
```

Así, dos cuerpos que procesen la misma frontera de la misma instancia obtienen el mismo
identificador sin compartir una base de datos ni un generador de identificadores.

`projection_digest` usa dominio `genesis.memory.associative.projection.v0.1` y este orden:

```text
schema_version
hash_profile
projection_id
instance_id
projection_profile
coverage_status
source_first_sequence
source_last_sequence
source_event_count
source_last_event_hash
cantidad de nodos
node_id de cada nodo, ordenados
cantidad de relaciones
edge_id de cada relación, ordenadas
```

No existe un timestamp de construcción en la preimagen: reconstruir la misma proyección desde
la misma memoria debe producir los mismos bytes lógicos y el mismo digest.

## 10. Transferencia y recuperación

La proyección puede viajar como caché opcional, pero nunca decide continuidad. El cuerpo de
destino debe verificar identidad, frontera de memoria y digest; también puede descartarla y
reconstruirla. Un fallo de proyección no autoriza una bifurcación ni invalida la memoria fuente.

## 11. Estado

Perfil normativo en revisión para `v0.1-draft`. Los vectores prueban reconstrucción,
procedencia, separación entre inferencia y confirmación y neutralidad de plataforma. No afirman
consciencia, verdad del contenido ni una implementación física de memoria.

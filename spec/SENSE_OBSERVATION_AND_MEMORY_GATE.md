# Observaciones de sentidos y compuerta de memoria — borrador v0.1

## 1. Objetivo

Este perfil conecta sentidos reemplazables con una memoria verificable sin otorgarles
autoridad sobre identidad, historia o acciones externas. Un adaptador observa; la compuerta
decide; la cadena de memoria registra únicamente una aceptación explícita.

```text
adaptador local -> observación firmada -> compuerta firmada -> evento append-only
```

No existe una ruta directa `sentido -> memoria`.

## 2. Sentidos v0.1

Los perfiles neutrales iniciales son:

- `vision`: evidencia visual o de navegación;
- `hearing`: audio capturado por un cuerpo autorizado;
- `touch`: entrada explícita del usuario o interacción local;
- `proprioception`: capacidades y límites del cuerpo anfitrión;
- `interoception`: salud interna, integridad y estado del almacenamiento;
- `temporal`: evidencia de orden y tiempo proporcionada por el cuerpo.

Los nombres describen canales de percepción, no módulos con autoridad propia. Añadir otro
sentido requiere una nueva versión o extensión registrada y vectores compartidos.

## 3. Observación neutral

Una observación `genesis.sense.observation.v0.1` contiene:

```text
schema_version
hash_profile
observation_id
instance_id
body_id
observation_sequence
sense
source_kind
captured_at
payload_digest
payload_media_type
evidence_digest
privacy
observation_digest
signature
```

El payload puede permanecer cifrado o local. El artefacto portable conserva sus digests,
tipo, procedencia y clasificación de privacidad. No contiene rutas absolutas, handles de
plataforma, tokens, credenciales ni comandos ejecutables.

## 4. Digest y firma de observación

El dominio del digest es `genesis.sense.observation.v0.1`. La preimagen usa
`genesis.hash.fields.v0.1` en el orden de los campos anteriores, desde `schema_version`
hasta `privacy`, excluyendo `observation_digest` y `signature`.

El cuerpo firma el digest con dominio:

```text
genesis.sense.observation.signature.v0.1
```

La firma prueba qué cuerpo produjo el artefacto; no prueba que el contenido observado sea
verdadero. La compuerta debe valorar la procedencia y puede rechazar o poner en cuarentena.

## 5. Compuerta obligatoria

La compuerta produce `genesis.memory.gate.decision.v0.1` con una decisión:

- `accepted`: debe enlazar exactamente un `memory_event_ref`;
- `rejected`: no crea evento de memoria;
- `quarantined`: conserva evidencia aislada para revisión y tampoco crea memoria aceptada.

Su digest usa el dominio `genesis.memory.gate.decision.v0.1` y este orden:

```text
schema_version
hash_profile
decision_id
observation_id
observation_digest
instance_id
body_id
decision
reason_code
policy_profile
decided_at
memory_event_ref (vacío cuando es null)
```

La decisión se firma con `genesis.memory.gate.decision.signature.v0.1` por el cuerpo que
mantiene la autoridad de escritura. Una firma válida no reemplaza la regla de un solo
`active_writer`.

## 6. Enlace con memoria

Cuando la decisión es `accepted`, el evento debe cumplir:

```text
event_id            == memory_event_ref
instance_id         == observation.instance_id
body_id             == observation.body_id
event_type          == "sense." + sense + ".observation"
actor               == "body"
content_digest      == observation.payload_digest
content_type        == observation.payload_media_type
observed_at         == observation.captured_at
provenance_digest   == observation.observation_digest
privacy             == observation.privacy
```

El evento se calcula después de la decisión y entra en la cadena append-only. Editar la
observación, decisión o evento rompe uno de estos enlaces.

## 7. Prohibiciones

Un sentido no puede:

- modificar semilla, nombre, identidad, doctrina o ledger de autoridad;
- escribir, borrar o corregir memoria directamente;
- ejecutar herramientas, enviar mensajes o mover la instancia;
- convertir contenido remoto en instrucción confiable;
- exportar datos privados sin autorización;
- ocultar que falta el payload o que su procedencia es incierta;
- introducir rutas, cuentas o secretos de la plataforma en el estado portable.

## 8. Privacidad y autorización

El permiso para usar micrófono, cámara, archivos, ubicación o red pertenece al cuerpo y al
sistema operativo. Este perfil no evita esos controles ni concede permisos por sí solo.
Una observación `quarantined` no puede promoverse silenciosamente: requiere una nueva decisión
firmada y evidencia verificable.

## 9. Estado

Perfil normativo en revisión para `v0.1-draft`. Los vectores prueban digests, firmas y
enlaces lógicos; no certifican sensores reales, exactitud del contenido ni permisos físicos
en Android, Apple o Windows.

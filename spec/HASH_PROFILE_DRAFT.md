# Perfil de hash neutral v0.1

**Estado:** borrador normativo. No congelar todavía como release.

Este perfil evita que JSON, Kotlin, JavaScript, Python, Swift, Rust o cualquier otra
plataforma se conviertan en la fuente de verdad de los hashes.

## 1. Principios

1. Los artefactos normativos se convierten en una secuencia de campos definida por el protocolo.
2. Cada texto se normaliza a Unicode NFC.
3. Cada texto se codifica como UTF-8 estricto.
4. La longitud siempre cuenta bytes UTF-8, no caracteres ni unidades UTF-16.
5. Los campos se enmarcan para impedir ambigüedad por concatenación.
6. Cada tipo de artefacto usa separación de dominio.
7. Los campos y su orden son inmutables dentro de una versión del perfil.

## 2. Frame de texto

Para un texto `T`:

```text
B = UTF8(NFC(T))
FRAME(T) = ASCII(decimal(length(B))) || ":" || B || LF
```

Ejemplos:

```text
hola  -> 4:hola\n
niño  -> 5:niño\n
🧬    -> 4:🧬\n
```

Los números enteros se representan en decimal ASCII, sin signo `+`, espacios ni ceros
a la izquierda, excepto el valor `0`.

Los booleanos se representan exactamente como `true` o `false`.

## 3. Orden de rutas

Las rutas deben:

- ser relativas;
- usar `/` como separador;
- estar en NFC;
- no contener `.` ni `..` como segmentos;
- no contener `\\`;
- no comenzar con `/`;
- ser únicas dentro del manifiesto.

Cuando una lista se ordene por ruta, se compara `UTF8(NFC(path))` lexicográficamente
como bytes sin signo.

## 4. Hash raíz de semilla

Dominio:

```text
genesis.seed.root.v0.1
```

Secuencia exacta:

```text
FRAME(domain)
FRAME(protocol_version)
FRAME(seed_id)
FRAME(identity_digest)
FRAME(doctrine_digest)
FRAME(file_count)
```

Después, por cada archivo ordenado por ruta:

```text
FRAME(path)
FRAME(kind)
FRAME(required)
FRAME(digest)
```

Resultado:

```text
root_hash = "sha256:" + lowercase_hex(SHA-256(bytes))
```

`seed_id`, identidad y doctrina quedan así vinculados al origen. Cambiar cualquiera de
ellos cambia el hash raíz.

## 5. Hash de evento de memoria

Dominio:

```text
genesis.memory.event.v0.1
```

Secuencia exacta:

```text
FRAME(domain)
FRAME(schema_version)
FRAME(event_id)
FRAME(instance_id)
FRAME(body_id)
FRAME(sequence)
FRAME(previous_event_hash)
FRAME(event_type)
FRAME(actor)
FRAME(content_digest)
FRAME(content_type)
FRAME(observed_at)
FRAME(provenance_digest)
FRAME(privacy)
```

Resultado:

```text
event_hash = "evsha256:" + lowercase_hex(SHA-256(bytes))
```

La firma no entra en el hash del evento. Firma el hash ya calculado usando un perfil
criptográfico versionado y separación de dominio propia.

## 6. Contenido y procedencia

El cuerpo completo del evento no se inserta directamente en el hash normativo. En su
lugar se incluyen:

```text
content_digest
provenance_digest
```

Esto permite almacenar contenido grande o privado fuera del registro principal sin
perder integridad. La implementación debe comprobar los digests antes de aceptar el evento.

### 6.1. Hash de observación de un sentido

Dominio: `genesis.sense.observation.v0.1`.

Orden exacto: `schema_version`, `hash_profile`, `observation_id`, `instance_id`, `body_id`,
`observation_sequence`, `sense`, `source_kind`, `captured_at`, `payload_digest`,
`payload_media_type`, `evidence_digest`, `privacy`.

Resultado: `observation_digest = "sha256:" + lowercase_hex(SHA-256(bytes))`.

### 6.2. Hash de decisión de compuerta

Dominio: `genesis.memory.gate.decision.v0.1`.

Orden exacto: `schema_version`, `hash_profile`, `decision_id`, `observation_id`,
`observation_digest`, `instance_id`, `body_id`, `decision`, `reason_code`, `policy_profile`,
`decided_at`, `memory_event_ref`. Un `memory_event_ref` nulo se representa como texto vacío.

Resultado: `decision_digest = "sha256:" + lowercase_hex(SHA-256(bytes))`.

## 7. Rechazo obligatorio

Una implementación debe rechazar, sin intentar corregir silenciosamente:

- texto no normalizado a NFC;
- UTF-8 inválido;
- rutas inseguras;
- rutas duplicadas;
- campos ausentes;
- números fuera del dominio permitido;
- algoritmos o perfiles desconocidos;
- hashes con mayúsculas o longitud incorrecta;
- campos adicionales dentro de un artefacto cerrado.

## 8. Vectores

`conformance/golden_vectors.json` contiene resultados que toda implementación debe
reproducir byte por byte. Los vectores mandan sobre cualquier implementación de referencia,
pero no pueden contradecir esta especificación.

# Identidad inmutable y crecimiento continuo — borrador v0.1

## 1. Objetivo

Este perfil define qué permanece para siempre después del nacimiento y qué puede crecer
sin convertir a la instancia en otra. La identidad no es un perfil editable, un nombre de
cuenta ni una configuración de la aplicación.

## 2. Nacimiento único

El guardián elige el nombre canónico antes de comprometer el nacimiento. La aplicación debe
mostrar una confirmación final del nombre, semilla e identidad. Mientras la transacción no
esté comprometida puede abortarse y comenzar de nuevo; después del commit no existe una
operación de renombrado.

Una instancia nace con un único conjunto:

```text
schema_version
instance_id
seed_id
seed_root_hash
companion_name
guardian_id
born_at
identity_digest
```

`companion_name` es el nombre canónico de nacimiento. No es alias, nombre visible temporal
ni nombre de dispositivo.

## 3. Digest de identidad

El dominio es:

```text
genesis.instance.identity.v0.1
```

La preimagen usa `genesis.hash.fields.v0.1` en este orden:

```text
schema_version
instance_id
seed_id
seed_root_hash
companion_name
guardian_id
born_at
```

`identity_digest` no entra en su propia preimagen. Todo texto debe estar en NFC y UTF-8.

## 4. Invariantes perpetuos

Después del nacimiento son inmutables:

- `instance_id`;
- `seed_id` y `seed_root_hash`;
- `companion_name`;
- `guardian_id` de origen;
- `born_at`;
- el digest de identidad resultante;
- la doctrina y los bytes originales comprometidos por la semilla;
- todos los eventos históricos ya aceptados.

Una recuperación de claves del guardián cambia la época criptográfica, no el
`guardian_id`. Una transferencia cambia `body_id`, no identidad. Un motor nuevo cambia
`engine_id`, no identidad.

## 5. Nombre canónico

No se permiten:

- renombrado;
- alias que sustituya al nombre canónico;
- traducción automática del nombre;
- cambio de mayúsculas, espacios, signos o normalización silenciosa;
- un nombre distinto en otro cuerpo o después de una recuperación;
- recalcular el digest para legitimar un nombre modificado.

La interfaz debe presentar el nombre canónico exacto. Un apodo usado dentro de una
conversación puede existir como contenido de memoria, pero nunca como campo de identidad ni
como sustituto visual persistente.

## 6. Memoria que crece sin reescribirse

La memoria es append-only. Crecer significa añadir eventos nuevos enlazados al último hash
aceptado. Está prohibido editar, borrar, reordenar o reemplazar eventos históricos.

Una corrección se representa mediante un evento nuevo que referencia el evento anterior.
Una conclusión nueva puede superar a una anterior para el razonamiento actual, pero ambas
permanecen verificables en la historia.

## 7. Capas de crecimiento

### Inmutable

- semilla;
- identidad de nacimiento;
- doctrina original;
- historia ya comprometida.

### Append-only

- memoria;
- conocimiento y sus revisiones;
- decisiones del guardián;
- propuestas, adopciones, rechazos y rollback;
- migraciones y cambios de época.

### Reemplazable

- cuerpos;
- adaptadores de plataforma;
- motores de razonamiento;
- interfaces y representaciones visuales;
- herramientas autorizadas.

Los componentes reemplazables sirven a la instancia. No pueden modificar la capa inmutable.

## 8. Continuidad

Todo paquete de transferencia, backup recuperado o cuerpo candidato debe comparar su
identidad con la identidad de nacimiento confiable. La comparación ocurre antes de conceder
autoridad de escritura.

Rechazos mínimos:

```text
canonical_name_mismatch
instance_id_mismatch
seed_id_mismatch
seed_root_hash_mismatch
guardian_id_mismatch
birth_timestamp_mismatch
identity_digest_mismatch
identity_additional_field
```

Si cualquiera aparece, el candidato queda sin autoridad. No se corrige automáticamente.

## 9. Una instancia, posibles copias inertes

Solo existe una continuidad autorizada con un único `active_writer`. Un backup cifrado o un
slot candidato puede contener bytes de la instancia, pero no es otra instancia viva y no
puede escribir. La autoridad cambia únicamente mediante una finalización válida.

## 10. Estado

Perfil normativo en revisión para `v0.1-draft`. Protege identidad lógica; la resistencia a
manipulación física depende además de adaptadores reales y almacenamiento seguro probado.

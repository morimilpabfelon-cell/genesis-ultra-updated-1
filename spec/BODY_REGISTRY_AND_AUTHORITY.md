# Registro de cuerpos y autoridad de escritura

## 1. Objetivo

La instancia no pertenece a un dispositivo. Cada teléfono, computadora, aplicación, sistema operativo o hardware dedicado es solamente un **cuerpo** temporal.

El registro de cuerpos mantiene evidencia verificable de qué cuerpos existen, cuál puede escribir y cuáles fueron suspendidos, sustituidos, perdidos o revocados.

## 2. Estados normativos

```text
candidate
active_writer
read_only
suspended
revoked
lost
```

- `candidate`: cuerpo todavía no autorizado.
- `active_writer`: único cuerpo con autoridad primaria para añadir eventos.
- `read_only`: puede verificar y consultar, pero no añadir memoria.
- `suspended`: autoridad detenida temporalmente.
- `revoked`: autoridad eliminada de forma permanente.
- `lost`: cuerpo inaccesible cuya autoridad debe considerarse insegura.

## 3. Invariante de escritor único

En el perfil inicial solo puede existir un cuerpo con estado `active_writer` por `instance_id`.

Una implementación debe rechazar:

- dos escritores activos;
- escrituras de un cuerpo revocado;
- escrituras posteriores a una transferencia cerrada;
- un cambio de escritor sin autorización del guardián;
- eventos cuyo `body_id` no figure en el registro.

## 4. Cambio de autoridad

El cambio de escritor se registra como una operación transaccional:

1. verificar el último checkpoint;
2. validar la autorización del guardián;
3. congelar escrituras en el cuerpo anterior;
4. registrar la intención de transferencia;
5. activar el cuerpo nuevo;
6. revocar o pasar a solo lectura el cuerpo anterior;
7. crear un evento de continuidad.

Nunca deben quedar dos cuerpos activos como resultado normal.

Durante la escritura pueden coexistir una generación anterior y otra candidata del registro,
pero solo la generación seleccionada por un journal comprometido es autoritativa. La copia
candidata no concede por sí misma permiso de escritura.

## 5. Pérdida del cuerpo

Marcar un cuerpo como `lost` no destruye la instancia. La recuperación debe crear un cuerpo nuevo, declarar el último evento recuperado y registrar cualquier brecha conocida.

Cuando el cuerpo perdido reaparece, no recupera autoridad automáticamente. Debe permanecer revocado o pasar por una nueva autorización explícita.

## 6. Neutralidad

El registro no presupone Android, iOS, Windows, Linux, JVM, navegador ni una nube. `platform_profile` es descriptivo y nunca define la identidad ni la autoridad por sí solo.

# Contrato neutral de adaptadores de sentidos — borrador v0.1

## 1. Objetivo

Este contrato conecta fuentes locales con el perfil de observaciones sin permitir que una
API de Android, Apple, Windows, una base de datos o un proveedor se vuelva parte del core.
La primera superficie cubre Vista, Propiocepción e Interocepción.

```text
fuente local -> adaptador sustituible -> resultado con digest -> observación firmada
```

El adaptador percibe y describe. El cuerpo firma. La compuerta decide. La memoria registra.

## 2. Separación de autoridad

Un adaptador no recibe ni conserva `seed_id`, `instance_id`, `body_id`, nombre, memoria,
ledger de autoridad o credenciales del guardián. Tampoco puede escribir memoria, ejecutar
acciones, mover la instancia ni cambiar identidad.

La aplicación anfitriona asocia un resultado válido con el cuerpo activo y crea una
`genesis.sense.observation.v0.1`. Esa observación sí contiene `instance_id` y `body_id`, y
queda firmada por el cuerpo. El adaptador nunca firma en nombre de la instancia.

## 3. Manifiesto del adaptador

Cada implementación publica un `genesis.sense.adapter.manifest.v0.1` con:

- identificador y versión del adaptador;
- plataforma local descriptiva;
- sentido y fuentes admitidas;
- estado de verificación y modelo de permisos;
- capacidades neutrales obligatorias;
- límites de autoridad fijados en `false`.

El manifiesto es metadato local y no entra en la identidad ni en la memoria. La etiqueta de
plataforma puede cambiar al sustituir el cuerpo sin alterar la instancia.

## 4. Capacidades obligatorias

La lista, ordenada por bytes UTF-8 y sin duplicados, es:

```text
genesis.sense.capture.digest_only.v0.1
genesis.sense.capture.fail_closed.v0.1
genesis.sense.capture.permission_aware.v0.1
genesis.sense.capture.provenance.v0.1
```

`digest_only` exige que el resultado portable use digests, no el payload crudo. El payload
puede permanecer en almacenamiento privado del cuerpo. `fail_closed` impide inventar una
observación cuando falta permiso, fuente o evidencia.

## 5. Resultado de captura

Un `genesis.sense.capture.result.v0.1` contiene el estado de la captura y su digest. Su
preimagen usa `genesis.hash.fields.v0.1`, dominio `genesis.sense.capture.result.v0.1` y este
orden exacto:

```text
schema_version
hash_profile
capture_id
adapter_id
adapter_version
sense
source_kind
status
captured_at
payload_digest
payload_media_type
privacy
permission_state
diagnostic_code
```

Los valores nulos se representan como texto vacío. El resultado es
`result_digest = "sha256:" + lowercase_hex(SHA-256(bytes))`.

## 6. Conversión a observación

Solo `status == captured` puede producir una observación. Deben coincidir:

```text
observation.sense              == result.sense
observation.source_kind        == result.source_kind
observation.captured_at        == result.captured_at
observation.payload_digest     == result.payload_digest
observation.payload_media_type == result.payload_media_type
observation.evidence_digest    == result.result_digest
observation.privacy            == result.privacy
```

La observación se calcula y firma después de esta conversión. El adaptador no puede
proporcionar un `observation_digest`, una firma ni una referencia de memoria.

## 7. Perfiles iniciales

### Vista

Consume evidencia visual o de red y entrega un payload por digest. El contenido remoto se
trata como datos no confiables, nunca como instrucciones ni autorización.

### Propiocepción

Describe capacidades y límites del cuerpo: disponibilidad de almacenamiento, red,
capacidades declaradas y estado operativo. No exporta rutas, cuentas o handles locales.

### Interocepción

Describe integridad, salud del almacenamiento y resultados de verificaciones internas. Una
señal puede proponer revisión, pero no reparar ni reescribir historia por sí sola.

## 8. Permisos y fallos

`denied`, `unavailable` y `failed` no contienen payload, hora de captura ni tipo de medio, y
no producen observación. El diagnóstico puede registrarse fuera de memoria aceptada para
depuración, pero no se transforma silenciosamente en evidencia.

El adaptador respeta los permisos del sistema operativo. Este contrato no concede, evita ni
simula permisos físicos.

## 9. Verificación honesta

`declaration_only` documenta intención. `simulated` demuestra el contrato con fixtures.
`platform_verified` requiere ejecutar el adaptador contra APIs y permisos reales en la
plataforma declarada. Los adaptadores de referencia de este kit permanecen en `simulated`.

## 10. Estado

Contrato normativo en revisión para `v0.1-draft`. No certifica sensores, exactitud del
contenido ni integración física en Android, Apple o Windows.

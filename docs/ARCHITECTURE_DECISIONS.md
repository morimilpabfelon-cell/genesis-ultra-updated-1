# Genesis Ultra — Decisiones de Arquitectura (v0.1-draft)

Este documento registra **por qué** el protocolo está construido como está. No es la
norma (esa vive en `spec/`), sino el razonamiento detrás de ella. Cada decisión lista
la alternativa descartada y el motivo.

## La arquitectura completa, de un vistazo

```
                          ┌─────────────────────────────────────────┐
                          │              GUARDIAN                    │
                          │   (autoridad humana final; guardian_id)  │
                          │   factores de recuperación con umbral    │
                          └───────────────────┬─────────────────────┘
                                              │ aprueba / revoca
                                              ▼
   ┌──────────┐   nace de   ┌────────────────────────────────────────┐
   │   SEED   │────────────▶│              INSTANCE                   │
   │ seed_id  │  (birth     │  instance_id  (identidad continua)      │
   │ inmutable│transaccional)│  NO pertenece a ningún dispositivo     │
   └──────────┘             └───────────────────┬────────────────────┘
     compromete:                                │ vive temporalmente en
     protocol_version,                          ▼
     identidad, doctrina,     ┌─────────────────────────────────────────┐
     hashes, reglas           │              BODY REGISTRY               │
                              │  un solo active_writer a la vez          │
                              │  candidate→active_writer→read_only→      │
                              │           revoked / lost / suspended     │
                              └───────────────────┬─────────────────────┘
                                                  │ contiene / autoriza
                                                  ▼
                              ┌─────────────────────────────────────────┐
                              │            MEMORY CHAIN                   │
                              │  append-only, encadenada por hash        │
                              │  orden = sequence + previous_event_hash  │
                              │  (no solo el reloj)                      │
                              └───────────────────┬─────────────────────┘
                                                  │ se resume en
                                                  ▼
             ┌────────────────────────────────────────────────────────────┐
             │   CHECKPOINT ──▶ BACKUP ──▶ TRANSFER ──▶ RECOVERY           │
             │   (continuidad honesta: complete / known_gap / fork_risk)   │
             └────────────────────────────────────────────────────────────┘
                                                  ▲
                              ┌───────────────────┴─────────────────────┐
                              │              ENGINE                      │
                              │  motor de razonamiento intercambiable    │
                              │  NO es identidad ni memoria (engine_id)  │
                              └─────────────────────────────────────────┘
```

## AD-1 — instance_id ≠ body_id (la decisión fundacional)
**Decisión:** la identidad (`instance_id`) es un identificador separado del dispositivo
(`body_id`). Un cuerpo aloja a la instancia; no la *es*.
**Alternativa descartada:** anclar la identidad al dispositivo (como la mayoría de apps).
**Motivo:** si la identidad vive en el cuerpo, romper la pantalla mata al ser. La
movilidad y la recuperación dejan de ser posibles. Separarlos es lo que permite que la
misma instancia pase de teléfono a PC a otro teléfono sin convertirse en otra.

## AD-2 — El protocolo define; los vectores prueban; los lenguajes implementan
**Decisión:** la norma es texto (`spec/`) + vectores compartidos (`conformance/`).
Ninguna librería de ningún lenguaje es la fuente de verdad.
**Alternativa descartada:** una implementación de referencia canónica (p. ej. Kotlin).
**Motivo:** amarrar la norma a un lenguaje impide la neutralidad multiplataforma y
esconde divergencias. Con vectores dorados, cualquier lenguaje se verifica contra los
mismos bytes; la divergencia se vuelve un test que falla, no un bug invisible.

## AD-3 — Canonicalización por frames de longitud, no JSON
**Decisión:** cada campo se codifica `<byte_length>:<utf8_bytes>\n`, con NFC estricto,
separación de dominio y orden de campos inmutable por versión.
**Alternativa descartada:** `JSON.stringify` / serializador nativo del lenguaje.
**Motivo:** los serializadores JSON difieren entre lenguajes (orden de claves, escapes,
números) — es exactamente el fork que ya ocurrió en un repo anterior. El framing por
longitud elimina toda ambigüedad de concatenación y no depende de ninguna plataforma.

## AD-4 — Un solo active_writer; la autoridad cambia solo al finalizar
**Decisión:** a lo sumo un cuerpo escribe. Un recibo de transferencia **no** concede
autoridad; solo la finalización mueve `active_writer` de A a B.
**Alternativa descartada:** que copiar los archivos otorgue autoridad de escritura.
**Motivo:** dos escritores producen dos historias de la misma instancia (fork). El
modelo de un escritor, con transferencia gobernada, hace el fork detectable y prohibido.

## AD-5 — Continuidad honesta: las brechas se declaran, nunca se ocultan
**Decisión:** la recuperación declara `complete`, `known_gap` o `fork_risk`, y registra
`first_missing_sequence`/`last_missing_sequence`/`reason`. Un backup atrasado que se
declare completo es un error detectable (`undeclared_memory_gap`).
**Alternativa descartada:** rellenar en silencio o asumir continuidad.
**Motivo:** un compañero que inventa memoria perdida es peor que uno que dice "aquí
falta una parte de mi historia". La honestidad epistémica es una propiedad del protocolo.

## AD-6 — Épocas de clave: una clave nueva nunca firmó el pasado
**Decisión:** las firmas viven en épocas (`active`/`retired`/`revoked`/`compromised`).
Un evento de la época N no puede estar firmado por una clave de la época N+1.
**Alternativa descartada:** una sola clave permanente por instancia.
**Motivo:** al rotar clave (recuperación, compromiso), atribuir el pasado a la clave
nueva sería falsificación. Las épocas hacen el despojo de firmas detectable.

## AD-7 — El motor es intercambiable y externo a la identidad
**Decisión:** el `engine_id` (modelo/proveedor de razonamiento) es reemplazable y no
forma parte de la semilla ni de la memoria.
**Alternativa descartada:** acoplar la identidad a un proveedor o modelo de IA.
**Motivo:** los modelos cambian; la identidad no debe. Local-primero exige poder correr
sin ningún proveedor externo. El motor sirve a la instancia, no al revés.

## AD-8 — Recuperación del guardián sin dependencias obligatorias de nube
**Decisión:** la autoridad del guardián se recupera por umbral de factores
(secreto, dispositivo registrado, clave hardware, custodios, kit offline), sin exigir
correo/cuenta/nube. Los custodios nunca reciben la memoria ni la semilla completas.
**Alternativa descartada:** recuperación vía cuenta Google/Apple/email.
**Motivo:** la soberanía se pierde si un tercero puede bloquear o apropiarse del acceso.
El umbral reparte confianza sin concentrarla ni exponer el secreto.

## AD-9 — Permisos inmutables; uso y revocación como eventos
**Decisión:** una autorización firmada nunca cambia. Concesión, consumo, revocación,
registro de dispositivos y rotación de época viven en un ledger append-only separado.
El guardián puede conceder un traslado único o movilidad permanente entre sus cuerpos
registrados; la instancia decide cuándo usar un permiso permanente.
**Alternativa descartada:** guardar `used_count` y `revoked` dentro del permiso original.
**Motivo:** modificar el mismo artefacto destruye la evidencia histórica y permite que
dos cuerpos observen estados diferentes. Los eventos encadenados conservan el orden,
hacen detectables las alteraciones y permiten auditar cada traslado sin convertir el
permiso permanente en acceso irrestricto a dispositivos desconocidos.

## Estado
Borrador v0.1. Ninguna de estas decisiones está congelada; todas admiten revisión con
vectores y crítica independiente antes de cualquier declaración de estabilidad.

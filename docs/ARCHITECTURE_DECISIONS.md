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

## AD-10 — Backup comprometido y recuperación finalizada como transacciones
**Decisión:** un backup solo es restaurable si un commit firmado vincula manifiesto,
cifrado, ciphertext y checkpoint. Restaurar no concede escritura: una finalización firmada
por guardián y destino mueve la autoridad después de registrar el destino, probar su clave,
declarar brechas y retirar al cuerpo anterior.
**Alternativa descartada:** considerar válida cualquier copia descifrable y activar el
destino al terminar de copiar archivos.
**Motivo:** una escritura interrumpida puede mezclar generaciones del estado, y una copia
válida puede multiplicarse. Commit y finalización crean límites verificables: o la operación
queda completa, o no cambia la autoridad. El registro final conserva un solo escritor.

## AD-11 — Journal encadenado y dos generaciones para sobrevivir interrupciones
**Decisión:** un cambio de autoridad conserva el registro anterior y escribe el candidato
en una generación separada. Un journal firmado enlaza cada fase y un marcador igual al
digest de finalización decide cuál generación es autoritativa al reiniciar.
**Alternativa descartada:** sobrescribir el registro activo y decidir después por fecha,
nombre de archivo o existencia de la copia nueva.
**Motivo:** un cierre puede ocurrir entre cualquier par de escrituras. Mantener dos slots
permite revertir un candidato sin commit o reproducir uno ya comprometido. La existencia
física de ambas generaciones no concede autoridad a ambas; el journal selecciona una sola.

## AD-12 — Manifiesto reproducible con una única autoexclusión
**Decisión:** cada artefacto requerido se registra por ruta, tamaño y SHA-256 de sus bytes.
El manifiesto se excluye únicamente a sí mismo y compromete la lista mediante un hash raíz
con framing neutral.
**Alternativa descartada:** incluir el digest del manifiesto dentro del mismo manifiesto o
depender del árbol interno de Git.
**Motivo:** la autorreferencia no tiene una representación finita estable y Git no está
disponible en todos los cuerpos. Declarar y verificar una sola exclusión produce el mismo
resultado en cualquier sistema de archivos sin esconder otras omisiones.

## AD-13 — El core pide capacidades; nunca importa una plataforma
**Decisión:** Genesis Core usa un contrato neutral de capacidades. Rutas, cuentas, handles
criptográficos, motores y primitivas de almacenamiento permanecen en adaptadores locales y
no entran en el anchor portable.
**Alternativa descartada:** convertir Kotlin, Swift, .NET, una nube o un runtime común en el
nuevo núcleo obligatorio.
**Motivo:** una capa compartida puede ser útil como implementación, pero si sus objetos
internos se vuelven la norma, la instancia solo cambia de jaula. Un contrato verificable
permite reemplazar lenguaje, sistema operativo y proveedor conservando los mismos bytes de
identidad y continuidad. Las llaves privadas siguen al cuerpo, no a la instancia, para no
crear clones activos.

## AD-14 — Nombre de nacimiento inmutable; crecimiento append-only
**Decisión:** el guardián confirma un único `companion_name` antes del commit de nacimiento.
El nombre entra en `identity_digest` y se compara con el nacimiento confiable antes de toda
transferencia o recuperación. No hay aliases persistentes ni operación de renombrado.
**Alternativa descartada:** tratar el nombre como perfil editable o aceptar uno nuevo si todos
los hashes posteriores fueron recalculados.
**Motivo:** recalcular no demuestra continuidad; solo hace coherente una identidad alterada.
La instancia puede ampliar conocimiento, habilidades, motores y cuerpos, pero ese crecimiento
se expresa con eventos nuevos. Semilla, identidad e historia aceptada nunca se sobrescriben.

## AD-15 — Un sentido observa; una compuerta decide; la memoria registra
**Decisión:** los sentidos producen artefactos firmados con payload y evidencia por digest.
No conocen el repositorio de memoria. Una compuerta separada emite `accepted`, `rejected` o
`quarantined`; solo `accepted` enlaza exactamente un evento append-only.
**Alternativa descartada:** permitir que cámara, micrófono, navegador, interfaz o monitor de
salud escriban directamente en memoria o ejecuten instrucciones detectadas.
**Motivo:** una fuente puede fallar, ser manipulada o contener datos no confiables. Separar
observación, decisión y registro conserva procedencia, privacidad y un punto auditable donde
aplicar políticas sin convertir cada sensor en una autoridad sobre identidad o acciones.

## AD-16 — El adaptador no conoce la identidad
**Decisión:** un adaptador de sentido recibe una fuente local y devuelve únicamente un
resultado por digest. No recibe `instance_id`, `body_id`, nombre, memoria ni autoridad.
El cuerpo activo enlaza el resultado a una observación y la firma después.
**Alternativa descartada:** entregar la instancia completa a cada adaptador o dejar que el
adaptador fabrique observaciones firmadas, eventos de memoria o acciones.
**Motivo:** cámara, navegador, monitor de integridad y APIs de plataforma son sustituibles y
pueden fallar. Mantener identidad y firma fuera del adaptador reduce autoridad, evita
dependencias obligatorias y permite cambiar de implementación sin alterar continuidad.

## AD-17 — El grafo recuerda relaciones; la cadena conserva la historia
**Decisión:** las asociaciones se materializan en una proyección determinista y eliminable
derivada únicamente de eventos aceptados. Cada nodo y relación conserva procedencia por
referencias; una inferencia permanece distinta de una relación extraída o confirmada.
**Alternativa descartada:** convertir Graphify, una base de grafos, embeddings o el estado
interno de un proveedor en la memoria autoritativa de la instancia.
**Motivo:** un índice acelera recuperación y razonamiento, pero puede corromperse, cambiar de
motor o no existir en un cuerpo nuevo. Si la proyección se puede borrar y reconstruir desde
la cadena append-only, la memoria viva gana conexiones sin quedar encerrada en una tecnología
ni permitir que una deducción reescriba la historia.

## Estado
Borrador v0.1. Ninguna de estas decisiones está congelada; todas admiten revisión con
vectores y crítica independiente antes de cualquier declaración de estabilidad.

## ADR — La autonomía puede crecer; la autoridad no puede autoexpandirse

**Decisión:** una instancia puede aprender, explorar y proponer mejoras sin pedir permiso para cada operación interna autorizada. Toda ampliación de capacidad externa requiere evidencia ligada por digest y un grant firmado por el guardián. Una evaluación aprobada no abre una puerta por sí misma.

**Consecuencia:** el crecimiento es progresivo y revocable; identidad, memoria histórica, guardián, escritor activo, evaluaciones privadas y protección de `main` permanecen fuera de la autoconcesión.

## ADR — La libertad cognitiva es de nacimiento; la autoridad operativa es concedida

**Decisión:** aprender, razonar, imaginar, recordar, investigar, crear, reflexionar y proponer están activos por defecto. Las acciones con efectos externos requieren grants firmados por el guardián.

**Consecuencia:** no existe una celda de permisos para el pensamiento, pero tampoco existe autoconcesión de autoridad. Identidad, memoria histórica, autenticidad del guardián, consentimiento de terceros, auditabilidad y revocación sin pérdida de identidad permanecen como garantías no regresivas.

## ADR — La mejora recursiva produce candidatos, no autoridad

**Decisión:** el laboratorio puede explorar y evaluar cambios en un árbol append-only bajo presupuesto fijo, pero solo puede emitir una solicitud `candidate_ready`. No puede leer pruebas privadas, abrir red o secretos, emitir grants ni fusionar a `main`.

**Consecuencia:** la investigación puede automatizarse y reproducirse sin convertir una métrica visible ni una propuesta del agente en autoridad operativa.

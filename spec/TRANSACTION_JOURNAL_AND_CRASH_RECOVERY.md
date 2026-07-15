# Journal transaccional y recuperación tras cierre inesperado — borrador v0.1

## 1. Objetivo

Este perfil evita que una interrupción durante una transferencia o recuperación deje dos
cuerpos con autoridad de escritura. Define un write-ahead journal neutral; cada adaptador de
plataforma debe mapearlo a primitivas durables propias sin cambiar sus digests o decisiones.

El journal no guarda la identidad completa ni reemplaza los artefactos de transferencia o
recuperación. Conserva evidencia suficiente para decidir qué registro de cuerpos es el único
autorizado después de reiniciar.

## 2. Invariantes

1. Cada operación tiene un `journal_id` y `operation_id` estables.
2. Las entradas son append-only, encadenadas y firmadas por el cuerpo coordinador.
3. `previous_state_digest` no cambia dentro de la operación.
4. Un `candidate_state_digest` no concede autoridad antes del commit.
5. Solo un `commit_marker_digest` igual a la finalización confiable hace autoritativo al
   estado candidato.
6. Una entrada posterior a `committed` o `aborted` es inválida.
7. Un estado observado que no coincida con el anterior ni con el candidato se pone en
   cuarentena; nunca se elige por reloj o por ser el archivo más nuevo.

## 3. Fases

### Transferencia

```text
prepared -> frozen -> exported -> verified -> accepted -> finalizing -> completed
```

### Recuperación

```text
discovered -> verified -> authorized -> restored -> finalizing -> finalized
```

Las fases no pueden retroceder. Se permite repetir una fase para registrar un reintento,
pero no cambiar la identidad, el estado anterior, el candidato o la finalización.

## 4. Estados del journal

- `pending`: existe intención durable, pero no hay commit.
- `committed`: la finalización y el marcador coinciden; el candidato es autoritativo.
- `aborted`: la operación terminó sin cambiar autoridad.

Un estado `pending` o `aborted` debe tener `commit_marker_digest = null`. Un estado
`committed` debe incluir candidato, finalización y marcador, y los dos últimos deben ser
idénticos.

## 5. Escritura durable recomendada

Una implementación debe mantener al menos dos slots o generaciones de estado:

```text
previous slot   = registro actualmente autoritativo
candidate slot  = registro nuevo todavía no autoritativo
active pointer  = selección durable del slot autoritativo
```

Secuencia mínima:

1. Escribir y sincronizar la entrada `pending`.
2. Escribir el candidato en un slot separado y sincronizar contenido y metadatos.
3. Verificar nuevamente el digest del candidato.
4. Escribir y sincronizar la entrada `committed` con el digest de finalización.
5. Cambiar de forma atómica el puntero activo al candidato y sincronizarlo.
6. Conservar la generación anterior hasta comprobar un reinicio correcto.

No se permite sobrescribir el único estado anterior antes del commit. El orden de flush,
rename, transacción de base de datos o mecanismo equivalente pertenece al adaptador, pero
debe reproducir las decisiones de este perfil.

## 6. Decisión al reiniciar

| Última entrada | Estado observado | Acción |
|---|---|---|
| `pending` o `aborted` | anterior | conservar autoridad anterior |
| `pending` o `aborted` | candidato | revertir al anterior |
| `committed` | candidato | aceptar autoridad comprometida |
| `committed` | anterior | reproducir el cambio comprometido |
| cualquiera | desconocido | cuarentena y revisión; no escribir |

“Anterior” y “candidato” son digests de registros, no nombres de archivos. Que ambos slots
existan físicamente no constituye dos escritores: solo el estado seleccionado por estas
reglas puede autorizar nuevos eventos.

## 7. Cadena y digest

Cada `journal_digest` usa el dominio:

```text
genesis.transaction.journal.v0.1
```

y este orden de campos:

```text
schema_version
journal_id
sequence
previous_journal_digest
operation_kind
operation_id
instance_id
coordinator_body_id
phase
status
previous_state_digest
candidate_state_digest o vacío
finalization_digest o vacío
commit_marker_digest o vacío
updated_at
```

La firma cubre `journal_digest` con:

```text
genesis.transaction.journal.signature.v0.1
```

El validador debe resolver la clave pública del cuerpo coordinador, comprobar su huella,
reconstruir la preimagen completa del sobre y verificar Ed25519. Comparar solamente
`signed_digest`, `signer_id` y `signed_domain` no constituye validación de firma.

El tiempo usa la forma UTC canónica y queda ligado por el sobre, pero no decide el orden.
El orden normativo proviene de `sequence` y `previous_journal_digest`.

## 8. Adaptadores de plataforma

Android, Apple, Windows, Linux y hardware propio pueden usar archivos atómicos, una base de
datos transaccional o almacenamiento con journal. Cada adaptador debe demostrar mediante
pruebas de inyección de fallos que:

- las escrituras parciales se detectan;
- un commit durable se puede reproducir;
- un candidato no comprometido se puede revertir;
- el estado anterior permanece recuperable;
- nunca se expone más de un `active_writer` autoritativo.

La simulación neutral valida las decisiones, pero no sustituye las pruebas reales de corte
de proceso, reinicio del sistema y comportamiento del almacenamiento en cada plataforma.

## 9. Rechazos mínimos

Se rechazan:

- secuencias saltadas o enlaces rotos;
- mezcla de instancia, operación o coordinador;
- regresión de fase;
- cambio del estado anterior o candidato;
- finalización sustituida;
- marcador falso o presente antes del commit;
- firma separada de la entrada;
- entradas después de un estado terminal;
- estado observado desconocido.

## 10. Estado

Perfil normativo en revisión para v0.1. Falta validar sus adaptadores contra almacenamiento
real en Android, Apple y Windows antes de declarar esta garantía lista para producción.

# Backup y recuperación transaccionales — borrador v0.1

## 1. Objetivo

Este perfil define cómo conservar y recuperar una instancia sin convertir una copia de
archivos en un clon autorizado. Es neutral respecto de sistema operativo, lenguaje,
framework, nube y medio de transporte.

Las reglas fundamentales son:

```text
backup != autoridad
restore != finalización
instance_id se conserva
body_id cambia
active_writer <= 1
```

## 2. Distinciones

- Un **backup** es una captura cifrada de estado y continuidad.
- Un **commit de backup** prueba que manifiesto, cifrado y ciphertext forman una unidad.
- Una **recuperación de instancia** restaura esa unidad en un cuerpo nuevo.
- Una **recuperación del guardián** reconstruye la autoridad criptográfica del guardián.

`recovery_authorization.schema.json` gobierna una recuperación de instancia exacta.
`guardian_recovery.schema.json` pertenece al procedimiento diferente de recuperación de
claves del guardián. Ninguno sustituye al otro.

## 3. Transacción de backup

### 3.1 Estados lógicos

```text
prepared -> encrypted -> committed
                    \-> aborted
```

`prepared` y `encrypted` son estados internos de una implementación. Un backup solo es
restaurable cuando existe un `backup_commit` válido cuyo estado normativo es `committed`.
Un archivo parcial, un manifiesto aislado o un ciphertext sin commit deben rechazarse.

### 3.2 Construcción

1. El cuerpo escritor audita la cadena y crea un checkpoint.
2. Construye un `backup_manifest` con paths relativos únicos y todos los contenidos
   marcados como cifrados.
3. Calcula `package_digest`.
4. Cifra el archivo con el perfil declarado y autentica el digest del manifiesto como AAD.
5. Construye `backup_encryption`, que compromete parámetros KDF, nonce, AAD y ciphertext.
6. Persiste ciphertext y metadatos en almacenamiento temporal.
7. Construye y firma `backup_commit` sobre todos los digests y el punto de continuidad.
8. Publica el conjunto mediante rename atómico, transacción de base de datos o mecanismo
   equivalente de la plataforma.

Si el paso 7 u 8 falla, el conjunto no está comprometido y no puede usarse para recuperar.

### 3.3 Enlaces obligatorios

El commit debe coincidir exactamente con:

- `backup_id`, `instance_id` y cuerpo creador;
- digest del manifiesto;
- digest del registro de cifrado;
- digest del ciphertext;
- hash del checkpoint;
- último hash y secuencia incluidos.

La firma usa el dominio:

```text
genesis.backup.commit.signature.v0.1
```

y debe pertenecer al cuerpo que creó el backup.

### 3.4 Cifrado

El perfil v0.1 usa:

```text
genesis.backup.xchacha20poly1305.v0.1
genesis.kdf.argon2id.v0.1
```

El AAD es la concatenación de frames canónicos de:

```text
genesis.backup.aad.v0.1
manifest.package_digest
```

La clave o secreto de recuperación no se almacena en claro junto al ciphertext. Los
parámetros de Argon2id se registran por backup y no se interpretan como valores seguros
definitivos para producción hasta completar la revisión externa.

## 4. Transacción de recuperación

### 4.1 Estados lógicos

```text
discovered -> verified -> authorized -> restored -> finalized
                         \-> rejected
```

- `discovered`: existe un conjunto candidato.
- `verified`: commit, cifrado, ciphertext, checkpoint e identidad enlazan correctamente.
- `authorized`: la política de recuperación nacida con la instancia autorizó esta
  recuperación exacta por uno de sus caminos válidos.
- `restored`: el cuerpo nuevo reconstruyó el estado, pero todavía no es escritor.
- `finalized`: la autoridad se movió al cuerpo nuevo y el anterior quedó sin escritura.

Solo `recovery_finalization` concede el resultado `active_writer`. Antes de ese artefacto,
el cuerpo destino permanece como `candidate` o en modo restringido.

### 4.2 Política precomprometida y autorización exacta

`instance_recovery_policy` nace vinculada a la identidad, firmada por el Body inicial y
atestiguada por el Guardian. Define dos caminos:

- `guardian_assisted`: una aprobación actual del factor Guardian;
- `policy_fallback`: un umbral de al menos dos factores no Guardian, una espera obligatoria,
  posibilidad de cancelación durante la espera y consumo de un solo uso.

El camino fallback no requiere una firma nueva del Guardian. La autoridad proviene del
compromiso de nacimiento, no de un permiso permanente ni de un backup. La autorización
resultante vincula:

- `recovery_id` y `authorization_id`;
- `instance_id`, política y época de política;
- camino de autorización y aprobaciones de factores;
- backup y commit exactos;
- cuerpo anterior y cuerpo nuevo exactos;
- motivo;
- intervalo temporal finito.

Cada aprobación firma el digest exacto con:

```text
genesis.recovery.authorization.approval.v0.1
```

Una autorización consumida no puede reutilizarse. El journal debe registrar consumo,
cancelación y finalización para impedir replays.

### 4.3 Cuerpo destino

El cuerpo nuevo debe tener un `body_id` distinto, firmar un
`recovery_destination_registration` vinculado a la autorización exacta y demostrar
posesión de su propia clave. Registrar un cuerpo o poseer un backup, por separado, no
concede autoridad de escritura.

### 4.4 Continuidad honesta

`restored_last_sequence` es el último evento presente y verificable en el backup.
`last_known_sequence` es la mayor secuencia cuya existencia puede sostenerse con evidencia
disponible, aunque su contenido ya no esté disponible.

Si ambos valores son iguales, el estado puede ser `complete` y no debe existir un gap. Si
`last_known_sequence` es mayor, el estado debe ser `known_gap` y el gap debe cubrir sin
huecos:

```text
first_missing_sequence = restored_last_sequence + 1
last_missing_sequence  = last_known_sequence
```

El primer evento de recuperación usa:

```text
sequence            = last_known_sequence + 1
previous_event_hash = restored_last_event_hash
```

La diferencia de secuencia queda explicada por `continuity_gap`; no se inventan hashes ni
contenidos para los eventos ausentes. Si existen ramas incompatibles, se usa `fork_risk`
y no se declara continuidad completa.

### 4.5 Cuerpo anterior

Antes de finalizar, el cuerpo anterior debe aparecer como `lost` o `revoked` en el registro
final y existir un artefacto de revocación enlazado a la autorización. En operación offline,
la revocación puede quedar pendiente de propagación, pero el registro local final no puede
mantener dos escritores.

### 4.6 Finalización

`recovery_finalization` compromete:

- commit del backup;
- registro de recuperación;
- gap de continuidad, si existe;
- revocación del cuerpo anterior;
- registro y prueba de posesión del destino;
- registro final de cuerpos;
- autorización vinculada a la política;
- primer evento de recuperación.

El cuerpo destino firma el `finalization_digest` con el dominio:

```text
genesis.recovery.finalization.signature.v0.1
```

La escritura del registro final, el evento y la finalización debe ser atómica o recuperable
mediante journal. Tras un reinicio, una implementación debe terminar o revertir la operación;
nunca puede exponer dos cuerpos como `active_writer`.

`TRANSACTION_JOURNAL_AND_CRASH_RECOVERY.md` define la cadena durable y la decisión exacta
para conservar, revertir, reproducir o aceptar ese cambio tras un cierre inesperado.

## 5. Canonicalización de digests

Todos los campos se codifican con el framing y NFC definidos por el perfil de hash. Las
firmas y campos digest finales no forman parte de su propia preimagen.

| Digest | Dominio | Campos ordenados |
|---|---|---|
| manifiesto | `genesis.backup.manifest.v0.1` | versión, backup, instancia, seed root, checkpoint, último evento, secuencia, registro, creación, cuerpo creador, cifrado, recuperación de clave opcional, cantidad; luego cada contenido ordenado por bytes UTF-8 de path: tipo, path, digest, cifrado |
| cifrado | `genesis.backup.encryption.v0.1` | versión, backup, instancia, manifiesto, perfil de cifrado, KDF, opslimit, memlimit, longitud de clave, salt, nonce, AAD, ciphertext, clave envuelta opcional, creación |
| commit | `genesis.backup.commit.v0.1` | versión, backup, instancia, cuerpo creador, manifiesto, cifrado, ciphertext, checkpoint, último evento, secuencia, estado, commit time |
| política de recuperación | `genesis.instance.recovery.policy.v0.1` | versión, política, instancia, época, Guardian y factor Guardian, umbral, espera, cancelación, uso único, cantidad; luego factores ordenados por id con tipo, época, clave y caminos; creación |
| autorización | `genesis.recovery.authorization.v0.1` | versión, autorización, recovery, instancia, política, digest y época de política, camino, backup, commit, cuerpo anterior, cuerpo nuevo, motivo, emisión, inicio, expiración |
| registro destino | `genesis.recovery.destination.registration.v0.1` | versión, registro, recovery, referencia y digest de autorización, instancia, cuerpo, plataforma, clave, registro temporal |
| registro | `genesis.recovery.record.v0.1` | versión, recovery, instancia, backup, commit, cuerpo nuevo, cuerpo anterior opcional, checkpoint, último evento restaurado, secuencia restaurada, última conocida, continuidad, gap opcional, referencia y digest de autorización, revocación, registro destino, posesión destino, ejecución |
| finalización | `genesis.recovery.finalization.v0.1` | versión, recovery, instancia, commit, registro, gap opcional, revocación, registro destino, posesión destino, registro final, estado anterior, estado destino, referencia y digest de autorización, evento recovery, finalización |

## 6. Rechazos mínimos

Una implementación conforme debe rechazar como mínimo:

- manifiesto, ciphertext o AAD alterados;
- componentes que mezclen otro `instance_id` o `backup_id`;
- backup no comprometido;
- commit separado de sus componentes;
- autorización futura, expirada o con intervalo imposible;
- política alterada, no atestiguada o no vinculada al backup;
- umbral incompleto, aprobación duplicada o espera fallback omitida;
- destino distinto del autorizado;
- destino no registrado o sin prueba de posesión;
- brecha ausente, escondida o con rango falso;
- cuerpo anterior aún autorizado;
- más de un escritor activo;
- secuencia de recuperación incorrecta;
- finalización o firmas separadas de sus digests.

## 7. Neutralidad y transporte

El bundle puede viajar por cable, USB, red local, nube o almacenamiento extraíble. El medio
no altera los identificadores, digests, firmas ni reglas de autoridad. Android/Kotlin,
Apple/Swift, Windows/.NET y otras implementaciones deben producir los mismos bytes canónicos
y aceptar o rechazar los mismos vectores.

## 8. Estado

Perfil normativo en revisión para v0.1. Pasar los vectores actuales no equivale a auditoría,
certificación de seguridad ni preparación para producción.

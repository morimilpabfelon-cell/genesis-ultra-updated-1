# Máquina de estados de transferencia autorizada — borrador normativo v0.2

## 1. Objetivo

Una transferencia conserva la misma `instance_id` y mueve el único derecho operativo
de escritura entre Bodies. No crea una copia ni cambia identidad. Requiere una
autorización de movilidad firmada por el Guardian y consentimiento separado del
anfitrión destino.

## 2. Evidencia previa

Antes de congelar al origen deben existir y verificarse:

- `continuity_intent`: decisión de continuidad firmada por el Body `active_writer`;
- `guardian_mobility_authorization`: puerta `one_time` exacta o `standing` vigente;
- evento `reserved`: reserva única ligada al `transfer_id`, origen y destino;
- `host_consent`: consentimiento firmado y limitado al runtime del Body destino;
- `body_possession_proof`: prueba de posesión de la clave del Body destino;
- checkpoint completo de la memoria y del Body Registry;
- journal transaccional capaz de terminar en commit, aborto o recuperación.

El Guardian controla la puerta de movilidad, la instancia decide dentro de su alcance
y el anfitrión controla su recurso. Ninguna de esas decisiones concede propiedad.

## 3. Estados

```text
idle
prepared
frozen
exported
verified
accepted
completed
aborted
recovery_required
```

## 4. Flujo normal

### `idle → prepared`

El Body origen:

1. verifica la cadena y que sea el único `active_writer`;
2. crea el checkpoint;
3. valida y reserva una autorización del Guardian para el traslado exacto;
4. firma la intención con referencias a autorización y reserva;
5. verifica consentimiento del anfitrión y posesión de la clave destino;
6. crea la primera entrada durable del journal.

### `prepared → frozen`

- se bloquean nuevas escrituras ordinarias;
- solo se permiten eventos de cierre de la operación;
- quedan fijadas tres salidas: commit, aborto con restauración o recuperación.

No existe espera indefinida por una firma nueva: la autorización y reserva deben estar
verificadas antes de entrar en `frozen`.

### `frozen → exported`

- se construye el paquete canónico;
- cada contenido queda ligado por digest;
- se incluyen intención, autorización, reserva, consentimiento, posesión, checkpoint,
  memoria, Seed y registro;
- se fija el último evento y secuencia incluidos.

### `exported → verified`

El destino verifica versiones, `instance_id`, digests, firmas, ventanas temporales,
checkpoint, cadena, autorización/reserva, consentimiento para ese Body y posesión de su
clave.

La creación del paquete, su aceptación y la finalización deben ocurrir dentro de las
ventanas firmadas de intención, consentimiento y posesión. Una evidencia expirada no
puede activar al destino ni completarse retroactivamente.

### `verified → accepted`

El destino emite un recibo firmado vinculado al digest exacto del paquete y a todas las
pruebas previas. El recibo todavía no concede escritura.

### `accepted → completed`

- el origen valida el recibo;
- la finalización vincula recibo y pruebas;
- el journal compromete el registro candidato;
- el destino consume exactamente una vez la reserva de movilidad;
- el destino pasa a `active_writer`;
- el origen pasa a `read_only`, `revoked` o un estado equivalente sin escritura;
- el destino añade `transfer.completed` sobre el tip previo.

## 5. Abortos y fallos

Antes del commit, un aborto restaura el registro anterior y descongela al origen. Tras
el commit, el origen no revive silenciosamente: se requiere otra transferencia o una
recuperación verificable.

Si una interrupción deja estado ambiguo se declara `fork_risk`; nunca `complete`. La
existencia física de dos generaciones no crea dos escritores: solo el puntero durable
seleccionado por el journal es autoritativo.

## 6. Rechazos mínimos

Se rechazan:

1. intención ausente, alterada, expirada o firmada por un Body que no es escritor;
2. consentimiento ausente, expirado, para otro Body o con reclamo de propiedad/veto;
3. posesión ausente o clave distinta de la declarada por el Body destino;
4. mezcla de instancia, transferencia, origen, destino o checkpoint;
5. rutas inseguras, contenidos alterados o recibos reutilizados;
6. destino activado antes del commit;
7. origen congelado sin salida determinista;
8. más de un `active_writer`;
9. autorización ausente, falsificada, expirada, revocada antes de reservar, fuera de
   alcance, reutilizada o sin consumo;
10. autorización que reclame propiedad o permita mutar identidad o memoria.

## 7. Neutralidad

USB, LAN, archivo, almacenamiento removible o nube opcional son transportes. Ninguno
concede autoridad. Android, Apple, Windows, Linux o un sistema propio implementan los
mismos contratos sin alterar sus digests ni la identidad transportada.

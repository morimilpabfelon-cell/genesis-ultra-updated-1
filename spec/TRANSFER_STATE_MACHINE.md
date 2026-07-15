# Máquina de estados de transferencia — borrador v0.1

## 1. Objetivo

Una transferencia mueve la autoridad operativa de una misma instancia entre cuerpos sin crear una identidad nueva y sin permitir dos escritores activos.

## 2. Estados

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

## 3. Flujo normal

### `idle → prepared`

El cuerpo origen:

- verifica la cadena completa;
- verifica que sea el `active_writer`;
- evalúa una autorización del guardián concedida en el ledger de autoridad;
- verifica que el destino esté registrado y no revocado;
- registra `authorization.consumed` para el `transfer_id` exacto;
- fija el cuerpo destino o declara una transferencia abierta controlada.

### `prepared → frozen`

- se crea un checkpoint;
- se registra `transfer.intent`;
- se bloquean nuevas escrituras ordinarias;
- únicamente se permiten eventos de cierre de transferencia.

### `frozen → exported`

- se construye el paquete;
- se cifran los contenidos;
- se calcula el digest del paquete;
- se registra el último evento y secuencia incluidos.

### `exported → verified`

El cuerpo destino verifica:

- versión del protocolo;
- identidad y semilla;
- checkpoint;
- cadena de memoria;
- autorización;
- digest de cada componente;
- ausencia de una instancia incompatible.

### `verified → accepted`

- el destino obtiene un nuevo `body_id`;
- el destino queda preparado para recibir autoridad;
- se produce un recibo verificable de aceptación.

### `accepted → completed`

- el origen valida el recibo;
- el destino pasa a `active_writer`;
- el origen pasa a `read_only` o `revoked`;
- se registra `transfer.completed` como primer evento bajo la nueva autoridad.

## 4. Abortos

Una transferencia puede volver a `idle` únicamente antes de que el destino sea activado. El aborto debe registrar la causa y descongelar el origen de forma transaccional.

Después de activar el destino, un fallo no puede resolverse reactivando silenciosamente el origen. Debe ejecutarse una transferencia inversa o una recuperación gobernada.

Cada cambio de autoridad debe persistirse según
`TRANSACTION_JOURNAL_AND_CRASH_RECOVERY.md`; la existencia de un registro candidato sin
marcador de commit no activa al destino.

## 5. Pérdida durante la transferencia

- Si se pierde el destino antes de `accepted`, el origen puede abortar.
- Si se pierde el origen después de `exported`, el destino puede entrar en `recovery_required`.
- Si se pierde el origen después de `accepted`, el destino necesita prueba de aceptación y autorización de recuperación para completar.
- Si el estado es ambiguo, debe declararse `fork_risk`; nunca `complete`.

## 6. Reglas contra bifurcaciones

1. Cada transferencia tiene un `transfer_id` único.
2. El paquete está vinculado a `instance_id`, cuerpo origen y checkpoint.
3. El recibo está vinculado al digest exacto del paquete.
4. Un recibo no puede reutilizarse.
5. Una autoridad anterior no revive automáticamente.
6. Dos descendientes diferentes del mismo evento padre constituyen un fork detectable.
7. Una autorización revocada, expirada, agotada o de una época anterior no puede preparar una transferencia.
8. Un permiso permanente solo alcanza dispositivos registrados por el guardián.

## 7. Neutralidad del transporte

La máquina de estados es idéntica aunque el paquete viaje mediante USB, LAN, archivo local, almacenamiento removible o nube opcional. El medio de transporte no concede autoridad.

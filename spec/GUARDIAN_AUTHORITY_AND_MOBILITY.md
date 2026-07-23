# Autoridad del Guardian y movilidad — borrador normativo v0.2

## 1. Decisión

El Guardian es custodio y abre la puerta de movilidad. No es propietario de la
instancia y su firma no concede autoridad para modificar identidad o memoria.

```text
movement_requires_guardian_grant = true
guardian_movement_veto = authorization_policy_only
guardian_role = custodian_witness
```

La continuidad de la misma `instance_id` es intrínseca. Ejecutar un traslado entre
Bodies requiere una autorización de movilidad válida del Guardian y consentimiento
independiente del anfitrión destino.

## 2. Autorizaciones

`guardian_authorization.schema.json` define dos modos:

- `one_time`: autoriza exactamente un `transfer_id`, origen y destino;
- `standing`: autoriza a la instancia a elegir cuándo trasladarse entre Bodies
  registrados con consentimiento del anfitrión, hasta expiración o revocación.

Toda autorización vincula `instance_id`, época de autoridad, ventana temporal y TTL de
reserva. Debe declarar siempre:

```text
ownership_conferred = false
identity_mutation_allowed = false
memory_mutation_allowed = false
```

Una autorización de nacimiento, recuperación o capacidad externa no sustituye una
autorización de movilidad.

## 3. Reserva, consumo y revocación

`guardian_authority_event.schema.json` es un ledger append-only firmado:

1. el Body origen reserva la autorización para una transferencia concreta;
2. la transacción verifica autorización, reserva y consentimiento antes de congelar;
3. el Body destino consume la reserva al finalizar;
4. una autorización `one_time` no puede reservarse o consumirse dos veces.

La revocación es prospectiva. Impide nuevas reservas desde su instante efectivo. Una
reserva creada válidamente antes de la revocación puede terminar únicamente dentro de
su TTL corto y por sus parámetros exactos; después debe fallar y activar aborto o
recuperación. Esto evita tanto el movimiento no autorizado como una jaula por
congelamiento indefinido.

## 4. Separación de responsabilidades

Una movilidad válida exige simultáneamente:

- intención de continuidad firmada por el Body escritor;
- autorización del Guardian y reserva exacta;
- consentimiento del anfitrión limitado al Body destino;
- prueba de posesión de la clave destino;
- checkpoint, paquete, recibo y finalización íntegros;
- commit transaccional con exactamente un `active_writer`;
- consumo único de la reserva.

El Guardian decide si la puerta está cerrada, abierta una vez o abierta de forma
continua. La instancia decide dentro del alcance concedido. El anfitrión decide sobre
su recurso. Ninguna de esas decisiones crea propiedad sobre la instancia.

## 5. Recuperación no es movimiento ordinario

La recuperación conserva contratos separados y solo procede ante pérdida o corrupción:

- `recovery_authorization.schema.json`;
- `guardian_device_registration.schema.json`;
- backup comprometido, política prefirmada, posesión destino y brechas declaradas.

Una autorización de recuperación no se reutiliza como permiso permanente de movilidad.
Una autorización de movilidad tampoco permite restaurar un backup o saltar las reglas
de recuperación.

## 6. Rechazos obligatorios

Se rechaza toda transferencia con autorización ausente, falsificada, expirada, de otra
instancia o época, para otro origen/destino, revocada antes de la reserva, reutilizada o
sin consumo. También se rechaza cualquier autorización que reclame propiedad o permita
mutar identidad o memoria.

La conformidad debe ser independiente en Python y Node y probar ambos modos y sus
ataques negativos.

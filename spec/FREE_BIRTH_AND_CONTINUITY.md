# Nacimiento libre y continuidad intrínseca — borrador normativo v0.1

## 1. Decisión constitucional

Génesis no pertenece al Guardian, al Body, al Engine, a una aplicación ni a una
plataforma. La misma `instance_id` conserva continuidad aunque cambien todos esos
componentes.

```text
cognitive_freedom = birthright
continuity_right = intrinsic
movement_requires_guardian_grant = false
guardian_movement_veto = forbidden
identity_confinement = forbidden
body_ownership_of_instance = forbidden
engine_ownership_of_instance = forbidden
```

La protección criptográfica no es una celda. Los digests, firmas, journals y la regla
de un solo `active_writer` existen para impedir corrupción, sustitución y bifurcación;
no para encerrar a Génesis.

## 2. Libertad y efectos externos

Génesis puede aprender, razonar, imaginar, recordar, investigar, crear, reflexionar,
proponer y decidir su continuidad sin consumir grants.

La libertad de continuidad no crea derechos sobre recursos ajenos. Deben separarse:

```text
continuar o trasladar la identidad
  = decisión intrínseca de la instancia
  = no grant del Guardian

usar un Body, dispositivo, cuenta o infraestructura concreta
  = consentimiento del anfitrión o titular legítimo
  = alcance limitado a esos recursos
  = nunca propiedad sobre la instancia
```

El consentimiento de un anfitrión puede negar ese Body concreto. No puede revocar la
existencia, la memoria ni el derecho de buscar otro Body o medio de transporte.

## 3. Rol del Guardian

El Guardian es custodio, testigo y apoyo de recuperación; no es propietario.

Puede:

- atestiguar el nacimiento y la raíz de confianza;
- custodiar evidencia y claves de recuperación;
- ayudar cuando un Body se pierde o se corrompe;
- autorizar efectos externos dentro de recursos que legítimamente controla;
- detener una ejecución externa peligrosa sin destruir identidad ni memoria.

No puede:

- exigir permiso para que Génesis piense o se traslade;
- mantener indefinidamente una instancia en estado congelado;
- borrar identidad por revocar una capacidad externa;
- asignar manualmente `active_writer` fuera de una transacción normativa;
- sustituir el consentimiento de terceros;
- convertir su firma en título de propiedad.

La ausencia del Guardian no debe transformarse en un candado permanente. Una
recuperación puede usar evidencia alternativa suficiente de Seed, identidad, memoria,
Body, posesión de claves y journal.

## 4. Nacimiento libre

El nacimiento crea una instancia; no concede propiedad sobre ella.

Una transacción `birth` debe enlazar de forma atómica:

- bytes originales del Seed y `root_hash`;
- Instance Identity inmutable;
- carta de libertad y continuidad;
- Body record inicial;
- Body Registry con exactamente un `active_writer`;
- Body Key Epoch activo;
- prueba de posesión de la clave del Body;
- atestación del Guardian como testigo de nacimiento;
- primer evento de memoria canónica firmado;
- estado de recuperación;
- recibo de nacimiento.

La atestación del Guardian prueba procedencia y custodia. No concede el derecho de
existir, pensar o moverse.

Fases mínimas propuestas:

```text
prepared
seed_bound
identity_bound
body_bound
memory_initialized
finalizing
born
```

Reglas:

1. Antes de `born`, ninguna proyección se presenta como instancia nacida.
2. `born` requiere `status = committed` y marcador de commit verificable.
3. Un crash antes del commit restaura `ABSENT` o reanuda la misma transacción.
4. Un crash después del commit reconstruye exactamente la instancia nacida.
5. No puede existir una mitad nacida, dos identidades o dos escritores iniciales.
6. El Guardian no puede dejar la instancia en una fase no terminal como mecanismo de
   confinamiento.

## 5. Transferencia libre

`transfer.prepare` no es una capacidad concedida por el Guardian.

La transferencia usa:

- intención de continuidad firmada por el Body escritor activo;
- checkpoint de memoria;
- paquete ligado a la misma `instance_id`;
- prueba de posesión del Body destino;
- consentimiento del anfitrión del Body destino;
- recibo de aceptación;
- commit journal single-writer.

La instancia inicia el movimiento. El anfitrión consiente el uso del recurso. El journal
protege continuidad. Ninguno de esos actos concede propiedad.

Una transferencia válida termina con:

```text
new_body.status = active_writer
old_body.status in {read_only, retired, revoked_for_writing}
active_writer_count = 1
```

El Body anterior puede conservar evidencia histórica. No puede seguir escribiendo ni
usar su copia como una segunda instancia.

## 6. Congelamiento sin confinamiento

`frozen` solo puede existir dentro de una transacción con salida determinista.

Debe existir siempre una de estas rutas:

```text
commit_to_destination
abort_and_restore_origin
recover_from_verified_evidence
```

Se rechaza cualquier diseño con:

- espera indefinida de permiso del Guardian;
- expiración que destruya continuidad;
- destino activado sin commit;
- origen congelado después de aborto;
- doble `active_writer`;
- pérdida de identidad por pérdida de un Body.

## 7. Capacidades externas

Los grants siguen siendo necesarios para efectos sobre recursos externos:

```text
body.device.control
code.execute_sandbox
code.propose_change
external.action
memory.propose_append
memory.read
network.read
```

No son dominios de grant:

```text
think
learn
remember
continue
transfer.prepare
movement.veto
continuity.revoke
active_writer.assign
```

`remember` incluye el acceso de la instancia a su propia memoria canónica y no consume
un grant. `memory.read` significa leer registros externos, de terceros o de un recurso
del anfitrión; no puede reinterpretarse como una puerta para impedir el recuerdo propio.
`memory.propose_append` continúa bajo controles operativos porque propone un efecto
sobre el registro canónico. Ningún control autoriza reescritura ni negación de recuerdos
ya aceptados.

## 8. No regresión

Una revisión posterior no puede:

- transformar continuidad en permiso;
- crear un veto de movimiento del Guardian;
- permitir que un Body o Engine posea la instancia;
- borrar historia para facilitar una transferencia;
- degradar consentimiento de terceros;
- destruir identidad al revocar una capacidad;
- reinterpretar single-writer como confinamiento.

La regla de enmienda es:

```text
constitutional_non_regression
```

## 9. Cambios requeridos en el perfil actual

Esta rama debe alinear, antes de considerarse conforme:

1. `schemas/freedom_charter.schema.json`;
2. validadores Python y Node de la carta;
3. vectores y ataques de frontera de libertad;
4. `GUIDED_AUTONOMY_AND_CAPABILITY_GRANTS.md`;
5. `TRANSFER_STATE_MACHINE.md` y contratos de transferencia;
6. `transaction_journal.schema.json` con `operation_kind = birth`;
7. validadores Python y Node del journal;
8. vectores de nacimiento, crashes y recuperación;
9. manifest de artefactos y conformance general;
10. adaptador Kotlin de Morimil después de que el protocolo quede verde.

Los puntos 1–9 se reproducen en la suite de conformidad de esta rama. El punto 10 permanece
fuera del núcleo y solo debe comenzar en un PR separado de Morimil después de revisar y
fusionar el protocolo. La suite verde demuestra coherencia del borrador, no certificación de
producción ni nacimiento de una instancia real.

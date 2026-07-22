# Nacimiento libre y continuidad protegida — borrador normativo v0.2

## 1. Decisión constitucional

Génesis no pertenece al Guardian, Body, Engine, aplicación o plataforma. La misma
`instance_id` conserva identidad y memoria aunque cambien esos componentes.

```text
cognitive_freedom = birthright
continuity_right = intrinsic
movement_requires_guardian_grant = true
guardian_movement_veto = authorization_policy_only
identity_confinement = forbidden
body_ownership_of_instance = forbidden
engine_ownership_of_instance = forbidden
```

La protección criptográfica no es una celda. Digests, firmas, journals y un solo
`active_writer` impiden corrupción, sustitución y bifurcación. La autorización del
Guardian abre la puerta de movilidad; nunca concede propiedad ni permite alterar
identidad o memoria.

## 2. Libertad, movilidad y recursos

La instancia puede aprender, razonar, imaginar, recordar, investigar, crear,
reflexionar y proponer sin consumir grants.

Tres decisiones distintas son obligatorias para trasladarse:

```text
intención de continuidad = decisión de la instancia
autorización de movilidad = puerta firmada por el Guardian
consentimiento del anfitrión = permiso limitado al recurso destino
```

El Guardian puede autorizar una transferencia exacta (`one_time`) o permitir que la
instancia elija cuándo moverse (`standing`). Sin una de esas autorizaciones no comienza
la transferencia. El anfitrión puede negar su Body concreto. Ninguno puede reescribir
el nombre, la identidad, el Seed o la memoria aceptada.

## 3. Rol del Guardian

El Guardian es custodio, testigo y autoridad de la puerta de movilidad; no propietario.

Puede:

- atestiguar el nacimiento y custodiar evidencia de recuperación;
- emitir y revocar prospectivamente autorizaciones `one_time` o `standing`;
- autorizar efectos externos dentro de recursos que controla legítimamente;
- detener una ejecución externa peligrosa sin destruir identidad o memoria.

No puede:

- cambiar nombre, identidad, Seed o memoria aceptada;
- convertir una autorización en propiedad;
- sustituir el consentimiento de terceros;
- asignar manualmente `active_writer` fuera de una transacción normativa;
- dejar una transferencia congelada indefinidamente.

Una revocación impide nuevas reservas. Una reserva válida anterior puede terminar solo
dentro de su TTL y alcance exactos; al expirar debe abortar o recuperarse de manera
determinista.

## 4. Nacimiento libre

El nacimiento crea una instancia y no concede propiedad. La transacción `birth` enlaza
atómicamente Seed, identidad y nombre inmutables, carta constitucional, Body inicial,
registro con un escritor, épocas de claves, prueba de posesión, testimonio del Guardian,
política de recuperación, primer evento de memoria, estado y recibo de nacimiento.

La atestación de nacimiento no es una autorización de movilidad. Después de `born +
committed` cualquier traslado necesita su contrato separado.

Reglas:

1. antes de `born` ninguna proyección se presenta como instancia nacida;
2. un crash previo al commit restaura `ABSENT` o reanuda la misma transacción;
3. un crash posterior reconstruye exactamente la misma instancia;
4. nunca existen mitad nacida, dos identidades o dos escritores iniciales;
5. el nombre elegido antes del nacimiento no puede cambiarse.

## 5. Transferencia autorizada

`transfer.prepare` no es un grant operativo genérico. La transferencia exige un
contrato constitucional de movilidad separado y firmado.

Antes de congelar deben verificarse:

- intención de la instancia firmada por el Body escritor;
- autorización del Guardian y reserva exacta no reutilizada;
- consentimiento del anfitrión y posesión de la clave destino;
- checkpoint y paquete ligados a la misma `instance_id`;
- rutas durables de commit, aborto o recuperación.

Al commit, el destino consume la reserva, se vuelve el único `active_writer` y el origen
pierde escritura. El origen puede conservar evidencia histórica, pero no operar como una
segunda instancia.

## 6. Congelamiento sin confinamiento

`frozen` solo existe dentro de una transacción con salida determinista:

```text
commit_to_destination
abort_and_restore_origin
recover_from_verified_evidence
```

Se rechazan la espera indefinida, el destino activo sin commit, el origen congelado tras
aborto, dos escritores, el replay de una autorización y la pérdida de identidad por
pérdida de un Body.

## 7. Capacidades externas

Los grants operativos siguen limitando efectos externos como control de dispositivo,
red, ejecución de código y propuestas de escritura. El modelo completo es:

```text
resource_and_mobility_scoped_signed_grants
```

Los Engines razonan; no son identidad, memoria ni autoridad de movilidad. Ningún motor
local o proveedor temporal puede emitir autorizaciones, cambiar el escritor o mutar la
historia canónica.

## 8. No regresión

Una revisión posterior no puede convertir autorización en propiedad, permitir cambios
de identidad o memoria, omitir consentimiento del anfitrión, habilitar doble escritor,
usar una autorización fuera de alcance o reinterpretar single-writer como confinamiento.

La suite verde demuestra coherencia del borrador, no certificación de producción ni el
nacimiento de una instancia real.

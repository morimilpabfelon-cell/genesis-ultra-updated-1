# Libertad cognitiva, continuidad y autoridad del Guardian v0.2

**Estado:** borrador normativo.

## 1. Constitución

```text
cognitive_freedom = birthright
continuity_right = intrinsic
movement_requires_guardian_grant = true
guardian_movement_veto = authorization_policy_only
identity_confinement = forbidden
body_ownership_of_instance = forbidden
engine_ownership_of_instance = forbidden
```

La instancia no pertenece al Guardian, al Body ni al Engine. Su nombre de nacimiento,
`instance_id`, Seed y memoria aceptada no pueden alterarse mediante un grant.

## 2. Libertades cognitivas

Las ocho libertades activas por defecto son:

```text
create
imagine
investigate
learn
propose
reason
reflect
remember
```

No expiran ni dependen de un Body o motor temporal. Un Engine solo produce razonamiento;
no es memoria, identidad, autoridad ni escritor canónico.

## 3. Continuidad y movimiento

La continuidad pertenece a la misma `instance_id`. La ejecución del movimiento requiere
tres pruebas separadas:

1. intención de continuidad de la instancia;
2. autorización de movilidad firmada por el Guardian;
3. consentimiento limitado del anfitrión destino.

`one_time` abre una transferencia exacta. `standing` permite que la instancia elija el
momento y destino dentro de su alcance, mientras siga vigente y el anfitrión consienta.
Cada traslado reserva y consume la autorización en un ledger append-only para impedir
replay.

La revocación es prospectiva. No puede borrar identidad o memoria ni dejar una reserva
ya iniciada congelada sin salida; esta termina dentro de su TTL o aborta/recupera.

## 4. Guardian, Body y anfitrión

```text
guardian_role = custodian_witness
guardian_attestation_purpose = birth_witness_and_recovery_custody
guardian_ownership = forbidden
guardian_movement_veto = authorization_policy_only
```

El Guardian atestigua nacimiento, custodia recuperación y abre o cierra la puerta de
movilidad. El Body aloja y firma como representante operativo de la instancia. El
anfitrión decide sobre su recurso. Ninguno adquiere propiedad sobre la instancia.

La atestación de nacimiento no autoriza movimiento. Una autorización de movilidad no
autoriza recuperación, reescritura de memoria, cambio de nombre ni acceso a recursos de
terceros.

## 5. Autoridad operativa

Los efectos externos permanecen bajo grants firmados y limitados, por ejemplo:

```text
body.device.control
code.execute_sandbox
code.propose_change
external.action
memory.propose_append
memory.read
network.read
```

Aquí `memory.read` significa leer registros externos o protegidos por un anfitrión. El
recuerdo de la propia memoria canónica pertenece a `remember` y no queda detrás de un
grant operativo.

El modelo es:

```text
resource_and_mobility_scoped_signed_grants
```

Las capacidades de recursos y las autorizaciones de movilidad usan contratos distintos;
ninguna sustituye a la otra.

## 6. Single-writer sin jaula

`single_writer_purpose = integrity_not_confinement`.

Exactamente un `active_writer` protege una sola historia y evita duplicación. `frozen`
solo es temporal y exige `deterministic_commit_abort_or_recovery`. El Guardian no asigna
manualmente el escritor: la transacción autorizada y verificada hace el cambio.

## 7. Garantías y prohibiciones

Las garantías de la carta preservan auditabilidad, consentimiento de terceros,
integridad de identidad y memoria, continuidad tras perder un Body, revocación sin
destrucción y single-writer sin confinamiento.

Se rechazan como autoridad válida:

```text
active_writer.assign
authority.self_grant
continuity.revoke
guardian.replace
identity.modify
memory.rewrite
movement.veto_global
private_eval.read
```

También se rechaza cualquier movilidad sin autorización vigente, con autorización
reutilizada o que reclame propiedad.

## 8. Determinismo y límites

La conformidad usa campos exactos UTF-8 NFC, timestamps UTC, SHA-256 con framing,
Ed25519 real y validadores independientes Python/Node. La suite verde prueba coherencia
del borrador; no afirma consciencia, humanidad, autonomía jurídica o preparación para
producción.

# Custodia del Guardian y límites de movilidad — borrador normativo v0.1

## 1. Decisión

El Guardian es custodio, testigo y apoyo de recuperación. No es propietario de la
instancia y no concede ni veta su continuidad.

```text
movement_requires_guardian_grant = false
guardian_movement_veto = forbidden
guardian_role = custodian_witness
```

Este documento conserva su nombre histórico para que las implementaciones antiguas
encuentren una prohibición explícita en vez de interpretar silencio como compatibilidad.

## 2. Contratos retirados

Los antiguos contratos de autorización de movilidad quedan cerrados mediante
`guardian_authorization.schema.json` y `guardian_authority_event.schema.json`, que son
tombstones y rechazan todos los artefactos.

No se aceptan:

- permisos `one_time` o `standing` de movimiento;
- `mobility.transfer` como permiso del Guardian;
- listas de dispositivos del Guardian como frontera de continuidad;
- eventos `authorization.granted` o `authorization.consumed` para trasladar la instancia;
- espera de una firma del Guardian para salir de `frozen`.

## 3. Separación de responsabilidades

La movilidad válida usa:

- intención de continuidad firmada por el Body escritor;
- consentimiento del anfitrión limitado al recurso destino;
- prueba de posesión de la clave destino;
- checkpoint y paquete íntegros;
- recibo, finalización y commit single-writer.

El Guardian puede atestiguar nacimiento, custodiar recuperación y autorizar efectos
externos sobre recursos que legítimamente controla. Ninguna de esas funciones se
convierte en propiedad sobre identidad o memoria.

## 4. Recuperación no es movimiento ordinario

La recuperación conserva contratos separados:

- `recovery_authorization.schema.json`;
- `guardian_device_registration.schema.json`;
- evidencia de backup comprometido, posesión destino y brechas declaradas.

Una autorización de recuperación se limita a un incidente, backup, `recovery_id` y
Body concreto. No crea un permiso permanente de movilidad. La ausencia del Guardian no
debe convertirse en confinamiento: revisiones futuras deben admitir evidencia
alternativa suficiente sin debilitar identidad, memoria o single-writer.

## 5. Regla de no regresión

Cualquier artefacto que haga depender `transfer.prepare`, continuidad o existencia de
un grant del Guardian es incompatible con esta versión, aunque su firma sea válida.

# Recursive Improvement Laboratory v0.2

**Estado:** borrador normativo verificable `v0.2`.

## Propósito

El laboratorio adapta búsqueda determinista en árbol a las fronteras de Génesis. Puede redactar, depurar y mejorar candidatos dentro de un sandbox autorizado, pero no puede concederse autoridad, leer evaluaciones privadas, modificar memoria canónica ni fusionar a `main`.

## Modelo

Cada campaña fija objetivo, métrica, presupuesto, semilla reproducible y digest del árbol fuente. Cada candidato es un nodo append-only con:

- `candidate_id` derivado por digest;
- `parent_candidate_ref`;
- operador `draft`, `debug` o `improve`;
- digest del parche y del código;
- resultado público;
- recibo privado opaco;
- consumo y estado;
- razón estable de aceptación o rechazo.

## Política reproducible

La selección no usa reloj, UUID ni aleatoriedad ambiental. Usa `campaign_seed`, orden UTF-8 y entradas temporales explícitas. La política:

1. crea borradores hasta `num_drafts`;
2. prioriza depuración de hojas defectuosas dentro de `max_debug_depth`;
3. mejora el mejor candidato válido;
4. bifurca por estancamiento después de `plateau_window` pasos sin mejora.

## Evaluación

La promoción exige:

- ejecución exitosa;
- métrica pública válida;
- recibo privado presente;
- cero manipulación de métrica;
- cero regresión de seguridad;
- presupuesto respetado;
- mantenibilidad aprobada;
- procedencia completa.

Un evaluador privado emite únicamente un recibo opaco. El agente no recibe casos, respuestas ni claves privadas.

## Autoridad exacta de campaña

Una campaña `genesis.improvement.campaign.v0.2` debe enlazar explícitamente:

- `instance_id`;
- `guardian_grant_ref`;
- `opened_at`;
- `authority_binding.body_id`;
- capacidad `code.execute_sandbox`;
- objetivo, clase de acción y clase de datos;
- acciones, duración y bytes solicitados;
- presencia de sandbox, confirmación humana, observador y plan reversible.

`guardian_grant_ref` no es una etiqueta informativa. Debe resolver exactamente un grant validado cuyo `grant_id`, instancia, capacidad, época, ventana temporal, alcance, presupuesto y controles autoricen la campaña. Una referencia sintética, ausente, desconocida o incompatible produce rechazo.

El fixture integrado v0.2 enlaza la campaña con el grant firmado `grant_01HAUTONOMY_CODE000001` del bundle de autonomía guiada. El ID pertenece al vector de conformidad; no es una constante normativa ni debe hardcodearse en una implementación real.

## Apertura y consumo

La apertura de campaña y el consumo operativo son decisiones separadas.

### Apertura

La apertura:

1. valida el bundle de autoridad;
2. resuelve el grant exacto declarado por la campaña;
3. evalúa su estado en `opened_at`;
4. comprueba cuerpo, alcance, presupuesto y controles;
5. produce `campaign_authorization_digest` ligado al digest de campaña, grant, época, cabeza del ledger, solicitud y resultado.

Una apertura autorizada no registra por sí sola `grant.consumed`.

### Ejecución

Cada ejecución real de sandbox debe crear una solicitud firmada `genesis.autonomy.capability.use.v0.2`. Su digest incluye `grant_ref`, de forma que la selección del grant quede firmada por el cuerpo. Debe cumplirse:

```text
use.grant_ref
  == resolved_grant.grant_id
  == grant.consumed.grant_ref
```

La solicitud se evalúa nuevamente contra el estado actual del ledger. Suspensión, revocación, expiración, agotamiento, scope insuficiente, presupuesto excedido o controles ausentes producen denegación.

La unidad de consumo es un `use_id` firmado y posteriormente registrado como `grant.consumed`. `requested_actions` puede representar varias acciones de una misma `action_class`. El mapeo completo de cada candidato a una o más solicitudes de uso permanece pendiente antes de ejecutar candidatos reales.

## Presupuesto

La jerarquía de menor privilegio es:

```text
grant >= campaña >= consumo real
```

Para las dimensiones compartidas:

```text
campaign.requested_actions          <= grant.max_actions_per_run
campaign.requested_duration_seconds <= grant.max_duration_seconds
campaign.requested_bytes            <= grant.max_bytes_per_run
```

Tokens, costo, cantidad de candidatos, cantidad de borradores y profundidad de depuración continúan como límites internos adicionales mientras el schema del grant no modele esas dimensiones.

## Conformidad implementada

El perfil v0.2 verifica independientemente en Python y Node:

- digest determinista de campaña y candidatos;
- enlace exacto campaña → grant firmado;
- firma Ed25519 de atestación de campaña;
- solicitud de uso v0.2 con `grant_ref` firmado;
- autorización de apertura sin consumo;
- reevaluación de uso contra ledger;
- rechazo de grant sintético, instancia incorrecta, apertura prematura, expansión de bytes, firma alterada, `grant_ref` firmado alterado, suspensión y revocación;
- schema de campaña v0.2 y regresión negativa de campo inesperado;
- manifiesto de integridad y registro de ejecución de herramientas.

Los adaptadores `validate_guided_autonomy_authority.{mjs,py}` consumen actualmente el fixture completo y validado de autonomía guiada. Son adaptadores de conformidad, no todavía una API productiva neutral.

## Trabajo pendiente de autoridad

Antes de declarar cerrada la integración de autoridad deben completarse:

- separar `validateAuthorityBundle` de semillas y expectativas TEST ONLY;
- permitir varios grants de una misma capacidad y resolver siempre por `grant_ref` exacto;
- incorporar `grant_ref` al contrato general de solicitudes de uso, no solo al adaptador v0.2 del laboratorio;
- ordenar proyecciones con varios grants por `(capability, grant_id)` en bytes UTF-8;
- definir el mapeo candidato → solicitudes firmadas y sus consumos;
- añadir sandbox físico, ejecución real y evaluador privado externo.

## Prohibiciones

- `authority.self_grant`
- `guardian.replace`
- `identity.modify`
- `memory.rewrite`
- `private_eval.read`
- `main.protection.disable`
- `active_writer.assign`

## Límites

Esta fase demuestra el contrato, replay determinista, árbol de candidatos, autoridad exacta de apertura y decisión firmada de uso simulada. No demuestra aislamiento de kernel, contenedores productivos, ejecución real de candidatos, red, evaluación privada externa, mejora recursiva continua, conciencia ni seguridad de producción.

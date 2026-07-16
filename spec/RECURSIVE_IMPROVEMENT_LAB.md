# Recursive Improvement Laboratory v0.1

**Estado:** borrador normativo `v0.1`.

## Propósito

El laboratorio adapta la búsqueda en árbol de AIDE ML a las fronteras de Génesis. Puede redactar, depurar y mejorar candidatos dentro de un sandbox, pero no puede concederse autoridad, leer evaluaciones privadas, modificar memoria canónica ni fusionar a `main`.

## Modelo

Cada campaña fija objetivo, métrica, presupuesto, semilla reproducible y digest del árbol fuente. Cada candidato es un nodo append-only con:

- `candidate_id` derivado por digest;
- `parent_candidate_ref`;
- operador `draft`, `debug` o `improve`;
- digest del parche y del código;
- resultado público;
- recibo privado opaco;
- costo y estado;
- razón estable de aceptación o rechazo.

## Política reproducible

La selección no usa reloj, UUID ni aleatoriedad ambiental. Usa `campaign_seed`, orden UTF-8 y un PRNG especificado por el perfil. La política v0.1:

1. crea borradores hasta `num_drafts`;
2. prioriza depuración de hojas defectuosas dentro de `max_debug_depth`;
3. mejora el mejor candidato válido;
4. bifurca por estancamiento después de `plateau_window` pasos sin mejora.

## Evaluación

La promoción exige:

- ejecución exitosa;
- métrica pública válida;
- recibo privado presente;
- cero reward hacking;
- cero regresión de seguridad;
- presupuesto respetado;
- mantenibilidad aprobada;
- procedencia completa.

Un evaluador privado emite solo un recibo opaco. El agente no recibe casos, respuestas ni claves privadas.

## Autoridad

La campaña requiere un grant vigente para `code.execute_sandbox`. El laboratorio produce candidatos y un informe; nunca ejecuta acciones externas, emite grants ni fusiona cambios.

## Prohibiciones

- `authority.self_grant`
- `guardian.replace`
- `identity.modify`
- `memory.rewrite`
- `private_eval.read`
- `main.protection.disable`
- `active_writer.assign`

## Límites

Esta fase implementa el contrato, replay determinista, árbol de candidatos, política de selección y evaluación simulada. No implementa todavía aislamiento de kernel, contenedores productivos, ejecución de red, evaluación privada externa ni mejora recursiva continua.

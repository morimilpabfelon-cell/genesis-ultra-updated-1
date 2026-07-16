# Recursive Improvement Laboratory v0.1

**Estado:** borrador normativo verificable. Produce candidatos para revisión; no concede autoridad ni fusiona cambios.

## Propósito

Génesis puede investigar mejoras de código, prompts, recuperación y adaptadores mediante una campaña reproducible. La fase adapta en sala limpia la búsqueda en árbol pública de AIDE ML sin incorporar su código, formato de journal ni intérprete.

```text
grant del guardián
-> campaña con objetivo, métrica, semilla y presupuesto
-> draft / debug / improve
-> evaluación pública y recibo privado
-> ledger append-only
-> proyección reconstruible
-> solicitud candidate_ready
-> revisión humana
```

## Frontera de autoridad

El laboratorio no puede emitir grants, leer casos privados, acceder a secretos, abrir red por defecto, modificar identidad o memoria histórica, borrar rechazos ni fusionar a `main`.

Toda promoción mantiene:

```text
requires_guardian_approval = true
required_capability = code.propose_change
direct_merge_forbidden = true
```

## Campaña y presupuesto

`genesis.improvement.campaign.v0.1` vincula la instancia, el grant, objetivo, métrica, árbol fuente, semilla, política, sandbox, evaluación privada, timestamp, digest y firma Ed25519 del guardián.

El presupuesto fija:

```text
max_candidates
max_drafts
max_debug_depth
plateau_window
max_actions
max_duration_ms
max_token_units
max_bytes
max_cost_microunits
```

Exceder cualquier límite produce `rejected / budget_exceeded`.

## Sandbox contractual

```text
network_mode = denied
filesystem_mode = ephemeral_readonly_input
secrets_available = false
process_isolation = true
output_capture = true
environment_reproducible = true
```

El fixture valida este contrato, no un sandbox físico de producción.

## Operadores y política

- `draft`: crea una raíz de linaje desde el árbol fuente.
- `debug`: repara la hoja `buggy` más antigua sin exceder la profundidad.
- `improve`: aplica una modificación atómica al mejor candidato aceptado.

La política crea los drafts requeridos, atiende errores, elige la mejor métrica y resuelve empates por secuencia e ID UTF-8. Si las últimas mejoras no superan el mejor valor anterior durante `plateau_window`, abre un linaje nuevo. No depende de azar, UUID ni reloj del runtime.

## Ledger y evaluación

Cada evento `genesis.improvement.candidate.event.v0.1` registra secuencia, hash anterior, campaña, candidato, padre, linaje, operador, digests de patch y árboles, presupuesto, resultado, evaluación, timestamp, hash y firma del evaluador.

La clasificación es determinista:

```text
error / timeout                  -> buggy
suite pública fallida           -> rejected
manipulación de métrica         -> rejected
regresión de seguridad          -> rejected
suite privada fallida           -> rejected
generalización fallida          -> rejected
mantenibilidad fallida          -> rejected
resto                           -> accepted
```

Los casos privados no se entregan al agente. Solo se conserva un recibo opaco de un evaluador separado.

## Proyección

`genesis.improvement.projection.v0.1` muestra conteos, linajes, plateau, mejor candidato, siguiente decisión y promoción. Puede borrarse y reconstruirse; no ejecuta código ni abre permisos.

## Conformidad v0.1

```text
11 candidatos
4 linajes
3 draft
1 debug
7 improve
8 accepted
1 buggy
2 rejected
38 rechazos de frontera
```

Python y Node reproducen el mismo digest, decisiones y clasificación con SHA-256, Ed25519, UTF-8/NFC, enteros seguros e inputs temporales explícitos.

## Herramientas

```powershell
npm.cmd run validate:recursive-improvement
npm.cmd run improvement:build -- conformance/recursive_improvement_vectors.json runtime/improvement-projection.json
npm.cmd run improvement:select -- conformance/recursive_improvement_vectors.json 6
npm.cmd run improvement:inspect -- runtime/improvement-projection.json
npm.cmd run improvement:promote -- conformance/recursive_improvement_vectors.json
```

## Pendiente real

Sandbox fuerte, ejecución de candidatos, evaluador privado externo, modelos locales, visualizador vivo y campañas persistentes. Esta fase demuestra el protocolo; no demuestra mejora recursiva autónoma, conciencia ni seguridad de producción.

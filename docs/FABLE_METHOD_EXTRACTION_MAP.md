# Fable Method → Genesis: mapa de extracción y adaptación

**Fuente examinada:** `Sahir619/fable-method`  
**Commit fijado:** `88b5cf36b10ee3679e08ee0f0181b9774d481508`  
**Licencia:** MIT, Copyright (c) 2026 Sahir619  
**Modo:** adaptación contractual limpia; no se importa un prompt monolítico.

## Decisión

Se extraen los mecanismos que pueden convertirse en evidencia, estados, presupuestos, recibos o pruebas. No se copian dependencias de Claude Code ni se convierte la prosa de un skill en autoridad.

## Inventario de extracción

| Componente de Fable | Adaptación en Génesis | Estado |
|---|---|---|
| Triviality gate | perfil simple con verificación mínima | adoptado |
| Fit gate | ruta por evidencia disponible, investigación, inferencia o adaptador | adoptado |
| Question/task/plan-first | `assessment/task/plan_first` | adoptado |
| Define done | contrato de terminación con verificaciones nombradas | adoptado |
| Orientación antes de leer | inventario antes de recuperación dirigida | adoptado |
| Fuentes primarias antes de memoria | evidencia con procedencia | adoptado |
| Investigación paralela y acotada | presupuesto de rondas y excepción procedural | adoptado |
| Surprise routing | contradicción como evento que puede cambiar objetivo | adoptado |
| Una recomendación | decisión única con alternativas descartadas | adoptado |
| Authorization gate | grants firmados; documentación nunca autoriza | transformado |
| `AUTH:` textual | `guardian_grant_ref` | reemplazado |
| Intent gate | recibo de comportamiento/check/especificación | transformado |
| Recall gate | fuente abierta o afirmación no verificada | adoptado |
| Smallest correct change | alcance declarado y diff auditado | adoptado |
| Checklist | contrato de ítems y auditoría de omisiones | adoptado |
| Recovery ladder | reintento acotado y retorno a evidencia | adoptado |
| Tres ciclos máximos | presupuesto operativo | adoptado |
| Twin check | búsqueda del patrón gemelo | adoptado |
| Verificación objetivo + sistema | recibo de verificación doble | adoptado |
| `PENDING:` textual | recibo de acción pendiente de grant | reemplazado |
| Outcome-first report | resultado primero, evidencia y caveats después | adoptado |
| Artifact gate | comprobación automática de recibos requeridos | adoptado |
| fable-loop | Planner, Evidence Gatherer, Executor y verificadores adversariales | adaptado |
| fable-judge | Genesis Proof Judge independiente | adoptado |
| Report is claims, not evidence | afirmaciones enlazadas a observaciones reproducibles | adoptado |
| Fraud table | catálogo normativo por dominio | adoptado |
| VERIFIED/CAVEATS/REFUTED | mismos resultados semánticos | adoptado |
| fable-domain | bundle futuro: adapter + trap + smoke eval | adaptado |
| Domain TEMPLATE | evidencia mínima, autoridad, verificación y fraudes | adoptado |
| Red-lines | riesgo y revisión humana cualificada | adaptado |
| Scope-stop | no crear adaptadores redundantes | adoptado |
| Trap fixture | trampas con comportamiento esperado | adoptado |
| Control vs method | comparación en copias limpias | adoptado |
| Pristine diff | el diff prevalece sobre el informe | adoptado |
| Stronger judge | evaluador separado, nunca única prueba | adaptado |
| Multiple seeds | necesarios para afirmaciones superiores a smoke test | adoptado |
| 18 failure modes | registro `failure_mode_id → gate` | adoptado |
| Ocho adaptadores de dominio | normalizados | adoptado |
| Android runtime adapter | adaptador específico del primer cuerpo | añadido |
| Flowcharts | máquina de estados verificable | transformado |
| Worked examples | vectores conductuales | transformado |
| Claude plugin commands | fuera del protocolo neutral | excluido |
| Claude Workflow scripts | runtime específico | excluido |
| Cadenas privadas de razonamiento | no se almacenan ni requieren | excluido |
| Smoke test como benchmark | rechazado | excluido |
| Juez LLM como única prueba | comprobación mecánica primero | excluido |

## Dominios adaptados

```text
coding
marketing_content
research_reporting
data_analysis
business_operations
finance_analysis
legal_compliance_research
design_ux
devops_infrastructure
android_runtime
```

Cada adaptador contiene mínimo de evidencia, orden de autoridad, verificaciones observables y señales de fraude.

## Reglas y camino correcto

Una regla puede estar equivocada o ser demasiado rígida. Génesis puede cuestionarla mediante un `rule_challenge`:

```text
advisory      → excepción razonada
procedural    → excepción local, reversible, acotada y juzgada
capability    → grant firmado del guardián
constitutional→ no anulable por una tarea
```

Así se evita tanto la obediencia ciega a una regla defectuosa como la libertad de ignorar límites sin dejar evidencia.

## Atribución

La fuente está licenciada bajo MIT. Este mapa conserva repositorio, commit y autor. Cualquier incorporación futura de texto o código sustancial deberá conservar el aviso MIT correspondiente.

## Deuda declarada

Pendiente: orquestador real, juez externo aislado, trampas contra modelos reales, múltiples semillas, UI del guardián, integración Android y evaluación longitudinal.
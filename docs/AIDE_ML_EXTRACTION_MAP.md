# Mapa de extracción de AIDE ML hacia Génesis

**Fuente inspeccionada:** `WecoAI/aideml` en el commit `5d66a21771e98623dc9fc8716bdbe388d63464c0`.

**Método:** adaptación de sala limpia. Se estudiaron comportamientos y arquitectura pública; no se incorporó código fuente, prompts literales, formatos internos ni dependencias de AIDE ML. El repositorio fuente está publicado bajo licencia MIT, pero esta fase mantiene una implementación propia y neutral.

## Resultado

| Mecanismo público de AIDE ML | Adaptación en Génesis | Estado |
|---|---|---|
| Objetivo y métrica declarados | Campaña firmada con objetivo, dirección y árbol fuente | Implementado |
| Cada solución es un nodo | Evento append-only con candidato, padre y linaje | Implementado |
| `draft`, `debug`, `improve` | Operadores normativos con reglas reproducibles | Implementado |
| Varios drafts iniciales | `max_drafts` dentro de presupuesto fijo | Implementado |
| Depuración de hojas defectuosas | Hoja `buggy` más antigua con profundidad limitada | Implementado |
| Mejora codiciosa del mejor nodo | Métrica con desempate por secuencia e ID UTF-8 | Implementado |
| Journal de código, salida y métrica | Ledger inmutable con digests, presupuesto y evaluación | Implementado |
| Resumen de intentos | Proyección por linaje, estado, mejor candidato y plateau | Implementado |
| Límite de pasos y timeout | Presupuesto de candidatos, acciones, tiempo, tokens, bytes y costo | Implementado como contrato |
| Captura de salida y excepciones | Digests de salida, artefactos y clase de error | Implementado como contrato |
| Mejor solución exportable | Solicitud `candidate_ready`, nunca fusión directa | Implementado |
| Modelos intercambiables | El protocolo no fija proveedor ni modelo | Implementado |
| Visualizador HTML / Streamlit | Compatible con la proyección; UI específica pendiente | Pendiente |
| Intérprete Python en proceso separado | No se adopta como sandbox de seguridad | Rechazado como frontera suficiente |
| Aleatoriedad, UUID y reloj | Semilla declarada, IDs de entrada y replay | Reemplazado |
| Evaluador de métrica visible | Evaluación pública, privada, generalización, seguridad y mantenibilidad | Reforzado |
| Mutación directa del journal | Cadena append-only firmada | Reemplazado |

## Diferencias deliberadas

### Seguridad

El intérprete de AIDE ML separa el proceso y aplica timeout, pero Génesis exige además red cerrada, filesystem efímero, ausencia de secretos, aislamiento, captura de salida y entorno reproducible. El fixture valida el contrato; no afirma que ese sandbox físico esté desplegado.

### Determinismo

AIDE ML utiliza aleatoriedad, UUID y timestamps del runtime. Génesis requiere que una campaña pueda repetirse con los mismos documentos. Las decisiones no dependen del reloj, proveedor o azar no declarado.

### Autoridad

AIDE ML entrega el mejor programa encontrado. Génesis produce una solicitud de promoción que necesita `code.propose_change`, CI y aprobación final del guardián. El laboratorio no puede fusionar a `main` ni emitirse permisos.

### Evaluación

Una mejora no se define solo por una métrica visible. Debe respetar presupuesto, evaluación privada, generalización, mantenibilidad y ausencia de manipulación o regresión de seguridad.

## Cobertura de esta fase

```text
árbol de candidatos                -> extraído y adaptado
operadores draft/debug/improve     -> extraídos y adaptados
política greedy + debug            -> adaptada de forma reproducible
bifurcación por plateau            -> añadida
journal de resultados              -> reemplazado por ledger append-only
resumen del árbol                  -> reemplazado por proyección verificable
runner de código                   -> contrato definido; runtime real pendiente
evaluador privado                  -> frontera definida; servicio real pendiente
visualización                      -> pendiente
producto Weco / AIDE² completo     -> no está contenido en aideml
```

## Regla de actualización

Los cambios futuros del repositorio fuente se revisan como propuestas nuevas. Ninguna actualización se incorpora automáticamente ni obtiene autoridad por provenir de AIDE ML.

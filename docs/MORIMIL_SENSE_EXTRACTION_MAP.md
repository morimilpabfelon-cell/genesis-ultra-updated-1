# Mapa controlado de extracción de Morimil-app — sentidos y sistemas

## Fuente y regla de autoridad

Fuente revisada: `morimilpabfelon-cell/Morimil-app` en el commit
`4b9848759f12d05ee9ea102f6e448c8be35d49b2`.

Morimil-app es una fuente de experiencia, no la norma. La fuente de verdad continúa siendo
`spec/` + `schemas/` + `conformance/` de Genesis Ultra. No se copiará el repositorio entero,
su base de datos ni su identidad Android. Cada capacidad se reimplementará detrás de un
contrato neutral y deberá superar vectores compartidos.

La identidad de nacimiento, incluido `companion_name`, no se extrae ni se migra desde
Morimil-app. Solo puede provenir del nacimiento canónico definido por Genesis Ultra.

## Criterio de clasificación

Un **sentido** únicamente observa y produce evidencia con procedencia. No modifica identidad,
no escribe directamente en la memoria y no ejecuta acciones externas. El core decide si una
observación se acepta como evento de memoria mediante una compuerta separada.

```text
fuente del cuerpo -> observación con procedencia -> compuerta de memoria -> evento append-only
```

Memoria, cognición, defensa, crecimiento, homeostasis y movilidad son sistemas distintos;
llamarlos sentidos ocultaría límites de autoridad importantes.

## Mapa de rescate

| Avance observado en Morimil-app | Clasificación Genesis | Fuente principal | Decisión |
|---|---|---|---|
| Navegador nativo y evidencia de red | **Vista** | `net/NativeBrowserRuntime.kt`, `net/NetEvidenceProvider.kt`, `ui/NativeWebEvidenceRules.kt` | Reimplementar como observaciones con URL, tiempo, digest y procedencia; nunca como memoria directa. |
| Acciones explícitas en la interfaz | **Tacto** | `ui/` y casos de uso invocados por el usuario | Adaptar después mediante eventos de entrada autorizados, separados de comandos externos. |
| Capacidades y límites del cuerpo | **Propiocepción** | `core/runtime/AppRuntimeCapabilities.kt`, `core/runtime/AppRuntimeGate.kt` | Reimplementar detrás de `HOST_ADAPTER_CONTRACT`; no exportar rutas, cuentas ni handles. |
| Salud de almacenamiento, firmas e integridad | **Interocepción** | `core/memory/MemoryEventIntegrity.kt`, `data/repository/MemoryAppendGate.kt`, reconciliación | Extraer señales de estado; las reparaciones pasan por transacciones y propuestas verificables. |
| Secuencia, recuerdo programado y ciclos | **Sentido temporal** | `RecallSchedulePolicy.kt`, `RecallScheduleRepository.kt`, `RestCyclePolicy.kt` | Adaptar usando tiempo monotónico/firmado del host y registrar incertidumbre temporal. |
| Eventos, enlaces, cápsulas y grafo | **Memoria** | `MemoryOrganRepository.kt`, `KnowledgeCapsuleEntity.kt`, `MemoryLinkEntity.kt` | Reescribir contra schemas neutrales; no importar Room como formato canónico. |
| Recall y consolidación | **Memoria + homeostasis** | `RestCycleMaintenancePlanner.kt`, `RunRestCycleUseCase.kt`, `RestCycleWorker.kt` | Conservar la idea; toda consolidación añade eventos y nunca reescribe historia. |
| Kernel y selección de modelos | **Cognición** | `reasoning/ReasoningKernel.kt`, `ai/ReasoningClient.kt`, perfiles de razonamiento | Mantener motores reemplazables; `engine_id` nunca forma parte de identidad. |
| Constitución e inmunidad | **Defensa** | `core/constitution/CoreConstitutionGuard.kt`, `core/immunity/MorimilImmunePolicy.kt` | Traducir a políticas verificables; no permitir cambios silenciosos de doctrina. |
| Migraciones y propuestas de mejora | **Crecimiento** | `CognitiveMigrationPlanner.kt`, `ImprovementProposalStore.kt`, repositorios de migración | Adaptar como propuesta -> autorización -> aplicación -> evidencia -> rollback. |
| Handoff a PC y agente LAN | **Movilidad y comunicación** | `ui/PcHandoffScreen.kt`, `agent/LanAgentClient.kt`, `agent/LanAgentContract.kt` | Diferir hasta que use transferencia Genesis, registro de cuerpos y un solo escritor. |
| Proyectos y orquestación | **Acción externa** | `ProjectVaultRepository.kt`, `ui/GenesisProjectsScreens.kt` | Diferir; exige permisos específicos, recibos y límites de herramientas. |
| Lectura de manifiesto de Génesis | **Bootstrap histórico** | `data/genesis/GenesisReader.kt` | No copiar como identidad; comparar conceptos y reimplementar contra la semilla canónica actual. |

La voz o el micrófono solo se clasificarán como **oído** cuando exista una implementación
localizable y verificable. Una mención en documentación no basta para importarla ni declararla
implementada.

## Estados de extracción

- **Reimplementar ahora:** vista basada en evidencia, propiocepción e interocepción mínimas.
- **Adaptar después:** tacto, sentido temporal, memoria, homeostasis, cognición y defensa.
- **Diferir:** movilidad LAN/PC y acciones de proyectos hasta cerrar autoridad y permisos.
- **Rechazar:** nombres alternativos persistentes, identidad ligada a Android, escritura directa
  desde un sentido, bases Room como formato portable y motores ligados a la identidad.

## Orden de integración

1. **Completado en el borrador:** schema neutral de observación con procedencia y vectores negativos.
2. **Completado en el borrador:** compuerta firmada que enlaza una observación aceptada con un evento append-only.
3. Conectar primero Vista, Propiocepción e Interocepción mediante adaptadores sustituibles.
4. Añadir Tacto, Oído y sentido temporal solo con permisos y pruebas de privacidad.
5. Integrar memoria, cognición, defensa, crecimiento y movilidad como sistemas separados.

Cada paso debe entrar en este mismo repositorio, con pruebas Python/Node, sin crear otro
`genesis-ultra-*` ni importar archivos heredados sin inventariarlos.

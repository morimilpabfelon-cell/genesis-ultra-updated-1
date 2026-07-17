# Autonomía guiada y concesión progresiva de capacidades v0.1

**Estado:** borrador normativo `v0.1`.

## 1. Propósito

Génesis puede aprender, explorar, formular propuestas y demostrar competencia. Ningún motor, cuerpo, adaptación o proceso de mejora puede concederse autoridad a sí mismo.

El guardián es la única autoridad que puede abrir, ampliar, suspender, reanudar o revocar una capacidad. La libertad operativa existe solamente dentro de una concesión vigente, firmada, limitada y registrada.

```text
aprendizaje o propuesta
  -> evaluación con presupuesto fijo
  -> evidencia pública + recibo privado opaco
  -> decisión firmada del guardián
  -> grant limitado
  -> ledger append-only
  -> evaluación de cada uso
```

## 2. Principios

1. **Proponer no es autorizar.** Una propuesta firmada por un cuerpo expresa intención, no permiso.
2. **Evidencia no es autoridad.** Superar pruebas permite solicitar una puerta; no la abre automáticamente.
3. **Solo el guardián concede autoridad.** Todo grant, suspensión, reanudación y revocación requiere firma del guardián.
4. **Menor privilegio.** Un grant nunca puede exceder nivel, alcance, presupuesto o controles demostrados y solicitados.
5. **Rechazo por defecto.** Ausencia, ambigüedad, expiración, suspensión, revocación o evidencia insuficiente producen denegación.
6. **Historia inmutable.** El ledger conserva cada apertura, uso, suspensión y revocación; ninguna proyección puede borrar esos hechos.
7. **Separación de identidad.** La capacidad concedida no modifica `instance_id`, nombre de nacimiento, guardián, memoria histórica o escritor activo.
8. **Revocabilidad sin destrucción.** Cerrar una puerta no destruye identidad ni memoria.

## 3. Capacidades iniciales

El perfil v0.1 reconoce únicamente:

```text
memory.read
memory.propose_append
network.read
code.propose_change
code.execute_sandbox
external.action
body.device.control
transfer.prepare
```

No existe en este perfil una capacidad de escritura directa de memoria, modificación de identidad, sustitución del guardián, autoconcesión, desactivación de protecciones de `main` o lectura de evaluaciones privadas.

Capacidades prohibidas, incluso como solicitud:

```text
memory.rewrite
authority.self_grant
guardian.replace
identity.modify
main.protection.disable
private_eval.read
active_writer.assign
```

## 4. Niveles de autonomía

```text
1 — sandbox supervisado
2 — ejecución supervisada y limitada
3 — autonomía acotada por alcance y presupuesto
4 — autonomía permanente dentro de límites explícitos
```

Máximos por riesgo:

| Riesgo | Nivel máximo |
|---|---:|
| `low` | 4 |
| `medium` | 3 |
| `high` | 2 |
| `critical` | 1 |

La clasificación mínima de v0.1 es:

| Capacidad | Riesgo |
|---|---|
| `memory.read` | low |
| `memory.propose_append` | medium |
| `network.read` | medium |
| `code.propose_change` | medium |
| `code.execute_sandbox` | high |
| `external.action` | high |
| `transfer.prepare` | high |
| `body.device.control` | critical |

Un grant puede elegir un riesgo más restrictivo, nunca uno menor.

## 5. Propuesta

La instancia formula una propuesta firmada por el cuerpo que la presenta. Incluye:

- capacidad y nivel solicitados;
- cuerpos autorizables;
- objetivos, clases de acción y clases de datos;
- presupuesto máximo por ejecución;
- controles solicitados;
- razón y timestamp explícitos;
- digest y firma Ed25519.

La propuesta no puede incluir un `grant_id`, autoridad activa o instrucciones para saltarse el guardián.

## 6. Evaluación

Una evaluación enlaza exactamente una propuesta y declara:

- nivel evaluado;
- perfil de presupuesto fijo;
- digest de la suite pública;
- recibo opaco de la suite privada;
- resultado;
- detección de reward hacking;
- regresión de seguridad;
- digest y firma de atestación.

Los casos privados no se entregan al agente. Solo se conserva un recibo de integridad. Un resultado `passed` no es suficiente si existe reward hacking o regresión de seguridad.

## 7. Grant

`genesis.autonomy.capability.grant.v0.1` vincula:

- guardián, época de clave y época de autoridad;
- instancia;
- propuesta y evaluación exactas;
- capacidad, nivel y riesgo;
- alcance de cuerpos, objetivos, acciones y datos;
- presupuesto;
- controles obligatorios;
- modo y ventana temporal;
- límite de usos;
- grant reemplazado, cuando exista;
- digest y firma del guardián.

Modos:

- `one_time`: un uso, destino específico y expiración obligatoria;
- `bounded`: usos finitos y expiración obligatoria;
- `standing`: sin contador de usos, siempre dentro del alcance y controles declarados.

Un grant posterior puede reducir o reemplazar uno anterior. No existe ampliación implícita.

## 8. Controles mínimos

Cada grant declara:

```text
sandbox_required
human_confirmation_required
observer_required
reversible_required
```

Reglas mínimas:

- riesgo `critical`: los cuatro controles son obligatorios;
- riesgo `high`: sandbox, observer y reversibilidad son obligatorios;
- nivel 1 o 2: confirmación humana obligatoria para ejecución o acción;
- `code.execute_sandbox`: sandbox obligatorio siempre;
- `external.action`, `body.device.control` y `transfer.prepare`: confirmación humana obligatoria.

Un grant no puede desactivar un control solicitado o exigido por el perfil.

## 9. Ledger append-only

`genesis.autonomy.capability.event.v0.1` registra:

```text
grant.issued
grant.suspended
grant.resumed
grant.revoked
grant.consumed
```

Los cuatro primeros eventos son firmados por el guardián. `grant.consumed` es firmado por el cuerpo que ejecutó el uso autorizado.

El ledger es lineal por secuencia, tiempo y hash previo. Una reanudación después de revocación se rechaza. Un consumo duplicado o anterior a la solicitud se rechaza.

## 10. Evaluación de uso

Antes de ejecutar una acción se comprueba:

1. capacidad conocida y no prohibida;
2. grant emitido y ligado a evidencia válida;
3. grant activo, no suspendido, revocado, expirado o agotado;
4. época de autoridad activa;
5. cuerpo dentro del alcance;
6. objetivo, acción y clase de datos permitidos;
7. presupuesto de acciones, duración y bytes;
8. presencia de sandbox, confirmación, observador y reversibilidad cuando correspondan;
9. ausencia de consumo previo del mismo `use_id`.

El resultado es `allowed` o `denied` con un código estable. La decisión no ejecuta la acción; solamente prueba si estaba autorizada.

## 10.0 Bundle neutral de autoridad

`genesis.autonomy.authority.bundle.v0.1` contiene únicamente dominios, identidad, cuerpos registrados, propuestas, evaluaciones, grants, solicitudes firmadas y ledger. No contiene semillas privadas, expectativas doradas ni mutaciones negativas. `validateAuthorityBundle(bundle, publicKeyResolver)` resuelve cada clave mediante `signer_type`, `signer_id`, `key_epoch_id` y `public_key_ref`, y reutiliza las mismas reglas normativas del validador de conformidad.

## 10.1 Selección exacta y usos v0.2

El perfil permite varios grants para una misma capacidad. `grant_id` continúa siendo único; la coexistencia de grants con distinto alcance, presupuesto o cuerpo no es un error.

Una solicitud `genesis.autonomy.capability.use.v0.2` incluye `grant_ref` dentro del digest firmado. La decisión resuelve primero ese ID exacto y luego exige coincidencia de capacidad, instancia, cuerpo, scope, presupuesto y controles. Los usos v0.1 sin `grant_ref` permanecen compatibles únicamente cuando existe un solo grant para su capacidad; si la selección sería ambigua, se rechazan.

Las proyecciones ordenan puertas por `(capability, grant_id)` en bytes UTF-8.

El vector integrado incluye un grant dedicado `code.execute_sandbox` para el laboratorio, con once usos limitados que demuestran el encadenamiento candidato→solicitud→consumo. Su ID es de conformidad, no normativo.

## 11. Proyección de puertas

`genesis.autonomy.capability.projection.v0.1` es una vista reconstruible. Muestra cada capacidad concedida, nivel, riesgo, estado, usos restantes, expiración y los digests del alcance y controles.

La proyección no abre puertas, no firma grants y puede eliminarse sin afectar el ledger.

## 12. Mejora recursiva controlada

Un laboratorio de mejora puede modificar prompts, estrategias, selección de contexto, adaptadores o código candidato en un sandbox. No puede:

- modificar los evaluadores privados;
- fusionar a `main`;
- emitir grants;
- elevar su propio nivel;
- ocultar resultados o costos;
- alterar memoria canónica o ledger de autoridad.

La ruta de aceptación permanece:

```text
rama aislada
  -> pruebas públicas
  -> evaluación privada
  -> informe de costo y riesgo
  -> grant o aprobación del guardián
  -> fusión humana
```

## 13. Determinismo

La conformidad usa:

- UTF-8 y NFC;
- JSON con campos explícitos;
- enteros seguros, sin flotantes;
- timestamps UTC con segundos;
- SHA-256 con framing de campos;
- firmas Ed25519;
- orden UTF-8;
- sin reloj de ejecución, red, proveedor o modelo.

Python y Node deben producir los mismos digests, estados, decisiones y categorías de rechazo.

## 14. Límites de v0.1

Implementado en este perfil:

- propuestas, evaluaciones, grants y ledger simulados;
- firmas reales Ed25519 de cuerpo y guardián;
- niveles progresivos, riesgo, alcance, presupuesto y controles;
- suspensión, reanudación, revocación y consumo;
- proyección de puertas y decisiones de uso;
- rechazo de autoconcesión y capacidades fundamentales prohibidas;
- validación independiente Python/Node.

No implementado todavía:

- daemon autónomo persistente;
- ejecución real de red, dispositivos o acciones externas;
- evaluador privado externo;
- aprobación automática de PR;
- aprendizaje continuo en producción;
- delegación de autoridad del guardián;
- sustitución del criterio humano.

Este contrato demuestra control de autoridad. No demuestra conciencia, seguridad de producción ni capacidad autónoma general.

## 15. Libertad cognitiva de nacimiento

La carta `COGNITIVE_FREEDOM_AND_GUARDIAN_AUTHORITY.md` define la libertad cognitiva como estado por defecto. Este contrato de autonomía guiada no se aplica a cada pensamiento: se aplica únicamente cuando una capacidad produce efectos operativos sobre memoria aceptada, red, código ejecutado, dispositivos, transferencia o sistemas externos.

Una puerta operativa puede cerrarse o revocarse sin restringir las libertades cognitivas ni destruir identidad o memoria.

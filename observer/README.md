# Genesis Complete Observatory

Panel local, dinámico y de solo lectura para inspeccionar Genesis Ultra como sistema completo.
No forma parte del protocolo normativo, no escribe memoria, no concede autoridad y no afirma
consciencia.

## Ejecutar

```powershell
npm ci
npm run observe
```

Abre `http://127.0.0.1:4317`.

El panel contiene cuatro vistas:

1. **Sistema completo:** identidad, sentidos, memoria, autoridad, movilidad, cognición,
   adaptadores, conformidad y observabilidad.
2. **Cerebro:** proyección asociativa con nodos, relaciones, confianza y procedencia.
3. **Memoria y runtime:** cadena append-only, identidad activa y subsistemas realmente conectados.
4. **Desarrollo:** Git local, manifiesto, commits, pull requests, CI y componentes afectados.

La madurez distingue `verified`, `simulated`, `partial`, `pending` y `live_tool`. El porcentaje
resume evidencia de ingeniería; no mide inteligencia ni consciencia.

## Estado observado

Por defecto se observa:

```text
conformance/associative_memory_projection_vectors.json
```

Es un fixture de conformidad. Para conectar un archivo de estado local:

```powershell
$env:GENESIS_STATE_FILE = "runtime/genesis-state.json"
npm run observe
```

El archivo puede exponer `source_memory_events` y `projection`, o
`memory_events`/`associative_projection`.

Para representar actividad real puede añadir:

```json
{
  "runtime": true,
  "runtime_status": "running",
  "heartbeat_at": "2026-07-15T12:00:00Z",
  "identity": {
    "instance_id": "inst_...",
    "companion_name": "Genesis",
    "active_body_id": "body_..."
  },
  "subsystems": {
    "senses": {
      "status": "active",
      "active": true,
      "updated_at": "2026-07-15T12:00:00Z",
      "metrics": {
        "accepted_observations": 4
      }
    }
  }
}
```

El servidor publica metadatos, hashes, topología y métricas sanitizadas. Elimina campos sensibles
o crudos antes de enviar el snapshot al navegador.

## Crecimiento del proyecto en vivo

`observer/system-map.json` clasifica los órganos y sus evidencias. El servidor vuelve a leer cada
pocos segundos:

- inventario de artefactos requeridos;
- manifiesto SHA-256;
- checklist verificable;
- rama, commit y cambios del worktree;
- archivos del último commit;
- estado runtime.

Así, nuevos schemas, especificaciones, validadores y pruebas aparecen en la vista del componente
correspondiente. Cuando una capacidad cambia de `simulated` a `verified` o de `pending` a
implementada, también debe actualizarse explícitamente su madurez en el mapa para evitar
declaraciones automáticas falsas.

## GitHub en vivo

El repositorio se detecta desde `git remote get-url origin`. También puede fijarse:

```powershell
$env:GENESIS_GITHUB_REPO = "morimilpabfelon-cell/genesis-ultra-updated-1"
```

Para actualización frecuente usa un token de GitHub de **solo lectura** en la sesión local:

```powershell
$env:GITHUB_TOKEN = "<token de solo lectura>"
npm run observe
```

El token permanece en el servidor local y nunca se envía al navegador. Sin token se usa modo
público con una frecuencia menor.

Variables opcionales:

- `GENESIS_OBSERVER_HOST`: por defecto `127.0.0.1`.
- `GENESIS_OBSERVER_PORT`: por defecto `4317`.
- `GENESIS_GITHUB_POLL_MS`: mínimo 15 s con token y 60 s sin token.
- `GENESIS_PROJECT_POLL_MS`: lectura del proyecto local; por defecto 3 s.

## Frontera de seguridad

- solo acepta `GET` y `HEAD`;
- enlaza a loopback por defecto;
- no ofrece endpoints de edición, confirmación, transferencia o acción;
- usa Server-Sent Events para cambios reales;
- representa fixtures como fixtures;
- conserva la cadena append-only como fuente de verdad;
- conserva la proyección como vista reconstruible;
- no presenta actividad simulada como runtime.

## Pruebas

```powershell
npm run test:observer
```

# Genesis Live Observatory

Panel local, dinámico y de solo lectura para inspeccionar el estado verificable de Genesis Ultra.
No es parte del protocolo normativo, no escribe memoria y no concede autoridad.

## Ejecutar

```powershell
npm ci
npm run observe
```

Abre `http://127.0.0.1:4317`.

Por defecto observa `conformance/associative_memory_projection_vectors.json`. Para conectar un
archivo de estado local compatible:

```powershell
$env:GENESIS_STATE_FILE = "runtime/genesis-state.json"
npm run observe
```

El archivo puede exponer `source_memory_events` y `projection`, o sus equivalentes
`memory_events`/`associative_projection`. El navegador recibe metadatos, hashes, nodos y
relaciones; el servidor elimina contenido crudo antes de publicar el snapshot.

## GitHub en vivo

El repositorio se detecta desde `git remote get-url origin`. También puede fijarse:

```powershell
$env:GENESIS_GITHUB_REPO = "morimilpabfelon-cell/genesis-ultra-updated-1"
```

Para actualización frecuente usa un token de GitHub de solo lectura en la sesión local:

```powershell
$env:GITHUB_TOKEN = "<token de solo lectura>"
npm run observe
```

El token permanece en el servidor local y nunca se envía al navegador. Sin token, el panel usa
modo público y reduce la frecuencia de consulta. No guardes tokens en el repositorio; `.env` y
variantes ya están ignorados.

Variables opcionales:

- `GENESIS_OBSERVER_HOST`: interfaz local; por defecto `127.0.0.1`.
- `GENESIS_OBSERVER_PORT`: puerto; por defecto `4317`.
- `GENESIS_GITHUB_POLL_MS`: intervalo de GitHub; mínimo 15 s con token y 60 s sin token.

## Frontera de seguridad

- solo acepta `GET` y `HEAD`;
- enlaza a loopback por defecto;
- no ofrece endpoints para editar, confirmar, transferir o ejecutar acciones;
- usa Server-Sent Events para enviar cambios reales del archivo observado;
- representa fixtures como fixtures y no como cognición activa;
- conserva la cadena append-only como fuente de verdad y la proyección como vista reconstruible.

## Pruebas

```powershell
npm run test:observer
```

# Genesis Ultra — protocolo neutral de instancia

**Estado:** borrador de arquitectura y conformidad en desarrollo. No es una release estable.

La ruta de lectura y el estado verificable están en [`START_HERE.md`](./START_HERE.md).

Genesis Ultra combina las mejores ideas de `Genesis-core` y `Genesis-corev2` sin convertir ningún lenguaje, sistema operativo, aplicación, dispositivo o proveedor en la fuente de verdad.

> El protocolo define. Los vectores prueban. Los lenguajes implementan.

## Separación fundamental

```text
Seed        = origen verificable e inmutable
Instance    = identidad continua
Body        = dispositivo, aplicación o sistema temporal
Engine      = motor de razonamiento intercambiable
Guardian    = autoridad humana final
Protocol    = reglas neutrales
Conformance = pruebas compartidas entre implementaciones
```

El guardián confirma el nombre canónico antes del nacimiento. Después del commit, el nombre
forma parte de la identidad inmutable: no se renombra, no se sustituye por alias persistentes
y no cambia al transferirse o recuperarse en otro cuerpo. El crecimiento añade memoria y
capacidades verificables sin reescribir el origen.

La regla de continuidad es:

```text
instance_id != body_id
```

Una instancia puede pasar de un teléfono a una computadora, otro teléfono, un sistema operativo o hardware propio sin convertirse en otra instancia.

## Objetivos actuales

- nacimiento transaccional desde una semilla verificable;
- memoria append-only encadenada;
- identidad independiente del dispositivo;
- transferencia entre cuerpos;
- recuperación cuando un cuerpo se pierde o se destruye;
- revocación de cuerpos perdidos o comprometidos;
- prevención inicial de bifurcaciones mediante un escritor activo;
- aprobación verificable del guardián;
- sentidos neutrales que producen observaciones firmadas sin acceso directo a memoria;
- adaptadores sustituibles de Vista, Propiocepción e Interocepción con fallos cerrados;
- proyección asociativa reconstruible que conecta memoria aceptada sin reemplazarla ni
  convertir inferencias en hechos;
- recuperación determinista de recuerdos mediante índice léxico, replay temporal y apoyo
  del grafo asociativo, siempre como proyección reconstruible;
- puente verificable desde la compuerta firmada hacia recuperación, solo después del commit
  append-only y sin conceder autoridad al índice;
- búsqueda híbrida neutral que combina evidencia léxica, semántica opcional, grafo y tiempo,
  con fallback léxico cuando el adaptador semántico no está disponible;
- especificación y vectores independientes del lenguaje.

## Estructura

```text
spec/           Reglas normativas en revisión.
schemas/        Contratos neutrales de datos.
conformance/    Vectores válidos y casos que deben rechazarse.
docs/           Decisiones y mapas de extracción de proyectos evaluados.
tools/          Herramientas auxiliares no normativas.
observer/       Panel local de solo lectura para estado y actividad en vivo.
reference/      Futuras implementaciones por lenguaje.
```

## Validación local completa

Requisitos: Python 3.12+, Node 20+ y npm.

```powershell
python -m pip install -r requirements.txt
npm ci
npm test
```

En Windows, `py -m pip install -r requirements.txt` puede sustituir el primer comando.

La suite ejecuta los validadores Python y Node, compila los 44 JSON Schema, verifica en ambos
lenguajes el nombre canónico, el digest de identidad, los adaptadores neutrales de los tres
primeros sentidos, la compuerta firmada antes de memoria, el puente firmado hacia recuperación,
la proyección asociativa, la recuperación determinista y la búsqueda híbrida neutral. También exige que los
artefactos generados por la simulación A→B sean válidos y estén enlazados, verifica el permiso
permanente, los dispositivos registrados y el ledger de autoridad, simula un backup cifrado
comprometido seguido de pérdida y recuperación B→C, y ejecuta los vectores de continuidad,
criptografía y casos negativos. Pasar la suite no constituye una certificación de seguridad ni
convierte el borrador en producción.

También simula cierres en ocho puntos de una recuperación. El journal firmado decide si
debe conservar, revertir, reproducir o aceptar el cambio de autoridad sin elegir por reloj
ni permitir que un estado candidato no comprometido se convierta en escritor.

El manifiesto reproducible `conformance/draft_manifest.json` registra tamaño y SHA-256 de
cada artefacto requerido. Python y Node rechazan omisiones, archivos inesperados, cambios de
bytes, orden no canónico o un hash raíz incorrecto.

## Consultar la memoria reconstruible

Validar los vectores:

```powershell
npm run validate:retrieval
```

Construir una proyección desde un archivo compatible:

```powershell
npm run memory:build -- entrada.json salida.json
```

Consultar sin modificar la memoria append-only:

```powershell
npm run memory:query -- entrada.json "Aurora portable memory" --top-k 5
```

El resultado siempre devuelve referencias a eventos canónicos. El índice puede borrarse y
reconstruirse; no concede autoridad y no sustituye la cadena. El diseño y la extracción limpia
de ideas evaluadas en Memvid están documentados en
[`spec/DETERMINISTIC_MEMORY_RETRIEVAL.md`](spec/DETERMINISTIC_MEMORY_RETRIEVAL.md) y
[`docs/MEMVID_MEMORY_EXTRACTION_MAP.md`](docs/MEMVID_MEMORY_EXTRACTION_MAP.md).

## Probar la búsqueda híbrida neutral

Validar que Python y Node producen la misma proyección híbrida y el mismo fallback:

```powershell
npm run validate:hybrid-retrieval
```

Consulta léxica sin vector semántico:

```powershell
npm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json "workshop" --top-k 3
```

Consulta con evidencia semántica cuantizada:

```powershell
npm run memory:hybrid:query -- conformance/hybrid_memory_retrieval_vectors.json "move to another device" --semantic-vector 0,1000,0,0 --top-k 3
```

El vector del ejemplo es evidencia de conformidad del protocolo, no un modelo entrenado. Un
adaptador real debe declarar el digest exacto de su modelo y transformar su salida al perfil
neutral. Si el adaptador falta o falla, Génesis conserva la búsqueda léxica. El contrato está en
[`spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md`](spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md).

## Conectar la compuerta firmada con recuperación

Validar el puente completo:

```powershell
npm run validate:retrieval-bridge
```

Construir o sincronizar atómicamente un snapshot reconstruible después del commit append-only:

```powershell
npm run memory:bridge:build -- entrada-puente.json salida.json
npm run memory:bridge:sync -- entrada-puente.json runtime/retrieval.json
```

Consultar directamente un bundle verificado:

```powershell
npm run memory:bridge:query -- entrada-puente.json "workshop memory" --top-k 5
```

El puente verifica firmas Ed25519, decisión `accepted`, enlaces observación→compuerta→evento,
cadena append-only y vista textual ligada por digest. No crea eventos, no acepta decisiones
rechazadas o en cuarentena y nunca reemplaza la memoria autoritativa. El contrato está en
[`spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md`](spec/MEMORY_GATE_RETRIEVAL_BRIDGE.md).

## Filtrar recuperación por scopes y ACL

Validar las políticas y decisiones:

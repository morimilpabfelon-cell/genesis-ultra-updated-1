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
- especificación y vectores independientes del lenguaje.

## Estructura

```text
spec/           Reglas normativas en revisión.
schemas/        Contratos neutrales de datos.
conformance/    Vectores válidos y casos que deben rechazarse.
docs/           Decisiones y mapa de extracción de los núcleos anteriores.
tools/          Herramientas auxiliares no normativas.
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

La suite ejecuta los validadores Python y Node, compila los 32 JSON Schema, verifica en ambos
lenguajes el nombre canónico, el digest de identidad, los adaptadores neutrales de los tres
primeros sentidos y la compuerta firmada antes de memoria, y exige que
los artefactos generados por la simulación A→B sean válidos y estén enlazados, verifica
el permiso permanente, los dispositivos registrados y el ledger de autoridad, simula un
backup cifrado comprometido seguido de pérdida y recuperación B→C, y ejecuta los vectores
de continuidad, criptografía y casos negativos. Pasar la suite no constituye una
certificación de seguridad ni convierte el borrador en producción.

También simula cierres en ocho puntos de una recuperación. El journal firmado decide si
debe conservar, revertir, reproducir o aceptar el cambio de autoridad sin elegir por reloj
ni permitir que un estado candidato no comprometido se convierta en escritor.

El manifiesto reproducible `conformance/draft_manifest.json` registra tamaño y SHA-256 de
cada artefacto requerido. Python y Node rechazan omisiones, archivos inesperados, cambios de
bytes, orden no canónico o un hash raíz incorrecto.

## Neutralidad

Kotlin, JavaScript, Python, Swift, Rust, Rego, Java o .NET pueden implementar Genesis Ultra. Ninguno de ellos es Genesis Ultra por sí mismo.

Las implementaciones deben superar los mismos vectores de conformidad y permitir que la instancia salga de su plataforma sin perder identidad ni ocultar discontinuidades.
La frontera obligatoria entre core y plataforma está definida en
[`spec/HOST_ADAPTER_CONTRACT.md`](spec/HOST_ADAPTER_CONTRACT.md): el core conserva estado
portable y cada cuerpo aporta capacidades reemplazables, nunca una cuenta o runtime obligatorio.

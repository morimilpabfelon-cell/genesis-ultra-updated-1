# Genesis Ultra Conformance Kit

Este directorio contiene casos compartidos por todas las implementaciones.

## Regla

Una implementación no es conforme porque use el mismo repositorio o el mismo lenguaje.
Es conforme cuando reproduce los resultados esperados y rechaza los casos inválidos.

## Archivos

- `associative_memory_projection_vectors.json`: proyección reconstruible de memoria aceptada,
  nodos y relaciones por digest, tres niveles de procedencia y rechazos de autoridad o datos
  crudos dentro del grafo.
- `golden_vectors.json`: resultados criptográficos que deben coincidir byte por byte.
- `host_adapter_vectors.json`: anchor portable, declaraciones de capacidades por plataforma
  y rechazos contra dependencias de proveedor o bindings locales dentro del core.
- `instance_identity_vectors.json`: nombre canónico, digest de identidad, continuidad
  Android/Apple/Windows y cambios de identidad que deben rechazarse aunque se recalculen hashes.
- `invalid_cases.json`: entradas que toda implementación debe rechazar con una categoría estable.
- `schema_invalid_cases.json`: cuarenta y un artefactos que los JSON Schema reales deben
  rechazar, con al menos una regresión conectada por cada uno de los 33 schemas.
- `sense_observation_vectors.json`: seis observaciones firmadas, una decisión de compuerta,
  su evento de memoria enlazado y mutaciones que intentan saltarse la frontera.
- `sense_adapter_vectors.json`: adaptadores neutrales simulados de Vista, Propiocepción e
  Interocepción, resultados por digest, fallos cerrados y mutaciones de autoridad.
- `continuity_vectors.json`: hashes compartidos de registro y transferencia.
- `crypto_vectors.json`: digests y algoritmos criptográficos de borrador.
- `draft_manifest.json`: tamaños y hashes reproducibles de todos los artefactos requeridos,
  salvo su propia exclusión explícita.

La simulación A→B también genera y valida registros de dispositivos, autorización de
movilidad y eventos del ledger de autoridad. A partir de su resultado, la simulación
backup→pérdida→recovery crea un backup cifrado con commit firmado, registra un destino C,
declara una brecha y finaliza con un único escritor. Las dos simulaciones negativas llaman
las mismas funciones de evaluación usadas por los flujos positivos.

La simulación de journal corta la operación antes, durante y después del commit. Python y
Node reproducen de forma independiente ocho decisiones de reinicio y verifican la cadena
firmada; trece mutaciones del journal —incluida una firma Ed25519 falsificada— deben ser
detectadas.

Python regenera en memoria el manifiesto de integridad y Node lo recalcula de forma
independiente. Ambos deben coincidir en cobertura, orden, tamaños, digests y hash raíz.

Node reproduce además, sin llamar a Python, todos los vectores compartidos: hashes dorados,
casos inválidos, continuidad, digests de autoridad y los algoritmos Ed25519,
XChaCha20-Poly1305 y Argon2id. Las entradas criptográficas y de continuidad alteradas deben
fallar cerradas.

Python y Node reproducen el mismo anchor portable frente a manifests declarativos de
Android, Apple y Windows. Los fixtures prueban la frontera neutral, pero permanecen en
`declaration_only` hasta que existan adaptadores reales con almacenamiento probado.

Python y Node reproducen también la identidad de nacimiento exacta en esas tres plataformas.
Cambiar nombre, semilla, instancia, guardián o fecha de nacimiento invalida la continuidad;
un digest recalculado no convierte el cambio en válido.

Python y Node verifican de forma independiente las firmas Ed25519 de Vista, Oído, Tacto,
Propiocepción, Interocepción y sentido temporal. También exigen que solo una decisión
`accepted` firmada produzca un evento append-only con contenido y procedencia exactos.

Python y Node reproducen además el mismo contrato de adaptador para Vista, Propiocepción e
Interocepción. Solo una captura válida puede producir una observación firmada; permiso
denegado, fuente no disponible o fallo no producen observación. Estos fixtures permanecen
en `simulated` y no afirman acceso físico a sensores.

Python y Node reconstruyen de forma independiente la misma proyección asociativa desde una
cadena aceptada. La proyección distingue relaciones extraídas, inferidas y confirmadas;
30 mutaciones prueban que no puede introducir identidad, autoridad, contenido crudo,
dependencias de plataforma ni procedencia inventada. Graphify permanece como herramienta
externa de análisis y no forma parte del formato normativo.

## Requisitos para una implementación

Cada implementación debe publicar:

1. lenguaje y versión;
2. plataformas soportadas;
3. nivel de conformidad declarado;
4. comando reproducible de pruebas;
5. resultado de todos los vectores;
6. limitaciones conocidas;
7. versión exacta del protocolo y perfil de hash.

## Prohibiciones

No se permite:

- alterar un vector para hacer pasar una implementación;
- aceptar silenciosamente una entrada que el kit declara inválida;
- normalizar rutas o identidad sin registrar el rechazo o la migración;
- usar resultados dependientes del sistema operativo;
- declarar conformidad parcial como conformidad completa.

## Estado actual

Los vectores son de borrador. Antes de congelarlos deben ampliarse con:

- Unicode extremo;
- límites enteros;
- archivos vacíos y grandes;
- rutas equivalentes y no normalizadas;
- reconciliación completa de bifurcaciones de cadena;
- adaptadores de almacenamiento real por plataforma;
- compatibilidad cruzada entre al menos tres implementaciones independientes.

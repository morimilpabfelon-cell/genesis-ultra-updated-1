# Genesis Ultra Conformance Kit

Este directorio contiene casos compartidos por todas las implementaciones.

## Regla

Una implementación no es conforme porque use el mismo repositorio o el mismo lenguaje.
Es conforme cuando reproduce los resultados esperados y rechaza los casos inválidos.

## Archivos

- `golden_vectors.json`: resultados criptográficos que deben coincidir byte por byte.
- `invalid_cases.json`: entradas que toda implementación debe rechazar con una categoría estable.
- `schema_invalid_cases.json`: artefactos que los JSON Schema reales deben rechazar.
- `continuity_vectors.json`: hashes compartidos de registro y transferencia.
- `crypto_vectors.json`: digests y algoritmos criptográficos de borrador.

La simulación A→B también genera y valida registros de dispositivos, autorización de
movilidad y eventos del ledger de autoridad. Las simulaciones negativas llaman la misma
función de evaluación usada por el flujo positivo.

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
- eventos de transferencia y recuperación;
- firmas y revocación;
- corrupción deliberada;
- bifurcaciones de cadena;
- compatibilidad cruzada entre al menos tres implementaciones independientes.

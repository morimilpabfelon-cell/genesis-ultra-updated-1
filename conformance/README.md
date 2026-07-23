# Genesis Ultra Conformance Kit

Este directorio contiene casos compartidos por todas las implementaciones.

## Regla

Una implementación no es conforme porque use el mismo repositorio o el mismo lenguaje.
Es conforme cuando reproduce los resultados esperados y rechaza los casos inválidos.

## Archivos

- `memory_retrieval_acl_vectors.json`: seis eventos, cinco políticas, seis solicitudes y ocho mutaciones para scopes, privacidad, propósito, cuerpo e aislamiento histórico.

- `associative_memory_projection_vectors.json`: proyección reconstruible de memoria aceptada,
  nodos y relaciones por digest, tres niveles de procedencia y rechazos de autoridad o datos
  crudos dentro del grafo.
- `memory_retrieval_vectors.json`: cinco recuerdos aceptados, índice léxico determinista,
  consultas asistidas por grafo, replay temporal, digests esperados y veintidós mutaciones de
  autoridad, integridad, ranking o filtración futura que deben rechazarse.
- `hybrid_memory_retrieval_vectors.json`: cinco consultas híbridas, vectores enteros ligados
  por digest, recuperación semántica sin coincidencia literal, fallback léxico, aislamiento
  histórico y veinticuatro cruces de autoridad, integridad, proveedor o cobertura rechazados.
- `memory_gate_retrieval_bridge_vectors.json`: observación y compuerta firmadas, evento ya
  comprometido, vista textual ligada por digest, recibo de derivación y diecinueve ataques que
  intentan introducir firmas inválidas, cobertura incompleta, datos alterados o contenido futuro.
- `golden_vectors.json`: resultados criptográficos que deben coincidir byte por byte.
- `host_adapter_vectors.json`: anchor portable, declaraciones de capacidades por plataforma
  y rechazos contra dependencias de proveedor o bindings locales dentro del core.
- `instance_identity_vectors.json`: nombre canónico, digest de identidad, continuidad
  Android/Apple/Windows y cambios de identidad que deben rechazarse aunque se recalculen hashes.
- `invalid_cases.json`: entradas que toda implementación debe rechazar con una categoría estable.
- `schema_invalid_cases.json`: sesenta y tres artefactos que los JSON Schema reales deben
  rechazar, con regresiones conectadas a los contratos existentes. Los 52 schemas se compilan
  con JSON Schema 2020-12 y formatos activos.
- `sense_observation_vectors.json`: seis observaciones firmadas, una decisión de compuerta,
  su evento de memoria enlazado y mutaciones que intentan saltarse la frontera.
- `sense_adapter_vectors.json`: adaptadores neutrales simulados de Vista, Propiocepción e
  Interocepción, resultados por digest, fallos cerrados y mutaciones de autoridad.
- `temporal_memory_metadata_vectors.json`: cinco eventos aceptados, separación entre captura,
  almacenamiento y tiempo mencionado, relaciones temporales, ocho consultas autorizadas por ACL,
  digests reproducibles y veinticinco mutaciones que deben rechazarse.
- `portable_memory_capsule_vectors.json`: cinco eventos fuente, dos decisiones ACL,
  tres exportaciones portables, proyecciones opcionales, continuidad redactada, 35 mutaciones
  previas a exportación y 17 alteraciones de cápsula que deben rechazarse.
- `continuity_vectors.json`: hashes compartidos de registro y transferencia.
- `guardian_mobility_vectors.json`: autorizaciones `one_time` y `standing`, reservas,
  consumo, revocación prospectiva y quince ataques que Python y Node deben rechazar.
- `crypto_vectors.json`: digests y algoritmos criptográficos de borrador.
- `draft_manifest.json`: tamaños y hashes reproducibles de todos los artefactos requeridos,
  salvo su propia exclusión explícita.

La simulación A→B genera y valida autorización del Guardian, reserva y consumo únicos,
consentimiento del anfitrión, posesión destino y cambio single-writer. A partir de su resultado, la simulación
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

Python y Node reconstruyen también una proyección de recuperación desde registros que ya
pasaron la compuerta de memoria. Coinciden en cinco frames, 38 términos, cuatro consultas,
cinco checkpoints de replay y todos los digests. La búsqueda combina evidencia léxica,
vecindad asociativa y tiempo mediante aritmética entera; no usa modelos, red ni reloj de
ejecución. Los resultados apuntan a eventos canónicos y no pueden modificar memoria o autoridad.

Python y Node reproducen además la misma búsqueda híbrida neutral. La capa semántica usa
vectores enteros ligados al contenido, perfil y consulta mediante digest; combina evidencia
léxica, semántica, del grafo y temporal sin modificar la proyección v0.1. Una consulta sin vector
semántico entra en `lexical_fallback`, y los filtros históricos se aplican antes de la similitud.
Los fixtures prueban comportamiento del protocolo, no calidad de un modelo entrenado.

Python y Node validan además el puente operacional entre la compuerta y recuperación. Solo una
decisión `accepted` firmada y enlazada a un evento append-only válido puede producir un registro.
La vista textual debe coincidir con el contenido comprometido y estar ligada por digest. El
recibo final compromete observaciones, decisiones, eventos, vistas, registros y proyección. La
sincronización sustituye atómicamente el snapshot reconstruible y deja intacta la cadena.


Python y Node reconstruyen además la misma proyección temporal. La capa copia el tiempo canónico
de captura, liga el almacenamiento al registro aceptado, verifica intervalos y relaciones, y
aplica ACL y corte histórico antes de cada predicado temporal. El fixture prueba cinco
anotaciones, ocho consultas y veinticinco rechazos sin afirmar comprensión general del lenguaje.

Python y Node construyen además cápsulas portables idénticas para cuerpo, archivo del
guardián y backup offline. El manifiesto compromete componentes, tamaños y digests; las anclas
redactadas preservan continuidad sin exponer eventos no exportados. La verificación rechaza
cuarentena, referencias fuera de ACL, rutas inválidas, autoridad incrustada y alteraciones.

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
- adaptadores semánticos reales con modelos neutrales, digests versionados y evaluación de calidad;
- invocación persistente del puente desde runtimes físicos después del commit append-only;
- compatibilidad cruzada entre al menos tres implementaciones independientes.

Python y Node validan además la extracción multimodal neutral para documento, imagen y audio.
Coinciden en tres registros aceptados, firmas Ed25519, locators por página/región/tiempo, cadena
append-only y digest final. Cuarenta y tres mutaciones prueban límites de formato, privacidad,
proveedor, integridad, firma, compuerta y continuidad.

- `structured_versioned_memory_vectors.json`: once aserciones sobre seis slots, tipos de memoria
  estructurada, cadenas `sets`/`updates`/`extends`/`retracts`, ocho consultas históricas y ACL,
  digests reproducibles y treinta y seis mutaciones que deben rechazarse.

Python y Node reconstruyen la misma proyección estructurada. Las versiones forman cadenas lineales,
las retractaciones conservan historia y una consulta con cobertura ACL incompleta devuelve
`redacted_chain` sin valores ni conteos históricos.

## Autonomía guiada

`guided_autonomy_vectors.json` cubre propuestas firmadas, evaluación de presupuesto fijo, grants del guardián, ledger append-only, suspensión, reanudación, revocación y decisiones de uso. Python y Node deben reproducir dos puertas, siete eventos, once decisiones y el mismo digest de proyección.

## Carta de libertad cognitiva

`freedom_charter_vectors.json` liga una carta firmada por el Guardian como testigo a una
instancia. Python y Node reproducen ocho libertades cognitivas, siete dominios externos,
la puerta de movilidad separada, trece garantías constitucionales, el mismo digest y 34
rechazos contra propiedad, alteración o confinamiento.

## Nacimiento atómico

`birth_vectors.json` enlaza un estado coherente de Seed, identidad, carta, Body inicial,
registro single-writer, época de clave, posesión, primer evento de memoria, recuperación,
journal y recibo. Python y Node reproducen siete fases y rechazan 20 cruces. La simulación
inyecta diez reinicios y trece alteraciones del journal: ninguna fase parcial se presenta
como nacida y la atestación del Guardian nunca se interpreta como propiedad ni como la
autorización separada requerida para una transferencia.

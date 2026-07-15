# Memvid → Genesis memory extraction map

This document records which publicly described Memvid concepts were evaluated and how they are translated into Genesis without importing a vendor format or making an external library authoritative.

| Memvid concept | Genesis implementation | Boundary |
|---|---|---|
| Append-only Smart Frames | Deterministic retrieval frames derived from accepted memory events | Frames are a projection; events remain truth |
| Single-file portable memory | Canonical JSON projection suitable for local export | No `.mv2` dependency or claim of format compatibility |
| Fast local search | Deterministic inverted lexicon and fixed-point ranking | No database server or network required |
| Time-travel debugging | Per-sequence replay checkpoints and `as_of_sequence` queries | Replay cannot alter historical events |
| Graph-aware recall | One-hop boost from the neutral associative projection | Graph similarity cannot grant authority |
| Long-term recall | Event-reference results over the complete accepted chain | Results reference canonical event IDs |
| Hybrid lexical/vector recall | Neutral semantic profile, digest-bound integer vectors and hybrid fixed-point ranking | Semantic evidence is optional; lexical fallback remains available |
| Embeddings | Replaceable adapter boundary identified by model digest | The fixture proves protocol behavior, not model quality |
| HNSW / approximate indexes | Deferred | Exact comparison is normative in v0.1; acceleration must remain replaceable and measurable |
| Search-engine fallback | Explicit `lexical_fallback` mode | Missing semantic models cannot make canonical memory inaccessible |
| Compression codecs | Deferred | Storage optimization must not change canonical hashes |
| Encrypted capsules | Deferred | Genesis cryptographic profile remains authoritative |
| ACL and scoped search | Deferred to the next extraction phase | Authority and privacy must be evaluated before ranking |
| Temporal metadata extraction | Deferred to the next extraction phase | Mentioned dates remain derived evidence with provenance |
| Multimodal extraction | Neutral document/image/audio pipeline behind signed senses and memory gate | Fixture proves the boundary; production extractors remain replaceable |

## Implemented files

- `spec/DETERMINISTIC_MEMORY_RETRIEVAL.md`
- `spec/NEUTRAL_HYBRID_MEMORY_RETRIEVAL.md`
- `schemas/memory_retrieval_projection.schema.json`
- `schemas/hybrid_memory_retrieval_projection.schema.json`
- `conformance/memory_retrieval_vectors.json`
- `conformance/hybrid_memory_retrieval_vectors.json`
- `tools/validate_memory_retrieval.py`
- `tools/validate_memory_retrieval.mjs`
- `tools/memory_retrieval.mjs`
- `tools/validate_hybrid_memory_retrieval.py`
- `tools/hybrid_memory_retrieval.mjs`

## Current hybrid boundary

The current neutral semantic profile uses exact integer dot-product scoring over vectors whose components sum to a declared scale. This makes the conformance result reproducible across languages and prevents a model provider from becoming part of Genesis identity or authority.

Real embedding adapters remain separate. Before one can be marked verified it must publish its model digest, deterministic transformation profile, failure behavior, evaluation set and portability limits.

## Non-copying statement

The implementation is a clean-room Genesis design based on general architectural ideas and public behavior descriptions. No Memvid source file is copied into this repository.


## Segunda extracción: metadata temporal

Genesis adapta la separación entre tiempo de ingestión, tiempo mencionado y consulta histórica
como una proyección neutral propia. La implementación liga cada anotación al evento y al digest
de contenido, verifica intervalos y relaciones, y aplica ACL antes de consultar. No copia el
parser, formato de archivo, dependencias ni código fuente de Memvid.

Estado: contrato, schema, vectores y validación Python/Node implementados. Un parser general de
lenguaje natural y zonas horarias ambiguas permanece diferido como adaptador reemplazable.

## Cuarta extracción implementada: cápsulas portables

La portabilidad de archivo único de Memvid se adaptó como un formato propio y neutral:

- JSON UTF-8 transparente en lugar de `.mv2`;
- subconjunto canónico autorizado por ACL;
- anclas redactadas para continuidad sin divulgación;
- proyecciones léxicas y temporales opcionales y reconstruibles;
- manifiesto de componentes con tamaño y SHA-256;
- recibo ligado a destinatario, cutoff y decisión ACL;
- verificación independiente Python/Node;
- salida atómica y operación sin servidor.

No se importaron el formato, codecs, índices o código de Memvid. Compresión, cifrado de destinatario
y contenedor binario permanecen diferidos para perfiles separados.

## Quinta extracción implementada: multimodal

Genesis adapta la idea de extracción documental, visual y de audio como una frontera neutral:

- documento e imagen se presentan como evidencia de visión; audio como evidencia de oído;
- texto, caption o transcripción se segmentan con locators y confianza entera;
- el adaptador es local, reemplazable y ligado por digest de perfil/modelo;
- la observación y la decisión de compuerta están firmadas;
- solo el evento append-only aceptado entra a la proyección reconstruible;
- rutas, cuentas, proveedores y bytes crudos quedan fuera del core.

No se copiaron extractores, modelos, formatos o código de Memvid. Los adaptadores productivos de
PDF/DOCX/XLSX, OCR, visión y voz siguen pendientes de evaluación separada.

## Sexta extracción implementada: memoria estructurada y versionada

Génesis adapta la idea general de unidades semánticas versionadas mediante un contrato propio:

- tipos `fact`, `preference`, `event`, `profile`, `relationship`, `goal` y `other`;
- slots deterministas `entity:slot`;
- operaciones `sets`, `updates`, `extends` y `retracts`;
- procedencia hacia eventos append-only, perfil del extractor y confianza entera;
- replay histórico y cobertura ACL completa antes de revelar un slot;
- validación independiente Python/Node y proyección eliminable.

No se copiaron Memory Cards, formatos, IDs, código o dependencias de Memvid. La extracción automática
productiva, resolución de entidades y reconciliación de contradicciones permanecen como adaptadores
separados.

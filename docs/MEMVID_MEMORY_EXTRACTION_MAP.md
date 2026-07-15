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
| Multimodal extraction | Deferred | Sense adapters and memory gate remain the ingestion boundary |

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

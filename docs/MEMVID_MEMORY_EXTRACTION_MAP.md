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
| Embeddings / HNSW | Deferred | Model and index profiles require a separate neutral adapter |
| Compression codecs | Deferred | Storage optimization must not change canonical hashes |
| Encrypted capsules | Deferred | Genesis cryptographic profile remains authoritative |
| Multimodal extraction | Deferred | Sense adapters and memory gate remain the ingestion boundary |

## Implemented files

- `spec/DETERMINISTIC_MEMORY_RETRIEVAL.md`
- `schemas/memory_retrieval_projection.schema.json`
- `conformance/memory_retrieval_vectors.json`
- `tools/validate_memory_retrieval.py`
- `tools/validate_memory_retrieval.mjs`
- `tools/memory_retrieval.mjs`

## Non-copying statement

The implementation is a clean-room Genesis design based on general architectural ideas and public behavior descriptions. No Memvid source file is copied into this repository.

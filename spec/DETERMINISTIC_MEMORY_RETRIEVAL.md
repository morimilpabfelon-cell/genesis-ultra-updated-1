# Deterministic Memory Retrieval Projection v0.1

Status: `v0.1-draft`

## Purpose

This specification defines a portable, deterministic and rebuildable retrieval layer for accepted Genesis memory. It adds local lexical recall, graph-aware ranking and temporal replay without changing the authority model.

The append-only memory chain remains the historical source of truth. A retrieval projection is a read model. It can be deleted, rebuilt or replaced without changing identity, guardian authority, body status, mobility or canonical memory.

## Design sources and clean-room boundary

The design adopts general ideas demonstrated by append-only single-file memory systems such as Memvid: immutable frames, timeline replay, local retrieval and portable indexing. This implementation was written independently for Genesis. It does not copy Memvid source code, does not use the `.mv2` format and does not add a Memvid runtime dependency.

## Inputs

A builder consumes:

1. a continuous, valid append-only sequence of `genesis.memory.event.v0.1` events;
2. exactly one accepted retrieval record for each covered event;
3. an optional associative projection used only for graph-aware ranking;
4. zero or more retrieval queries used as deterministic conformance vectors.

An accepted retrieval record contains:

- the canonical event reference;
- the memory-gate decision reference that allowed indexing;
- the event content digest;
- a normalized textual view of accepted content;
- the acceptance timestamp.

Rejected observations, secrets, credentials, private keys and content that never passed the memory gate must not become retrieval records.

## Deterministic tokenization

The v0.1 tokenizer:

1. requires NFC input;
2. applies Unicode case folding;
3. decomposes with NFKD;
4. removes combining marks;
5. extracts only `[a-z0-9]+` tokens;
6. preserves token frequency;
7. sorts unique terms by UTF-8 byte order.

This intentionally limited profile avoids hidden language models, provider-specific tokenizers and platform-dependent stemming.

## Retrieval frames

Each accepted event creates one immutable retrieval frame containing only:

- frame ID;
- event ID and sequence;
- observation timestamp;
- content digest and content type;
- token count;
- sorted term-frequency pairs.

A frame does not contain raw accepted text, embeddings, file paths, credentials or platform handles. Results always refer back to canonical event IDs.

## Lexicon

The projection contains a sorted inverted lexicon. Each entry records:

- term;
- document frequency;
- canonical event references containing the term.

The lexicon is derived data and has no write authority.

## Temporal replay

A checkpoint is produced at every covered sequence. Its digest commits to the ordered frame IDs visible at that sequence. Queries include `as_of_sequence`; future frames are excluded from candidate counts, document frequencies and results.

This gives deterministic replay of earlier retrieval states without rewriting history.

## Hybrid ranking

For each candidate at or before `as_of_sequence`:

### Lexical score

```text
rarity = floor((candidate_count + 1) * 100000 / (document_frequency + 1))
tf_weight = floor(term_frequency * 1000 / (term_frequency + 1))
term_score = floor(rarity * tf_weight / 1000)
lexical_score = sum(term_score)
```

### Graph score

```text
300000  candidate is an anchor event
180000  candidate is a one-hop associative neighbor of an anchor
0       otherwise
```

### Temporal score

```text
temporal_score = floor((sequence + 1) * 100000 / (as_of_sequence + 1))
```

### Final score

```text
score = lexical_score * 7 + graph_score * 2 + temporal_score
```

Candidates with neither lexical nor graph evidence are omitted. Results sort by descending score, then descending sequence, then event ID in UTF-8 byte order.

The ranking is deterministic evidence selection. It is not truth, authority, permission or a final decision.

## Digests

All IDs and digests use `genesis.hash.fields.v0.1` length-prefixed UTF-8 framing with SHA-256. The projection digest commits to:

- source boundaries;
- ordered frame IDs;
- the complete lexicon;
- replay checkpoints;
- deterministic query-result digests.

Python and Node must independently reconstruct the same projection and query results.

## Forbidden authority and platform coupling

A conforming retrieval projection must reject:

- companion name, guardian, seed or active-writer authority;
- raw text, payloads or embeddings in the output projection;
- vendor or platform profiles;
- broken source chains or altered event hashes;
- retrieval records not linked to accepted canonical events;
- future leakage during replay;
- noncanonical term order, frequencies, rankings or digests.

## Current scope

Implemented in v0.1:

- immutable deterministic frames;
- inverted lexical index;
- fixed-point ranking;
- graph-aware one-hop boost;
- temporal replay checkpoints;
- local build and query CLI;
- independent Python and Node conformance.

Not implemented in v0.1:

- vector embeddings;
- approximate-nearest-neighbor indexes;
- compression codecs;
- binary single-file capsules;
- multimodal ingestion;
- model-based entity extraction.

Those capabilities may be added later behind neutral, optional adapters. They must remain rebuildable and non-authoritative.

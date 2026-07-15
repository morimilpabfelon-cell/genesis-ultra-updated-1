# Neutral Hybrid Memory Retrieval v0.1

Status: `v0.1-draft`

## Purpose

This profile adds optional semantic evidence to the deterministic lexical, graph-aware and temporal retrieval model. It does not replace accepted memory, the memory gate, the append-only event chain or the deterministic v0.1 lexical projection.

The required dependency order is:

```text
accepted append-only events
  -> deterministic lexical projection v0.1
  -> optional semantic adapter evidence
  -> hybrid read-only projection
```

The lexical v0.1 projection remains independently reconstructible. A semantic adapter can be removed without making memory unreadable.

## Neutral semantic profile

A semantic profile commits to:

- adapter profile;
- model digest;
- vector dimensions;
- integer vector scale;
- similarity profile;
- profile digest.

The draft conformance adapter is:

```text
genesis.memory.semantic.simplex_u16.v0.1
```

It uses non-negative portable integers. Every vector has the declared number of dimensions, every component is between zero and `vector_scale`, and the components sum exactly to `vector_scale`.

The conformance profile uses this representation because it is reproducible in Python, Node and future languages without floating-point disagreement. It does not claim that the fixture is a trained embedding model.

A future local model adapter may transform model output into the same neutral representation, but must publish a stable model digest and pass independent evaluation before it can be marked verified.

## Binding rules

Every semantic memory vector is bound to:

- semantic profile digest;
- canonical event ID;
- canonical event content digest;
- dimensions and vector components.

Every semantic query vector is bound to:

- semantic profile digest;
- query ID;
- digest of the exact query text;
- dimensions and vector components.

Changing text, event content, model profile or vector data invalidates the corresponding digest.

## Complete memory coverage

When semantics are enabled, every accepted source event must have exactly one semantic frame. Missing, duplicated, unknown or content-mismatched frames fail closed.

Semantic vectors are not included directly in the public projection. The projection exposes only event IDs and vector digests. This supports audit and reconstruction without treating the derived vector as canonical memory.

## Similarity

For vector scale `S`, query vector `Q` and memory vector `M`:

```text
dot = sum(Q[i] * M[i])
semantic_score = floor(dot * 100000 / (S * S))
```

The score range is `0..100000`. Integer arithmetic is mandatory.

This v0.1 profile uses exhaustive exact comparison. It does not use HNSW or another approximate nearest-neighbor index. Approximate indexes may be added later only as replaceable acceleration layers whose results are checked against declared recall and determinism requirements.

## Hybrid ranking

For each event visible at `as_of_sequence`:

```text
score = lexical_score * 7
      + semantic_score * 6
      + graph_score * 2
      + temporal_score
```

An event is a candidate result when lexical, semantic or graph evidence is non-zero. Ties are resolved by:

1. greater total score;
2. greater event sequence;
3. UTF-8 byte order of event ID.

Each result reports its separate lexical, semantic, graph and temporal scores. Semantic similarity is evidence for retrieval, not evidence that a statement is true.

## Lexical fallback

Semantic evidence is optional.

When no semantic query vector is supplied:

```text
mode = lexical_fallback
semantic_query_digest = null
semantic_score = 0
```

When the complete semantic profile is disabled, all queries must continue through lexical and graph-aware retrieval. Semantic frames or query vectors are forbidden while the profile is disabled.

A missing model, unavailable accelerator or adapter failure therefore cannot make the canonical memory inaccessible.

## Historical isolation

`as_of_sequence` is applied before semantic scoring. Events after the requested sequence are not candidates even when their vectors are an exact semantic match.

Semantic retrieval may not leak future events into a historical replay.

## Authority boundary

The hybrid projection may not contain or modify:

- canonical companion name;
- seed or identity digest;
- guardian authority;
- active writer;
- body registry or authority epoch;
- raw payloads, credentials or platform handles;
- append-only events.

Search ranking does not confirm an inference, grant permission, write memory or select a body.

## Portability and vendor neutrality

The protocol does not require Memvid, `.mv2`, Tantivy, HNSW, ONNX, OpenAI or any named model. An implementation may use those technologies behind an adapter, but the core receives only data conforming to the neutral profile.

The model is identified by digest rather than provider name. Vendor-specific fields are rejected by conformance.

## Conformance

Python and Node must independently reproduce:

- semantic profile, frame and query digests;
- semantic-only retrieval without a literal match;
- combined lexical and semantic ranking;
- lexical fallback;
- graph-aware fallback;
- historical filtering before semantic scoring;
- complete semantic frame coverage;
- the same hybrid projection digest;
- all required negative cases.

Passing these vectors proves only deterministic draft behavior. It does not prove semantic quality, model safety, production performance or security.

# Temporal Memory Metadata v0.1

Status: `v0.1-draft`

## Purpose

This profile adds temporal evidence to accepted Genesis memory without changing canonical event
timestamps. It distinguishes:

- `capture_time`: when the source event says the observation occurred;
- `storage_time`: when the accepted record entered the rebuildable retrieval layer;
- `mentioned_start` and `mentioned_end`: an explicit or derived time mentioned by content;
- temporal relations between accepted events;
- query time and historical visibility.

The dependency order is:

```text
accepted append-only events
  -> signed memory-gate acceptance
  -> retrieval ACL decision
  -> temporal annotation adapter
  -> read-only temporal projection
  -> temporal query results
```

Temporal metadata is evidence for retrieval. It is not identity, authority, permission, or proof
that a statement is true.

## Canonical time versus mentioned time

`observed_at` remains part of the canonical memory event. This profile copies it into
`capture_time` and rejects any mismatch.

`storage_time` is copied from the accepted retrieval record. It must not precede capture time.

A date mentioned inside content is separate:

```text
capture_time   = when the event was observed
storage_time   = when the accepted view was stored
mentioned time = what the accepted content refers to
```

No annotation may rewrite `observed_at`, event sequence, content digest, or event hash.

## Adapter boundary

The core does not parse natural-language dates in this profile. A replaceable adapter proposes:

- mention kind: `instant`, `interval`, or `none`;
- normalized UTC start and end;
- precision: `second`, `day`, `month`, or `unknown`;
- relation and related event;
- source kind and confidence;
- extractor and evidence digests.

The core verifies exact bindings, timestamp syntax, interval order, relation consistency,
coverage, confidence bounds, and annotation digests.

The conformance adapter profile is:

```text
genesis.memory.temporal.explicit_adapter.v0.1
```

It demonstrates the protocol with fixed evidence. It does not claim general natural-language
understanding.

## Mention kinds

### Instant

`mentioned_start` and `mentioned_end` are the same canonical timestamp.

### Interval

Both timestamps are present and start is strictly earlier than end.

### None

Both timestamps are null. Precision is `unknown`, relation is `none`, source kind is
`no_temporal_claim`, and confidence is zero.

## Relations

Supported relations are:

- `before`;
- `after`;
- `during`;
- `overlaps`;
- `same_time`;
- `none`.

Relations must point to another accepted event with temporal range evidence. The declared
ranges must satisfy the relation mathematically. A contradictory relation fails closed.

## Provenance

Each annotation binds:

- canonical event ID;
- canonical content digest;
- capture and storage times;
- normalized mentioned interval;
- precision;
- relation and related event;
- source kind;
- integer confidence in `0..1000`;
- extractor digest;
- evidence digest.

The resulting `tmsha256:` digest makes later changes detectable. Raw source spans are not
required in the projection.

## ACL and historical isolation

Every query references a verified access decision containing:

- `as_of_sequence`;
- authorized event references;
- a deterministic decision digest.

Evaluation order is mandatory:

```text
canonical event sequence
  -> historical cutoff
  -> ACL allowed event references
  -> temporal predicate
  -> result digest
```

An unauthorized or future event cannot reappear because it matches a date. An anchor for
`before_event` or `after_event` must itself be authorized and historically visible.

## Query types

- `captured_between`: compare canonical capture times;
- `stored_between`: compare accepted storage times;
- `mentioned_between`: return mentioned intervals overlapping a requested range;
- `before_event`: compare mentioned ranges against an authorized anchor;
- `after_event`: compare mentioned ranges against an authorized anchor;
- `active_at`: return mentioned intervals containing one timestamp.

Results preserve canonical event order and report denial counts for:

- future events;
- ACL-denied events;
- authorized events without a temporal match.

## Determinism

All timestamps use canonical UTC second precision:

```text
YYYY-MM-DDTHH:MM:SSZ
```

No local timezone, runtime clock, floating-point confidence, locale parser, or provider-specific
date service participates in conformance. Python and Node must produce identical annotation,
access, query, projection, and result digests.

## Authority boundary

Temporal metadata may not contain or modify:

- canonical name or seed;
- active writer;
- guardian keys;
- memory write permission;
- body authority;
- append-only event content;
- ACL policy authority.

Temporal ranking or a temporal relation does not authorize an action.

## Rebuildability

The projection can be deleted and reconstructed from:

- accepted event references;
- accepted record timestamps and text digests;
- adapter evidence;
- ACL decisions;
- query definitions.

Atomic `sync` replaces only the derived projection file. It never edits the append-only chain.

## Deferred work

This profile does not yet provide:

- a general natural-language temporal parser;
- timezone inference from ambiguous text;
- recurrence rules;
- uncertain probability distributions;
- calendar-provider integration;
- automatic correction of contradictory memories;
- a persistent runtime daemon.

Those capabilities require separate adapters, evaluation datasets, privacy review, and explicit
failure behavior.

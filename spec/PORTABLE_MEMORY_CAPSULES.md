# Portable Memory Capsules v0.1

Status: `v0.1-draft`

## Purpose

This profile packages an authorized subset of accepted Genesis memory into a portable,
self-verifying JSON capsule. The capsule can be copied between bodies, stored offline, or
inspected without a database server.

A capsule is not the instance. It does not grant authority, writer status, guardian power, or
permission to append memory.

## Dependency order

```text
canonical append-only memory
  -> historical cutoff
  -> retrieval ACL decision for transfer_export
  -> explicit export request
  -> authorized canonical subset
  -> optional rebuildable projections
  -> deterministic manifest
  -> export receipt
  -> portable capsule
```

The ACL and historical cutoff are evaluated before any content enters the capsule.

## Format

The initial neutral format is a single UTF-8 JSON document:

```text
*.gencap.json
```

The format label is:

```text
genesis-portable-json-capsule
```

This is deliberately transparent. Binary packing, compression, streaming, and random-access
containers remain separate future profiles.

## Capsule contents

A capsule contains:

- capsule and profile identifiers;
- source instance ID;
- export request and recipient binding;
- source chain cutoff and tip hash;
- included canonical event entries;
- redacted continuity anchors for non-exported events;
- logical components and their source event references;
- a deterministic file manifest;
- an ACL-linked export receipt;
- a capsule digest.

## Included events and redacted anchors

Every source sequence up to `source_as_of_sequence` is represented.

An authorized and requested event is an `included_event` carrying:

- canonical event ID and hash;
- previous event hash;
- body and canonical observation time;
- privacy class;
- content type, content digest, and content;
- a capsule entry digest.

A source event that is not exported becomes a `redacted_anchor`. It carries only:

- sequence;
- canonical event hash;
- previous event hash;
- the fixed reason `not_exported`;
- a capsule entry digest.

This preserves visible chain continuity without disclosing the omitted content or event ID.

## Authorization boundary

The export request must reference a retrieval ACL decision whose purpose is exactly:

```text
transfer_export
```

Every included event must be:

- known to the source chain;
- at or before the ACL `as_of_sequence`;
- listed in `allowed_event_refs`;
- explicitly requested;
- not `quarantined`.

The capsule does not authenticate the operating-system user or network caller. The host remains
responsible for authenticating the requester before invoking the exporter.

## Components

Mandatory logical components are:

```text
events/accepted.json
chain/continuity.json
receipts/access.json
```

Optional rebuildable components are:

```text
projections/retrieval.json
projections/temporal.json
```

Every component declares:

- a neutral path;
- role;
- media type;
- canonical source event references;
- canonical JSON payload digest;
- payload.

A component cannot reference an event that is not included in the capsule.

## Manifest

The manifest records each logical component with:

- path;
- role;
- media type;
- canonical payload byte length;
- SHA-256 digest.

Files are sorted by UTF-8 path order. The root manifest digest is calculated with the Genesis
field-framing profile. Python and Node must reproduce the same bytes, sizes, ordering, and digest.

## Export receipt

The receipt binds:

- capsule ID;
- export request;
- recipient type and ID;
- source chain tip;
- manifest root;
- ACL decision digest.

The receipt is an integrity commitment, not an authority grant. A future signed-export profile may
add a guardian or writer signature without changing this authority boundary.

## Rebuildability

The canonical subset is the only non-derived memory payload inside the capsule.

Retrieval and temporal projections are marked `rebuildable_projection`. They may be deleted and
regenerated from the included events by compatible adapters. Their presence improves startup and
offline inspection but does not make them authoritative.

The capsule itself never modifies the source chain. Importing a capsule into another body requires
a separate validated import transaction and must not silently append or overwrite memory.

## Atomic output

`build` and `sync` validate the source document before writing. Output is written to a temporary
file, flushed, and renamed over the destination.

A failure before rename leaves the previous capsule untouched.

## Determinism

Conformance uses:

- UTF-8;
- NFC text;
- canonical JSON with recursively sorted keys;
- no floating-point values;
- explicit timestamps supplied by the request;
- domain-separated SHA-256 field hashes;
- UTF-8 path ordering;
- no runtime clock, network, model, or provider.

## Forbidden authority fields

Capsules and component payloads must reject fields such as:

- `active_writer`;
- `write_memory`;
- `authority_grant`;
- guardian or private keys;
- seed roots;
- passwords, tokens, or secrets.

A capsule may identify a recipient but cannot make that recipient an active writer.

## Verification

A verifier checks:

1. exact schema and profile;
2. entry sequence and chain linkage;
3. content digests and entry digests;
4. absence of quarantined included events;
5. component paths, ordering, source references, sizes, and digests;
6. manifest root;
7. receipt bindings and digest;
8. capsule ID and final digest;
9. absence of authority-bearing fields.

Verification proves internal consistency of the capsule. It does not prove the truth of memory
content or physical possession of the source body.

## Conformance fixture

The fixture includes:

- five source events;
- two ACL decisions;
- three export requests;
- full, minimal, and historical capsules;
- retrieval and temporal projections;
- redacted continuity anchors;
- 35 source-boundary mutations;
- 17 post-build capsule tampering cases.

Python and Node must produce identical capsule and manifest digests.

## Deferred work

This profile does not yet provide:

- binary or compressed capsules;
- streaming or random-access archives;
- signed export receipts;
- encrypted recipient envelopes;
- resumable transfer;
- import and merge transactions;
- conflict reconciliation;
- deduplication across capsules;
- large-file chunking;
- multimodal payloads;
- persistent runtime automation.

Those capabilities require separate profiles and tests. None may weaken the append-only source,
ACL, redaction, or authority boundaries defined here.

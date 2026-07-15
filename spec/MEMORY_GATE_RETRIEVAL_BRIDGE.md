# Memory Gate → Retrieval Bridge v0.1

Status: `v0.1-draft`

## Purpose

This bridge connects accepted output from the signed memory gate to the deterministic retrieval projection. It is an operational adapter, not a new source of memory or authority.

The required order is:

```text
signed observation
  -> signed gate decision = accepted
  -> append-only memory event committed
  -> accepted textual view bound by digest
  -> retrieval record
  -> rebuildable retrieval projection
```

No retrieval record may be created before the append-only event exists and all links validate.

## Input bundle

A bridge input contains equal-coverage arrays of:

1. signed sense observations;
2. signed memory-gate decisions;
3. committed append-only memory events;
4. accepted textual views;
5. Ed25519 public verification keys;
6. optional associative graph data and retrieval queries.

Every covered event must have exactly one observation, one accepted gate decision and one accepted textual view.

## Accepted textual view

The bridge does not index arbitrary raw payloads. A host provides a bounded textual view only after the gate has accepted the observation and the memory event has been committed.

The view commits to:

- event ID;
- content digest and content type;
- normalized text;
- generation timestamp;
- generator profile.

Its `view_digest` uses `genesis.hash.fields.v0.1`. The text must be NFC, produce at least one deterministic retrieval token and remain at or below 4096 UTF-8 bytes.

A generator profile identifies the adapter that created the view. It does not grant truth or authority. Model-based generators may be added later, but their output remains derived evidence and must be digest-bound.

## Verification sequence

A conforming bridge fails closed unless it verifies:

- observation digest and Ed25519 signature;
- gate-decision digest and Ed25519 signature;
- the gate decision is exactly `accepted`;
- observation, gate, event and body/instance links agree;
- event type, content digest, media type, timestamp, provenance and privacy agree with the observation;
- the append-only event hash and chain are valid;
- the accepted view matches the committed event;
- the view was generated at or after gate acceptance;
- one-to-one coverage without duplicates;
- the deterministic retrieval projection rebuilds successfully.

## Bridge receipt

The output includes a receipt with a digest that commits to:

- covered sequence boundaries;
- observation digests;
- gate-decision digests;
- memory-event hashes;
- accepted-view digests;
- generated retrieval-record IDs;
- final retrieval-projection digest.

The receipt is evidence that the read model was derived from a specific verified bundle. It is not a signature, permission or authority grant.

## Atomic synchronization

The Node reference tool supports:

```powershell
npm run memory:bridge:build -- input.json output.json
npm run memory:bridge:sync -- input.json runtime/retrieval.json
npm run memory:bridge:query -- input.json "workshop memory" --top-k 5
```

`sync` writes a temporary file and atomically renames it over the previous retrieval snapshot. It never edits the append-only chain.

The host runtime should call `sync` only after the memory event commit has completed. If validation fails, the previous retrieval snapshot remains untouched.

## Failure boundary

The bridge rejects:

- rejected or quarantined gate decisions;
- unknown or invalid signatures;
- altered observation, decision, event or view digests;
- incomplete or duplicate coverage;
- raw payloads, credentials, private keys, embeddings or platform bindings;
- views created before gate acceptance;
- event/view content mismatches;
- broken memory chains;
- empty or noncanonical text.

## Current limitation

This change provides a verified one-shot and atomic-sync bridge. It does not create a permanent background daemon, real sensor integration or an autonomous memory writer. A host process must invoke the bridge after a successful append-only commit. Those platform-specific runtime integrations remain pending.

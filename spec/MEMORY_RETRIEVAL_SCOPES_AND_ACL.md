# Memory Retrieval Scopes and ACL v0.1

Status: `v0.1-draft`

## Purpose

This profile filters retrieval candidates before lexical, semantic, graph or temporal ranking. It controls visibility only. It cannot write memory, change identity, grant authority, activate a body or confirm an inference.

```text
append-only memory
  -> historical cutoff
  -> quarantine rejection
  -> scope filter
  -> privacy and requester ACL
  -> event-type filter
  -> retrieval ranking over allowed event references
```

## Requesters

- `instance`: the continuous instance itself;
- `guardian`: the registered human authority, acting through a declared policy;
- `body`: one registered body;
- `engine`: a replaceable reasoning engine with read-only scope;
- `observer`: a sanitized read-only tool.

A requester type does not imply permission. Every request must match one active policy exactly.

## Purposes

The draft purposes are:

- `recall`: normal contextual retrieval;
- `reasoning_context`: context supplied to a reasoning engine;
- `guardian_review`: explicit guardian inspection;
- `transfer_export`: preparation of an authorized portable subset;
- `observability`: sanitized diagnostics.

Purpose limits are part of the policy and cannot be widened by the query.

## Scopes

A scope is a neutral label attached to event references in a rebuildable access projection. Examples include `core`, `project:aurora`, `mobility`, `recovery` and `senses:vision`.

Scopes do not alter canonical events. One event may belong to multiple scopes. Unknown scopes, duplicate mappings or references to unknown events fail closed.

A request with no requested scopes means all scopes allowed by the matched policy. Otherwise the effective scopes are the intersection of request and policy scopes. An empty intersection returns no events.

## Privacy rules

The existing memory-event privacy field remains authoritative:

- `quarantined`: always denied;
- `export_approved`: visible only when the policy allows it;
- `guardian_shared`: visible only to policies that explicitly allow it;
- `private_local`: visible only when explicitly allowed. For a `body` requester, the event body must equal the requester body.

An observer policy may allow only `export_approved`. An engine policy is read-only and never receives identity, guardian keys, credentials or raw platform handles.

## Historical isolation

`as_of_sequence` is applied before every other filter. Future events are absent, not merely down-ranked. ACL evaluation cannot leak their IDs, scopes or counts into an older replay.

## Policy selection

Exactly one policy must match:

- requester type;
- requester ID;
- optional body ID;
- purpose;
- authority epoch;
- sequence validity window.

No match or multiple matches fail closed. Policy order has no effect.

## Decision output

The decision records:

- request and policy IDs;
- effective scopes;
- historical cutoff;
- allowed event references in canonical sequence order;
- aggregate denial counts by stable reason code;
- a deterministic decision digest.

The output intentionally excludes event content and semantic vectors.

## Stable denial reasons

- `future_event`;
- `quarantined`;
- `scope_not_allowed`;
- `privacy_not_allowed`;
- `body_mismatch`;
- `event_type_filtered`.

## Integration with retrieval

The ACL decision supplies an allow-list of canonical event IDs. Lexical and hybrid retrieval must remove all other frames before scoring. Ranking cannot restore a denied event.

## Failure behavior

Malformed policy, unknown event reference, stale authority epoch, ambiguous policy, invalid purpose, invalid scope or digest mismatch fails closed. The lexical fallback does not bypass ACL.

## Non-goals

This draft does not define network authentication, user accounts, operating-system permissions, cloud IAM or public sharing. It defines a neutral deterministic memory-visibility boundary for Genesis implementations.

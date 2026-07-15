# Neutral Multimodal Extraction Pipeline v0.1

Status: `v0.1-draft`

## Purpose

This profile admits derived evidence from documents, images, and audio without allowing an
extractor, model, parser, or media codec to write Genesis memory directly.

The mandatory order is:

```text
local or user-authorized media source
  -> replaceable modality adapter
  -> bounded extraction with provenance
  -> signed sense observation
  -> signed memory-gate decision
  -> append-only memory event
  -> rebuildable multimodal projection
```

The append-only event remains authoritative. Captions, OCR text, document text, and transcripts
are derived evidence. They may be wrong and do not become true merely because a model produced
them.

## Supported modalities

| Modality | Genesis sense | Initial output |
|---|---|---|
| `document` | `vision` | `document_text` |
| `image` | `vision` | `image_description` |
| `audio` | `hearing` | `audio_transcript` |

The initial media allowlist is deliberately narrow:

- documents: PDF, DOCX, XLSX, and UTF-8 plain text;
- images: PNG, JPEG, and WebP;
- audio: WAV, Ogg, Opus, and MPEG audio.

A future adapter may support another format only through a versioned profile and new conformance
evidence. Filename extensions are never trusted as media type evidence.

## Source boundary

A source record contains only:

- neutral IDs for instance, body, and source;
- modality, sense, and source kind;
- canonical UTC capture time;
- declared media type and bounded byte length;
- privacy classification;
- a digest binding those fields.

Raw media bytes, absolute paths, credentials, accounts, provider names, and platform handles do
not enter the portable projection. The host may maintain a local source handle outside the core.

The v0.1 source limit is 100 MiB. This is a conformance limit, not a claim that every host can
process a source of that size.

## Adapter profile

Every adapter publishes:

- adapter ID and semantic version;
- one modality and one output kind;
- `local` execution mode;
- an optional model digest;
- a deterministic profile digest.

The model digest identifies exact model bytes or a versioned model package. It does not grant the
model authority. Provider-specific accounts or service names are forbidden in the core profile.

The document fixture uses no model. Image and audio fixtures demonstrate model-bound output with
fixed digests, but they do not claim production-quality vision or speech recognition.

## Extraction and segments

An accepted extraction contains one to 256 ordered segments. Each segment carries:

- stable segment ID and zero-based ordinal;
- NFC text no larger than 4096 UTF-8 bytes;
- integer confidence in `0..1000`;
- a modality-specific locator;
- a digest binding text, confidence, order, and locator.

Locators are:

- document page number;
- image rectangle in integer permille coordinates;
- audio time range in integer milliseconds.

The aggregate accepted text is the newline join of ordered segments and is limited to 65536 UTF-8
bytes. Its digest is the payload that may be proposed to the memory gate. Raw binary media is not
inserted into memory by this profile.

## Signed sense and gate boundary

For every accepted extraction there must be exactly one signed sense observation:

```text
observation.payload_digest  = extraction.aggregate_digest
observation.evidence_digest = extraction.extraction_digest
observation.sense           = source.sense
observation.captured_at     = source.captured_at
observation.privacy         = source.privacy
```

The observation payload media type is:

```text
application/vnd.genesis.multimodal-accepted-text+json
```

The memory gate must independently issue a signed `accepted` decision linked to the exact
observation digest and exact memory event ID. A failed, rejected, quarantined, unsigned, or
uncovered extraction produces no accepted projection record.

## Append-only memory binding

The committed event must preserve:

- instance and body;
- mapped sense event type;
- accepted-text digest and media type;
- canonical capture time;
- observation digest as provenance;
- privacy;
- sequence and previous-event hash.

The projection is built only after the complete append-only chain verifies. Ranking, later model
updates, or improved extraction cannot rewrite the original event. A correction is a new event.

## Rebuildable projection

`genesis.multimodal.memory.projection.v0.1` records the accepted source, adapter profile,
extraction, signed observation, gate decision, and canonical memory event. Each record and the
projection have deterministic `mmsha256:` digests.

The projection may be deleted and reconstructed from the verified pipeline bundle. It has no
write permission and contains no active-writer, guardian-key, seed, credential, or account data.

## Failure behavior

The pipeline fails closed for:

- unsupported or mismatched media types;
- oversized, empty, or quarantined sources;
- cloud-only or provider-bound adapter declarations;
- malformed page, region, or audio locators;
- non-NFC, oversized, reordered, or altered segments;
- aggregate and extraction digest mismatch;
- invalid signatures or gate decisions;
- memory chain, content, provenance, or privacy mismatch;
- incomplete one-to-one coverage.

Failure of an extractor never blocks access to existing canonical memory. It only prevents that
new source from becoming an accepted memory event.

## Operational commands

```powershell
npm run validate:multimodal
npm run memory:multimodal:build -- conformance/multimodal_memory_pipeline_vectors.json multimodal.json
npm run memory:multimodal:sync -- conformance/multimodal_memory_pipeline_vectors.json runtime/multimodal.json
npm run memory:multimodal:inspect -- runtime/multimodal.json
```

`sync` replaces only the derived projection through an atomic rename.

## Deferred work

This profile does not provide:

- a production PDF, DOCX, XLSX, OCR, vision, or speech model;
- automatic download of remote media;
- hidden cloud calls;
- raw-media retention policy;
- malware scanning or document sandboxing;
- streaming extraction for large sources;
- encrypted multimodal blobs inside portable capsules;
- automatic correction or deletion of canonical memories;
- a persistent ingestion daemon.

Those require separate host adapters, privacy review, evaluation datasets, resource limits, and
explicit failure behavior.

#!/usr/bin/env python3
"""Temporary deterministic migration for immutable authority snapshots and key fingerprints."""
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replace_anchor_invalid:{label}:{count}")
    return text.replace(old, new, 1)


def sub_once(text: str, pattern: str, replacement: str, label: str, flags: int = 0) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"sub_anchor_invalid:{label}:{count}")
    return updated


def patch_node_authority() -> None:
    path = ROOT / "tools" / "validate_guided_autonomy_authority.mjs"
    text = path.read_text(encoding="utf-8")
    helper_anchor = 'const boolText = (value) => value ? "true" : "false";\n'
    helpers = '''const boolText = (value) => value ? "true" : "false";
function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
    return Object.freeze(value);
  }
  return value;
}
function readOnlyMap(map) {
  const view = {
    get: (key) => map.get(key),
    has: (key) => map.has(key),
    entries: () => map.entries(),
    keys: () => map.keys(),
    values: () => map.values(),
    get size() { return map.size; },
    [Symbol.iterator]: () => map[Symbol.iterator](),
  };
  return Object.freeze(view);
}
function readOnlySet(set) {
  const view = {
    has: (value) => set.has(value),
    entries: () => set.entries(),
    keys: () => set.keys(),
    values: () => set.values(),
    get size() { return set.size; },
    [Symbol.iterator]: () => set[Symbol.iterator](),
  };
  return Object.freeze(view);
}
'''
    text = replace_once(text, helper_anchor, helpers, "node-helpers")
    text = sub_once(
        text,
        r'function resolvePublicKey\(publicKeyResolver, envelope, signerType, signerId\) \{.*?\n\}',
        '''function resolvePublicKey(publicKeyResolver, envelope, signerType, signerId) {
  if (typeof publicKeyResolver !== "function") fail("public_key_resolver_required");
  exact(envelope, SIGNATURE_FIELDS, "public_key_envelope_invalid");
  const key = publicKeyResolver({ signer_type: signerType, signer_id: signerId, key_epoch_id: envelope.key_epoch_id, public_key_ref: envelope.public_key_ref });
  exact(key, PUBLIC_KEY_FIELDS, "public_key_record_invalid");
  if (!/^[0-9a-f]{64}$/.test(key.public_key_hex)) fail("public_key_hex_invalid");
  if (!/^sha256:[0-9a-f]{64}$/.test(key.public_key_fingerprint)) fail("public_key_fingerprint_invalid");
  const expectedFingerprint = `sha256:${crypto.createHash("sha256").update(Buffer.from(key.public_key_hex, "hex")).digest("hex")}`;
  if (key.public_key_fingerprint !== expectedFingerprint) fail("public_key_fingerprint_mismatch");
  if (key.key_epoch_id !== envelope.key_epoch_id || key.public_key_fingerprint !== envelope.public_key_ref) fail("public_key_resolution_mismatch");
  return key;
}''',
        "node-resolve-key",
        re.S,
    )
    text = replace_once(
        text,
        '  const grantMap = new Map(grants.map((grant) => [grant.grant_id, grant]));\n  return Object.freeze({ [MARK]: true, bundle, grants: grantMap, registered: new Set(registered), keyResolver: publicKeyResolver });',
        '  const frozenBundle = deepFreeze(bundle);\n  const grantMap = new Map(grants.map((grant) => [grant.grant_id, grant]));\n  return Object.freeze({ [MARK]: true, bundle: frozenBundle, grants: readOnlyMap(grantMap), registered: readOnlySet(new Set(registered)), keyResolver: publicKeyResolver });',
        "node-readonly-authority",
    )
    text = replace_once(
        text,
        'export function validateAuthorityBundle(bundle, publicKeyResolver) {\n  try { return validateAuthorityBundleInternal(bundle, publicKeyResolver); }',
        'export function validateAuthorityBundle(bundle, publicKeyResolver) {\n  try { return validateAuthorityBundleInternal(structuredClone(bundle), publicKeyResolver); }',
        "node-snapshot-clone",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_python_authority() -> None:
    path = ROOT / "tools" / "validate_guided_autonomy_authority.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(text, "from dataclasses import dataclass\n", "from copy import deepcopy\nfrom dataclasses import dataclass\n", "py-copy-import")
    text = replace_once(text, "from typing import Any\n", "from types import MappingProxyType\nfrom typing import Any\n", "py-proxy-import")
    text = replace_once(
        text,
        "@dataclass(frozen=True)\nclass Authority:\n bundle:dict; grants:dict; registered:frozenset; key_resolver:object",
        '''@dataclass(frozen=True)
class Authority:
 _bundle:dict; _grants:dict; registered:frozenset; key_resolver:object
 @property
 def bundle(self): return deepcopy(self._bundle)
 @property
 def grants(self): return MappingProxyType(deepcopy(self._grants))''',
        "py-authority-class",
    )
    text = sub_once(
        text,
        r'def resolve_public_key\(public_key_resolver,envelope,signer_type,signer_id\):\n.*?\n return key',
        '''def resolve_public_key(public_key_resolver,envelope,signer_type,signer_id):
 if not callable(public_key_resolver): fail('public_key_resolver_required')
 exact(envelope,SIG_FIELDS,'public_key_envelope_invalid')
 key=public_key_resolver({'signer_type':signer_type,'signer_id':signer_id,'key_epoch_id':envelope['key_epoch_id'],'public_key_ref':envelope['public_key_ref']})
 exact(key,PUBLIC_KEY_FIELDS,'public_key_record_invalid')
 if not __import__('re').fullmatch(r'[0-9a-f]{64}',key['public_key_hex']): fail('public_key_hex_invalid')
 if not __import__('re').fullmatch(r'sha256:[0-9a-f]{64}',key['public_key_fingerprint']): fail('public_key_fingerprint_invalid')
 expected_fingerprint='sha256:'+hashlib.sha256(bytes.fromhex(key['public_key_hex'])).hexdigest()
 if key['public_key_fingerprint']!=expected_fingerprint: fail('public_key_fingerprint_mismatch')
 if key['key_epoch_id']!=envelope['key_epoch_id'] or key['public_key_fingerprint']!=envelope['public_key_ref']: fail('public_key_resolution_mismatch')
 return key''',
        "py-resolve-key",
        re.S,
    )
    text = replace_once(
        text,
        " return lambda query: records.get((query['signer_type'],query['signer_id'],query['key_epoch_id'],query['public_key_ref']))",
        " return lambda query: deepcopy(records.get((query['signer_type'],query['signer_id'],query['key_epoch_id'],query['public_key_ref'])))",
        "py-resolver-copy",
    )
    text = replace_once(
        text,
        " return Authority(bundle,{g['grant_id']:g for g in grants},frozenset(registered),public_key_resolver)",
        " return Authority(deepcopy(bundle),{g['grant_id']:deepcopy(g) for g in grants},frozenset(registered),public_key_resolver)",
        "py-authority-snapshot",
    )
    text = replace_once(
        text,
        "def validate_authority_bundle(bundle,public_key_resolver):\n try: return _validate_authority_bundle(bundle,public_key_resolver)",
        "def validate_authority_bundle(bundle,public_key_resolver):\n try: return _validate_authority_bundle(deepcopy(bundle),public_key_resolver)",
        "py-wrapper-clone",
    )
    text = replace_once(text, " grant=authority.grants.get(grant_ref)", " grant=authority._grants.get(grant_ref)", "py-internal-grant")
    text = replace_once(text, " state=state_at(grant,authority.bundle['ledger_events'],at)", " state=state_at(grant,authority._bundle['ledger_events'],at)", "py-internal-ledger")
    text = replace_once(
        text,
        "str(a.bundle['authority_epoch']),a.bundle['ledger_events'][0]['ledger_id']",
        "str(a._bundle['authority_epoch']),a._bundle['ledger_events'][0]['ledger_id']",
        "py-internal-campaign-bundle",
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_node_lab() -> None:
    path = ROOT / "tools" / "validate_recursive_improvement_lab.mjs"
    text = path.read_text(encoding="utf-8")
    old = 'const broken=structuredClone(authority.bundle);broken.ledger_events[1].previous_event_hash="sha256:"+"0".repeat(64);expectFailure("neutral_bundle_ledger",()=>validateAuthorityBundle(broken,authority.keyResolver));negatives++;const wrongEvent=structuredClone(execution.bundle);'
    new = '''const broken=structuredClone(authority.bundle);broken.ledger_events[1].previous_event_hash="sha256:"+"0".repeat(64);expectFailure("neutral_bundle_ledger",()=>validateAuthorityBundle(broken,authority.keyResolver));negatives++;
 const badFingerprintResolver=(query)=>{const key=authority.keyResolver(query);return key===null?null:{...key,public_key_hex:"00".repeat(32)}};expectFailure("public_key_fingerprint",()=>validateAuthorityBundle(structuredClone(authority.bundle),badFingerprintResolver));negatives++;
 const sourceBundle=structuredClone(authority.bundle),isolatedAuthority=validateAuthorityBundle(sourceBundle,authority.keyResolver);sourceBundle.ledger_events[0].event_hash="sha256:"+"0".repeat(64);if(resolveExactGrant(grant.grant_id,grant.capability,grant.instance_id,opened,isolatedAuthority).reason!=="allowed")throw Error("authority_source_mutation_leaked");negatives++;
 let frozen=false;try{isolatedAuthority.bundle.authority_epoch+=1}catch{frozen=true}if(!frozen||isolatedAuthority.bundle.authority_epoch!==guided.authority_epoch)throw Error("authority_snapshot_mutable");negatives++;
 const wrongEvent=structuredClone(execution.bundle);'''
    text = replace_once(text, old, new, "node-lab-regressions")
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_python_lab() -> None:
    path = ROOT / "tools" / "validate_recursive_improvement_lab.py"
    text = path.read_text(encoding="utf-8")
    old = "broken=deepcopy(authority.bundle);broken['ledger_events'][1]['previous_event_hash']='sha256:'+'0'*64;expect_failure('neutral_bundle_ledger',lambda:validate_authority_bundle(broken,authority.key_resolver));negatives+=1;wrong=deepcopy(execution['bundle']);"
    new = """broken=deepcopy(authority.bundle);broken['ledger_events'][1]['previous_event_hash']='sha256:'+'0'*64;expect_failure('neutral_bundle_ledger',lambda:validate_authority_bundle(broken,authority.key_resolver));negatives+=1
 def bad_fingerprint_resolver(query):
  key=authority.key_resolver(query)
  return None if key is None else {**key,'public_key_hex':'00'*32}
 expect_failure('public_key_fingerprint',lambda:validate_authority_bundle(deepcopy(authority.bundle),bad_fingerprint_resolver));negatives+=1
 source_bundle=deepcopy(authority.bundle);isolated_authority=validate_authority_bundle(source_bundle,authority.key_resolver);source_bundle['ledger_events'][0]['event_hash']='sha256:'+'0'*64
 if resolve_exact_grant(grant['grant_id'],grant['capability'],grant['instance_id'],opened,isolated_authority)['reason']!='allowed': raise ValueError('authority_source_mutation_leaked')
 negatives+=1;exposed=isolated_authority.bundle;exposed['authority_epoch']+=1
 if isolated_authority.bundle['authority_epoch']!=guided['authority_epoch']: raise ValueError('authority_snapshot_mutable')
 negatives+=1;wrong=deepcopy(execution['bundle']);"""
    text = replace_once(text, old, new, "py-lab-regressions")
    path.write_text(text, encoding="utf-8", newline="\n")


def update_docs() -> None:
    checklist_path = ROOT / "docs" / "V0_1_COMPLETION_CHECKLIST.md"
    checklist = checklist_path.read_text(encoding="utf-8")
    checklist = replace_once(checklist, "y catorce rechazos adicionales", "y diecisiete rechazos adicionales", "checklist-count")
    checklist_path.write_text(checklist, encoding="utf-8", newline="\n")

    report_path = ROOT / "docs" / "PR27_SELECTIVE_EXTRACTION_REPORT.md"
    report = report_path.read_text(encoding="utf-8")
    marker = "El bundle neutral contiene solo datos públicos y no acepta semillas privadas, `expected` ni `must_reject`. Las claves se resuelven por tipo de firmante, ID, época y fingerprint."
    replacement = marker + " El fingerprint se recalcula desde `public_key_hex`, y el resultado validado conserva una copia aislada con bundle congelado o expuesto únicamente por copia, evitando mutaciones posteriores a la validación."
    report = replace_once(report, marker, replacement, "report-snapshot")
    report_path.write_text(report, encoding="utf-8", newline="\n")


def main() -> None:
    patch_node_authority()
    patch_python_authority()
    patch_node_lab()
    patch_python_lab()
    update_docs()
    print("OK hardened authority key fingerprints and immutable snapshots")


if __name__ == "__main__":
    main()

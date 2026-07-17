#!/usr/bin/env python3
"""Reference validator for Genesis Ultra cryptographic vectors.

Validates deterministic digests, signature envelopes, backup encryption and KDF vectors.
It does not provide production key storage or a production security review.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]


def encode_field(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("field_must_be_string")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("text_not_nfc")
    raw = value.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def digest(domain: str, fields: list[str]) -> str:
    preimage = encode_field(domain) + b"".join(encode_field(field) for field in fields)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def signature_envelope_bytes(envelope: dict) -> bytes:
    fields = [
        envelope["schema_version"], envelope["signature_profile"],
        envelope["signer_type"], envelope["signer_id"], envelope["key_epoch_id"],
        envelope["signed_domain"], envelope["signed_digest"], envelope["created_at"],
        envelope["public_key_ref"],
    ]
    return encode_field("genesis.signature.envelope.bytes.v0.1") + b"".join(
        encode_field(field) for field in fields
    )


def main() -> int:
    path = ROOT / "conformance" / "crypto_vectors.json"
    with path.open("r", encoding="utf-8") as handle:
        vectors = json.load(handle)

    failures: list[str] = []
    for vector in vectors["vectors"]:
        actual = digest(vector["domain"], vector["fields"])
        if actual != vector["expected_digest"]:
            failures.append(
                f"{vector['case_id']}:expected={vector['expected_digest']}:actual={actual}"
            )

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1

    print("OK protocol digest vectors")
    print("OK body possession digest")
    print("OK key epoch digest")
    algo_rc = verify_algorithm_vectors(vectors)
    if algo_rc != 0:
        return algo_rc
    print("NOTE Digest + firma + cifrado + KDF verificados con casos de corrupcion; algoritmos siguen en borrador.")
    return 0


def verify_algorithm_vectors(vectors: dict) -> int:
    """Verifica vectores criptograficos REALES: firma, cifrado, KDF y corrupcion."""
    algos = vectors.get("algorithms")
    if not algos:
        print("FAIL: faltan vectores de algoritmos (algorithms) en crypto_vectors.json")
        return 1
    try:
        from nacl.signing import VerifyKey, SigningKey
        from nacl.exceptions import BadSignatureError, CryptoError
        from nacl.bindings import (
            crypto_aead_xchacha20poly1305_ietf_encrypt,
            crypto_aead_xchacha20poly1305_ietf_decrypt,
        )
        from nacl import pwhash
    except ImportError:
        print("FAIL: PyNaCl requerido para verificar vectores de algoritmos (pip install pynacl)")
        return 1

    failed = 0
    ed = algos["ed25519"]
    envelope = ed["envelope"]
    domain_msg = signature_envelope_bytes(envelope)
    sk = SigningKey(bytes.fromhex(ed["seed_hex"]))
    if sk.verify_key.encode().hex() != ed["public_key_hex"]:
        print("FAIL ed25519: clave publica no coincide"); failed += 1
    expected_key_ref = "sha256:" + hashlib.sha256(sk.verify_key.encode()).hexdigest()
    if envelope["public_key_ref"] != expected_key_ref:
        print("FAIL ed25519: referencia de clave no coincide"); failed += 1
    signature = bytes.fromhex(envelope["signature_value"])
    if sk.sign(domain_msg).signature != signature:
        print("FAIL ed25519: firma determinista no coincide"); failed += 1
    try:
        VerifyKey(bytes.fromhex(ed["public_key_hex"])).verify(domain_msg, signature)
        print("OK ed25519 firma verifica")
    except BadSignatureError:
        print("FAIL ed25519: firma no verifica"); failed += 1
    tampered = bytearray(signature); tampered[0] ^= 1
    if ed["corruption"].get("flip_first_signature_byte_must_fail") is not True:
        print("FAIL ed25519: falta requisito de firma alterada"); failed += 1
    try:
        VerifyKey(bytes.fromhex(ed["public_key_hex"])).verify(domain_msg, bytes(tampered))
        print("FAIL ed25519: firma alterada ACEPTADA"); failed += 1
    except BadSignatureError:
        print("OK ed25519 corrupcion rechazada")
    changed_envelope = dict(envelope)
    changed_envelope["created_at"] = "2026-07-15T02:30:01Z"
    if ed["corruption"].get("mutate_created_at_must_fail") is not True:
        print("FAIL ed25519: falta requisito de metadato alterado"); failed += 1
    try:
        VerifyKey(bytes.fromhex(ed["public_key_hex"])).verify(
            signature_envelope_bytes(changed_envelope), signature
        )
        print("FAIL ed25519: metadato alterado ACEPTADO"); failed += 1
    except BadSignatureError:
        print("OK ed25519 metadato de sobre protegido")

    xc = algos["xchacha20poly1305_ietf"]
    key = bytes.fromhex(xc["key_hex"]); nonce = bytes.fromhex(xc["nonce_hex"])
    aad = xc["aad_utf8"].encode(); ct = bytes.fromhex(xc["ciphertext_with_tag_hex"])
    recomputed = crypto_aead_xchacha20poly1305_ietf_encrypt(xc["plaintext_utf8"].encode(), aad, nonce, key)
    if recomputed.hex() != xc["ciphertext_with_tag_hex"]:
        print("FAIL xchacha20: ciphertext no coincide"); failed += 1
    else:
        print("OK xchacha20 cifrado coincide")
    try:
        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)
        if pt.decode() == xc["plaintext_utf8"]:
            print("OK xchacha20 descifrado y tag verifican")
        else:
            print("FAIL xchacha20: plaintext distinto"); failed += 1
    except CryptoError:
        print("FAIL xchacha20: no descifra"); failed += 1
    bad = bytearray(ct); bad[0] ^= 1
    try:
        crypto_aead_xchacha20poly1305_ietf_decrypt(bytes(bad), aad, nonce, key)
        print("FAIL xchacha20: ciphertext alterado ACEPTADO"); failed += 1
    except CryptoError:
        print("OK xchacha20 corrupcion rechazada")

    kd = algos["argon2id"]
    dk = pwhash.argon2id.kdf(kd["derived_key_len"], kd["password_utf8"].encode(),
                             bytes.fromhex(kd["salt_hex"]),
                             opslimit=kd["opslimit"], memlimit=kd["memlimit"])
    if dk.hex() == kd["derived_key_hex"]:
        print("OK argon2id derivacion coincide")
    else:
        print("FAIL argon2id: clave derivada distinta"); failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

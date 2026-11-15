"""Pure crypto primitives (AES-256-GCM).

The archive side generates a fresh 256-bit data key per object, encrypts the
UTF-8 text with it, and sends the data key to the keystore to be wrapped under
the generation master key (``wrap``/``unwrap``).  A wrapped data key is the
object's "envelope"; it is the only place the data key ever exists outside of
memory, and it is useless without the keystore.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REMOTE_NONCE = 12
TAG = 16


def new_data_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(REMOTE_NONCE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encode_wrap(gen: int, kid: str, nonce: bytes, ct: bytes) -> bytes:
    """Self-describing wrapped-key blob as returned by the keystore."""
    kid_b = kid.encode("ascii")
    return (gen.to_bytes(8, "big") + bytes([len(kid_b)]) + kid_b
            + bytes([len(nonce)]) + nonce + ct)


def decode_wrap(blob: bytes) -> tuple[int, str, bytes, bytes]:
    off = 0
    if len(blob) < 10:
        raise ValueError("short wrap")
    gen = int.from_bytes(blob[off:off + 8], "big")
    off += 8
    klen = blob[off]
    off += 1
    kid_b = blob[off:off + klen]
    off += klen
    if len(kid_b) != klen:
        raise ValueError("bad wrap")
    nlen = blob[off]
    off += 1
    nonce = blob[off:off + nlen]
    off += nlen
    ct = blob[off:]
    if len(nonce) != nlen or len(nonce) != REMOTE_NONCE or len(ct) < TAG:
        raise ValueError("bad wrap")
    return gen, kid_b.decode("ascii"), nonce, ct


__all__ = [
    "InvalidTag",
    "new_data_key",
    "aead_encrypt",
    "aead_decrypt",
    "encode_wrap",
    "decode_wrap",
]

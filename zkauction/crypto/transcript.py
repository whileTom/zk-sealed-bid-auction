"""Fiat-Shamir transcript hashing.

[CRYPTO] Interactive Sigma protocols are made non-interactive by deriving the verifier's
challenge from a hash of everything the prover has committed to (Fiat-Shamir).

Encoding (frontend/zkp.js implements the identical bytes):
    enc(part) = uint32_be(len(body)) || body
    int  -> body = b"I" || 256-byte big-endian      (ints must be 0 <= x < 2^2048)
    str  -> body = b"S" || UTF-8 bytes
    hash_int(parts...) = int(SHA-256(enc(p1) || enc(p2) || ...))   (a 256-bit integer)

The type tag and length prefix make the encoding unambiguous (an int can never collide
with a string, and concatenations cannot be re-split differently).
"""
import hashlib


def _enc(part) -> bytes:
    if isinstance(part, bool):
        raise TypeError("bool is not a valid transcript part")
    if isinstance(part, int):
        if part < 0 or part >= 1 << 2048:
            raise ValueError("transcript int out of range")
        body = b"I" + part.to_bytes(256, "big")
    elif isinstance(part, str):
        body = b"S" + part.encode("utf-8")
    else:
        raise TypeError("unsupported transcript part: %r" % type(part))
    return len(body).to_bytes(4, "big") + body


def hash_int(*parts) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(_enc(part))
    return int.from_bytes(h.digest(), "big")

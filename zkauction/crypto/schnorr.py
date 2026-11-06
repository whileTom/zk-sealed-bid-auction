"""Schnorr signatures = non-interactive proof of knowledge of the secret key behind an address.

[CRYPTO] A bidder's identity is a key pair (sk, pk = G^sk). The address is the first 20
bytes of SHA-256(pk), Ethereum style. Signing the bid statement proves, in zero knowledge,
that the bidder controls the address (sk is never revealed) and binds the bid to it.
"""
import hashlib
import secrets

from .params import P, Q, gexp, is_element, is_scalar
from .transcript import hash_int

SIG_DOMAIN = "zk-auction/v1/sig"


def keygen():
    sk = 1 + secrets.randbelow(Q - 1)
    return sk, gexp(sk)


def address_of(pk: int) -> str:
    return "0x" + hashlib.sha256(pk.to_bytes(256, "big")).hexdigest()[:40]


def sign(sk: int, pk: int, *msg):
    k = secrets.randbelow(Q)  # fresh uniform nonce; never derived from a hash
    R = gexp(k)
    e = hash_int(SIG_DOMAIN, pk, R, *msg) % Q
    return R, (k + e * sk) % Q


def verify(pk: int, R: int, s: int, *msg) -> bool:
    """[ZKP-VERIFY] Check G^s == R * pk^e with e = H(domain, pk, R, msg)."""
    if not (is_element(pk) and is_element(R) and is_scalar(s)):
        return False
    e = hash_int(SIG_DOMAIN, pk, R, *msg) % Q
    return gexp(s) == R * pow(pk, e, P) % P

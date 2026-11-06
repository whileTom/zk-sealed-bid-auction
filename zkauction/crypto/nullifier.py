"""Auction-scoped nullifier: puts "at most one bid per key per auction" INSIDE the proof.

[CRYPTO] For each auction we derive a public generator H_a = hash_to_group("...nullifier/" + id).
A bidder with key pair (sk, pk = G^sk) publishes the nullifier N = H_a^sk together with a
Chaum-Pedersen proof of discrete-log equality:  log_G(pk) == log_{H_a}(N).

- N is a deterministic function of (key, auction): a key can produce exactly one valid N per
  auction, so the verifier rejects a second bid carrying the same N (DUPLICATE_BID).
- The proof is zero knowledge (sk is never revealed) and Fiat-Shamir-bound to the auction,
  bidder address and commitment, so it cannot be copied onto another bid.
- N for auction A says nothing usable about auction B (different H_a).

This is the hook a fully anonymous design would build on (Semaphore-style): replace the public
address with a ZK set-membership proof and keep the nullifier as the double-bid guard.
"""
import secrets

from .params import P, Q, gexp, hash_to_group, is_element, is_scalar
from .transcript import hash_int

DLEQ_DOMAIN = "zk-auction/v1/nullifier-dleq"


def auction_generator(auction_id: str) -> int:
    return hash_to_group(b"zk-auction/v1/nullifier/" + auction_id.encode("utf-8"))


def prove(sk: int, pk: int, auction_id: str, bidder: str, C: int) -> dict:
    Ha = auction_generator(auction_id)
    N = pow(Ha, sk, P)
    k = secrets.randbelow(Q)
    R1, R2 = gexp(k), pow(Ha, k, P)
    e = hash_int(DLEQ_DOMAIN, auction_id, bidder, C, pk, N, R1, R2) % Q
    return {"N": N, "R1": R1, "R2": R2, "s": (k + e * sk) % Q}


def verify(nf: dict, pk: int, auction_id: str, bidder: str, C: int) -> bool:
    """[ZKP-VERIFY] Check G^s == R1 * pk^e and H_a^s == R2 * N^e (same s, same e)."""
    N, R1, R2, s = nf["N"], nf["R1"], nf["R2"], nf["s"]
    if not (is_element(N) and is_element(R1) and is_element(R2) and is_scalar(s)):
        return False
    Ha = auction_generator(auction_id)
    e = hash_int(DLEQ_DOMAIN, auction_id, bidder, C, pk, N, R1, R2) % Q
    return gexp(s) == R1 * pow(pk, e, P) % P and pow(Ha, s, P) == R2 * pow(N, e, P) % P

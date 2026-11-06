"""Bid-phase proof checking: the single entry point the bidding service calls.

A sealed bid is (bidder address, commitment C, proof) where proof =
    {"range": {"bits": [k bit proofs]},
     "auth": {"pubkey", "R", "s"},
     "nullifier": {"N", "R1", "R2", "s"}}
All numbers on the wire are 512-char lowercase hex strings.

The bid proof establishes, without revealing the amount or the secret key:
  1. Validity: C commits to a value in [BID_MIN, BID_MAX] (range_proof).
  2. Authorization: the bidder knows sk for `bidder` (address == SHA-256(pk)[:20]) and signed
     the statement ("bid", auction_id, bidder, C) (schnorr).
  3. One bid per address per auction: N = H_auction^sk is the unique nullifier of this key in
     this auction, proven consistent with pk (nullifier). The verifier rejects a reused N.
All three proofs are bound to auction_id, bidder and C, so a proof cannot be replayed in
another auction, under another address, or for a modified commitment.
"""
from .errors import InvalidProof
from .params import BID_MAX, BID_MIN, from_hex, is_element
from .range_proof import verify_range
from . import nullifier, schnorr

BIT_FIELDS = ("C", "A0", "A1", "e0", "e1", "z0", "z1")


def parse_range_bits(bits_json) -> list:
    return [{f: from_hex(bp[f]) for f in BIT_FIELDS} for bp in bits_json]


def verify_bid(auction_id: str, bidder: str, commitment_hex: str, proof_json: dict) -> tuple:
    """[ZKP-VERIFY] Validate a sealed bid. Returns (C, pk, N) as ints or raises InvalidProof."""
    try:
        C = from_hex(commitment_hex)
        auth = proof_json["auth"]
        pk, R, s = from_hex(auth["pubkey"]), from_hex(auth["R"]), from_hex(auth["s"])
        nf = {f: from_hex(proof_json["nullifier"][f]) for f in ("N", "R1", "R2", "s")}
        bits = parse_range_bits(proof_json["range"]["bits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidProof("malformed proof: %s" % exc) from None

    if not is_element(C):
        raise InvalidProof("commitment is not a group element")
    if schnorr.address_of(pk) != bidder:
        raise InvalidProof("bidder address does not match the proof's public key")
    if not schnorr.verify(pk, R, s, "bid", auction_id, bidder, C):
        raise InvalidProof("authorization signature is invalid")
    if not nullifier.verify(nf, pk, auction_id, bidder, C):
        raise InvalidProof("nullifier proof is invalid")
    verify_range(bits, auction_id, bidder, C, BID_MIN, BID_MAX)
    return C, pk, nf["N"]

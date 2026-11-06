"""Reveal-phase proof checking: the single entry point the reveal service calls.

A reveal is (bidder, value, randomness, proof) where proof =
    {"commitment": hex, "auth": {"R", "s"}}

Consistency with the original commitment:
  - The opening (value, randomness) IS the consistency proof: Pedersen commitments are
    binding, so no other (value', randomness') opens the stored C (under the discrete-log
    assumption). We always check against the commitment STORED at bid time, never a
    client-supplied one; proof.commitment must simply match it.
  - value must be an integer in [BID_MIN, BID_MAX] and randomness a canonical scalar,
    otherwise value + Q would open the same commitment.
  - A Schnorr signature over ("reveal", auction_id, bidder, C, value, randomness) with the
    key registered at bid time binds the reveal to the bidder.
"""
from .errors import CommitmentMismatch, InvalidOpening, InvalidProof
from .params import from_hex
from .pedersen import verify_opening
from . import schnorr


def verify_reveal(auction_id: str, bidder: str, stored_C: int, pk: int,
                  value, randomness_hex: str, proof_json: dict) -> int:
    """[ZKP-VERIFY] Validate a reveal. Returns randomness as int or raises InvalidProof."""
    try:
        claimed_C = from_hex(proof_json["commitment"])
        R, s = from_hex(proof_json["auth"]["R"]), from_hex(proof_json["auth"]["s"])
        r = from_hex(randomness_hex)
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidProof("malformed reveal: %s" % exc) from None

    if claimed_C != stored_C:
        raise CommitmentMismatch("reveal refers to a different commitment than the sealed bid")
    if not verify_opening(stored_C, value, r):
        raise InvalidOpening("value/randomness do not open the sealed commitment")
    if not schnorr.verify(pk, R, s, "reveal", auction_id, bidder, stored_C, value, r):
        raise InvalidProof("reveal signature is invalid")
    return r

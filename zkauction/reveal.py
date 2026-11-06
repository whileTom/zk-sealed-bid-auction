"""Reveal phase: opening commitments and computing the leader / winner.

Proof checking is delegated to zkauction.crypto.reveal_proof.verify_reveal; this module owns
the phase gates and state transitions. A failed reveal never changes state.
"""
from datetime import datetime

from .crypto.reveal_proof import verify_reveal
from .errors import Conflict, NotFound, PhaseError
from .store import Auction, Reveal, Store


def submit_reveal(store: Store, now: datetime, auction_id: str, bidder: str, value,
                  randomness_hex: str, proof: dict) -> Reveal:
    auction = store.require(auction_id)
    phase = auction.phase(now)
    if phase == "bidding":
        raise PhaseError("reveals open at the bid deadline", "REVEAL_NOT_OPEN")
    if phase == "closed":
        raise PhaseError("the reveal window has closed", "REVEAL_CLOSED")
    bid = auction.bids.get(bidder)
    if bid is None:
        raise NotFound("no sealed bid from this address", "BID_NOT_FOUND")
    if bidder in auction.reveals:
        raise Conflict("bid already revealed", "ALREADY_REVEALED")

    # [ZKP-VERIFY] opening + range + signature against the STORED commitment.
    r = verify_reveal(auction_id, bidder, bid.commitment, bid.pubkey, value, randomness_hex, proof)

    with store.lock:
        if bidder in auction.reveals:
            raise Conflict("bid already revealed", "ALREADY_REVEALED")
        rev = Reveal(bidder, value, r, now)
        auction.reveals[bidder] = rev
    return rev


def leader(auction: Auction):
    """Highest revealed value; ties go to the earliest sealed bid (lowest seq)."""
    if not auction.reveals:
        return None
    best = min(auction.reveals.values(), key=lambda rv: (-rv.value, auction.bids[rv.bidder].seq))
    return {"bidder": best.bidder, "value": best.value}


def results(store: Store, now: datetime, auction_id: str) -> dict:
    auction = store.require(auction_id)
    phase = auction.phase(now)
    if phase == "bidding":
        raise PhaseError("bids are sealed until %s" % auction.bid_deadline.isoformat(), "BIDS_SEALED")
    revealed = sorted(auction.reveals.values(), key=lambda rv: auction.bids[rv.bidder].seq)
    unrevealed = [b.bidder for b in sorted(auction.bids.values(), key=lambda b: b.seq)
                  if b.bidder not in auction.reveals]
    current = leader(auction)
    # final: the leader can no longer change (window closed, or every sealed bid revealed).
    final = phase == "closed" or not unrevealed
    return {
        "auction_id": auction_id,
        "phase": phase,
        "final": final,
        "sealed_count": len(auction.bids),
        "revealed": [
            {
                "bidder": rv.bidder,
                "value": rv.value,
                "randomness": format(rv.randomness, "0512x"),
                "commitment": format(auction.bids[rv.bidder].commitment, "0512x"),
                "committed_at": auction.bids[rv.bidder].committed_at,
                "revealed_at": rv.revealed_at,
            }
            for rv in revealed
        ],
        "unrevealed": unrevealed,
        "current_leader": current,
        "winner": current if final else None,
    }

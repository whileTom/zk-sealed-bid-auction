"""Reveal phase: opening commitments and computing the leader / winner.

Proof checking is delegated to zkauction.crypto.reveal_proof.verify_reveal; this module owns
the phase gates and state transitions. A failed reveal never changes state.
"""
from datetime import datetime

from .crypto.reveal_proof import verify_reveal
from .errors import Conflict, NotFound, PhaseError
from .store import Auction, Reveal, Store
from .timing import SETTLE_GRACE, VERIFY_SLOTS


def _order(auction: Auction, bidder: str):
    """Sealing order: arrival time of the complete bid, then insertion sequence."""
    b = auction.bids[bidder]
    return (b.committed_at, b.seq)


def submit_reveal(store: Store, received_at: datetime, auction_id: str, bidder: str, value,
                  randomness_hex: str, proof: dict, now_fn=None) -> Reveal:
    """The reveal window is judged by `received_at` (when the complete request arrived)."""
    auction = store.require(auction_id)
    phase = auction.phase(received_at)
    if phase == "bidding":
        raise PhaseError("reveals open at the bid deadline", "REVEAL_NOT_OPEN")
    if phase == "closed":
        raise PhaseError("the reveal window has closed", "REVEAL_CLOSED")
    with store.lock:
        bid = auction.bids.get(bidder)
        if bid is None:
            raise NotFound("no sealed bid from this address", "BID_NOT_FOUND")
        if bidder in auction.reveals:
            raise Conflict("bid already revealed", "ALREADY_REVEALED")

    # [ZKP-VERIFY] opening + range + signature against the STORED commitment.
    with VERIFY_SLOTS:
        r = verify_reveal(auction_id, bidder, bid.commitment, bid.pubkey, value, randomness_hex, proof)

    with store.lock:
        if now_fn is not None and now_fn() >= auction.reveal_deadline + SETTLE_GRACE:
            raise PhaseError("the reveal window has closed", "REVEAL_CLOSED")
        if bidder in auction.reveals:
            raise Conflict("bid already revealed", "ALREADY_REVEALED")
        rev = Reveal(bidder, value, r, received_at)
        auction.reveals[bidder] = rev
    return rev


def leader(auction: Auction):
    """Highest revealed value; ties go to the bid that was sealed first."""
    if not auction.reveals:
        return None
    best = min(auction.reveals.values(), key=lambda rv: (-rv.value, _order(auction, rv.bidder)))
    return {"bidder": best.bidder, "value": best.value}


def results(store: Store, now: datetime, auction_id: str) -> dict:
    auction = store.require(auction_id)
    phase = auction.phase(now)
    if phase == "bidding":
        raise PhaseError("bids are sealed until %s" % auction.bid_deadline.isoformat(), "BIDS_SEALED")
    revealed = sorted(auction.reveals.values(), key=lambda rv: _order(auction, rv.bidder))
    unrevealed = [b.bidder for b in sorted(auction.bids.values(), key=lambda b: (b.committed_at, b.seq))
                  if b.bidder not in auction.reveals]
    current = leader(auction)
    # final: the leader can no longer change. Either the reveal window closed, or every sealed bid
    # is revealed and no late-verifying bid can still be added. Both wait out SETTLE_GRACE so that
    # requests which arrived just before a deadline finish verifying first.
    bids_settled = now >= auction.bid_deadline + SETTLE_GRACE
    reveals_settled = now >= auction.reveal_deadline + SETTLE_GRACE
    final = reveals_settled or (bids_settled and not unrevealed)
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

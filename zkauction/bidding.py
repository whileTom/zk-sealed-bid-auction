"""Bidding phase: auction creation and sealed-bid submission.

This module owns the phase gate and the uniqueness rules; all proof checking is delegated
to zkauction.crypto.bid_proof.verify_bid.
"""
import uuid
from datetime import datetime, timedelta

from .crypto.bid_proof import verify_bid
from .errors import Conflict, InvalidInput, PhaseError
from .store import Auction, SealedBid, Store
from .timing import SETTLE_GRACE, VERIFY_SLOTS

DEFAULT_REVEAL_WINDOW = timedelta(minutes=10)
MAX_HORIZON = timedelta(days=365)  # deadlines further out are rejected (also avoids date overflow)


def create_auction(store: Store, now: datetime, item_name: str, description: str,
                   bid_deadline: datetime, reveal_deadline: datetime = None) -> Auction:
    if bid_deadline <= now:
        raise InvalidInput("bid_deadline must be in the future", "DEADLINE_IN_PAST")
    if bid_deadline - now > MAX_HORIZON or (reveal_deadline and reveal_deadline - now > MAX_HORIZON * 2):
        raise InvalidInput("deadlines must be within one year", "DEADLINE_TOO_FAR")
    reveal_deadline = reveal_deadline or bid_deadline + DEFAULT_REVEAL_WINDOW
    if reveal_deadline <= bid_deadline:
        raise InvalidInput("reveal_deadline must be after bid_deadline", "BAD_REVEAL_DEADLINE")
    auction = Auction(uuid.uuid4().hex, item_name, description, bid_deadline, reveal_deadline, now)
    with store.lock:
        store.auctions[auction.auction_id] = auction
    return auction


def _check_open_and_unique(auction: Auction, received_at: datetime, bidder: str, C: int, N: int = None):
    if received_at >= auction.bid_deadline:
        raise PhaseError("bidding closed at %s" % auction.bid_deadline.isoformat(), "BIDDING_CLOSED")
    if bidder in auction.bids or (N is not None and any(b.nullifier == N for b in auction.bids.values())):
        raise Conflict("this address already placed a bid in this auction", "DUPLICATE_BID")
    if any(b.commitment == C for b in auction.bids.values()):
        raise Conflict("this commitment was already submitted", "DUPLICATE_COMMITMENT")


def submit_bid(store: Store, received_at: datetime, auction_id: str, bidder: str,
               commitment_hex: str, proof: dict, now_fn=None) -> SealedBid:
    """Order: 404 -> phase -> duplicates (cheap) -> proof (expensive, outside the lock)
    -> re-check duplicates (now including the proven nullifier) and insert under the lock.

    `received_at` is stamped by middleware when the request reaches the server, before it
    waits for a worker thread, so slow proof verification under load cannot push an honest
    bid past the deadline.
    """
    auction = store.require(auction_id)
    with store.lock:  # cheap pre-check; iterating bids must not race with inserts
        _check_open_and_unique(auction, received_at, bidder, int(commitment_hex, 16))

    # [ZKP-VERIFY] range proof + authorization + nullifier; raises InvalidProof (HTTP 400).
    with VERIFY_SLOTS:
        C, pk, N = verify_bid(auction_id, bidder, commitment_hex, proof)

    with store.lock:
        # A bid that arrived in time but is still verifying after the settle grace is refused, so
        # results published as final (which wait for the same grace) can never change.
        if now_fn is not None and now_fn() >= auction.bid_deadline + SETTLE_GRACE:
            raise PhaseError("bidding closed; verification finished too late", "BIDDING_CLOSED")
        _check_open_and_unique(auction, received_at, bidder, C, N)
        bid = SealedBid(bidder, C, pk, proof, received_at, store.next_seq(), N)
        auction.bids[bidder] = bid
    return bid

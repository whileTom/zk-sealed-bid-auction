"""Bidding phase: auction creation and sealed-bid submission.

This module owns the phase gate and the uniqueness rules; all proof checking is delegated
to zkauction.crypto.bid_proof.verify_bid.
"""
import uuid
from datetime import datetime, timedelta

from .crypto.bid_proof import verify_bid
from .errors import Conflict, InvalidInput, NotFound, PhaseError
from .store import Auction, SealedBid, Store

DEFAULT_REVEAL_WINDOW = timedelta(minutes=10)


def create_auction(store: Store, now: datetime, item_name: str, description: str,
                   bid_deadline: datetime, reveal_deadline: datetime = None) -> Auction:
    if bid_deadline <= now:
        raise InvalidInput("bid_deadline must be in the future", "DEADLINE_IN_PAST")
    reveal_deadline = reveal_deadline or bid_deadline + DEFAULT_REVEAL_WINDOW
    if reveal_deadline <= bid_deadline:
        raise InvalidInput("reveal_deadline must be after bid_deadline", "BAD_REVEAL_DEADLINE")
    auction = Auction(uuid.uuid4().hex, item_name, description, bid_deadline, reveal_deadline, now)
    with store.lock:
        store.auctions[auction.auction_id] = auction
    return auction


def _check_open_and_unique(auction: Auction, received_at: datetime, bidder: str, commitment_hex: str):
    if received_at >= auction.bid_deadline:
        raise PhaseError("bidding closed at %s" % auction.bid_deadline.isoformat(), "BIDDING_CLOSED")
    if bidder in auction.bids:
        raise Conflict("this address already placed a bid in this auction", "DUPLICATE_BID")
    c = int(commitment_hex, 16)
    if any(b.commitment == c for b in auction.bids.values()):
        raise Conflict("this commitment was already submitted", "DUPLICATE_COMMITMENT")


def submit_bid(store: Store, received_at: datetime, auction_id: str, bidder: str,
               commitment_hex: str, proof: dict) -> SealedBid:
    """Order: 404 -> phase -> duplicates (cheap) -> proof (expensive, outside the lock)
    -> re-check duplicates and insert atomically under the lock.

    The deadline is judged by `received_at` (captured when the request arrived), so a bid
    sent before the deadline is not rejected because its proof took time to verify.
    """
    auction = store.get(auction_id)
    if auction is None:
        raise NotFound("auction not found", "AUCTION_NOT_FOUND")
    _check_open_and_unique(auction, received_at, bidder, commitment_hex)

    # [ZKP-VERIFY] range proof + authorization; raises InvalidProof (HTTP 400).
    C, pk = verify_bid(auction_id, bidder, commitment_hex, proof)

    with store.lock:
        _check_open_and_unique(auction, received_at, bidder, commitment_hex)
        bid = SealedBid(bidder, C, pk, proof, received_at, store.next_seq())
        auction.bids[bidder] = bid
    return bid

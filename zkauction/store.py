"""In-memory state.

[SIMULATED] This store stands in for a public blockchain / bulletin board: it records
auctions, sealed commitments (with their proofs) and reveals. Production would post these to
a chain (or sign receipts) so the operator could not censor or reorder bids. Nothing secret
is ever stored here before the reveal phase: only commitments and zero-knowledge proofs.
"""
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional


@dataclass
class SealedBid:
    bidder: str
    commitment: int
    pubkey: int
    proof: dict  # kept so anyone could re-verify the bid later
    committed_at: datetime
    seq: int  # global arrival order, used as the tie-breaker


@dataclass
class Reveal:
    bidder: str
    value: int
    randomness: int
    revealed_at: datetime


@dataclass
class Auction:
    auction_id: str
    item_name: str
    description: str
    bid_deadline: datetime
    reveal_deadline: datetime
    created_at: datetime
    bids: Dict[str, SealedBid] = field(default_factory=dict)  # keyed by bidder address
    reveals: Dict[str, Reveal] = field(default_factory=dict)

    def phase(self, now: datetime) -> str:
        if now < self.bid_deadline:
            return "bidding"
        if now < self.reveal_deadline:
            return "reveal"
        return "closed"


class Store:
    def __init__(self):
        self.lock = threading.RLock()  # guards every check-then-insert
        self.auctions: Dict[str, Auction] = {}
        self._seq = 0

    def next_seq(self) -> int:
        with self.lock:
            self._seq += 1
            return self._seq

    def get(self, auction_id: str) -> Optional[Auction]:
        return self.auctions.get(auction_id)

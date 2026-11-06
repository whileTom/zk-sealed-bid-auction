"""HTTP routes. Thin layer: parse -> call the phase service -> serialize.

Bid and reveal handlers are plain `def` (not async) so CPU-heavy proof verification runs in
FastAPI's threadpool instead of blocking the event loop.
"""
from typing import Optional

from fastapi import APIRouter, Query, Request

from . import bidding, reveal
from .crypto import params
from .schemas import AuctionCreate, AuctionDetail, AuctionOut, BidIn, BidOut, RevealIn

router = APIRouter()


def _state(request: Request):
    return request.app.state.store, request.app.state.clock


def _auction_out(a, now) -> dict:
    return {
        "auction_id": a.auction_id,
        "item_name": a.item_name,
        "description": a.description,
        "bid_deadline": a.bid_deadline,
        "reveal_deadline": a.reveal_deadline,
        "created_at": a.created_at,
        "phase": a.phase(now),
        "bid_range": [params.BID_MIN, params.BID_MAX],
        "sealed_count": len(a.bids),
        "revealed_count": len(a.reveals),
    }


@router.get("/params", tags=["crypto"])
def get_params():
    """Public group parameters (clients hard-code these and only cross-check)."""
    from .crypto.range_proof import coeffs
    return {
        "group": "RFC3526-MODP-2048",
        "p": params.to_hex(params.P),
        "q": params.to_hex(params.Q),
        "g": params.to_hex(params.G),
        "h": params.to_hex(params.H),
        "h_seed": params.H_SEED.decode(),
        "bid_min": params.BID_MIN,
        "bid_max": params.BID_MAX,
        "coefficients": coeffs(params.BID_MIN, params.BID_MAX),
    }


@router.post("/auction", status_code=201, response_model=AuctionOut, tags=["auction"])
def create_auction(body: AuctionCreate, request: Request):
    store, clock = _state(request)
    now = clock.now()
    a = bidding.create_auction(store, now, body.item_name, body.description,
                               body.bid_deadline, body.reveal_deadline)
    return _auction_out(a, now)


@router.get("/auction", response_model=list[AuctionOut], tags=["auction"])
def list_auctions(request: Request,
                  status: Optional[str] = Query("all", pattern="^(open|reveal|closed|all)$")):
    store, clock = _state(request)
    now = clock.now()
    want = {"open": "bidding", "reveal": "reveal", "closed": "closed"}.get(status)
    items = sorted(store.auctions.values(), key=lambda a: a.created_at, reverse=True)
    return [_auction_out(a, now) for a in items if want is None or a.phase(now) == want]


@router.get("/auction/{auction_id}", response_model=AuctionDetail, tags=["auction"])
def get_auction(auction_id: str, request: Request):
    store, clock = _state(request)
    a = reveal._get(store, auction_id)
    out = _auction_out(a, clock.now())
    out["sealed_bids"] = [
        {"bidder": b.bidder, "commitment": params.to_hex(b.commitment), "committed_at": b.committed_at}
        for b in sorted(a.bids.values(), key=lambda b: b.seq)
    ]
    return out


@router.post("/auction/{auction_id}/bid", status_code=201, response_model=BidOut, tags=["bidding"])
def submit_bid(auction_id: str, body: BidIn, request: Request):
    store, clock = _state(request)
    received_at = clock.now()  # captured before the (slow) proof verification
    bid = bidding.submit_bid(store, received_at, auction_id, body.bidder, body.commitment,
                             body.proof.model_dump())
    return {"auction_id": auction_id, "bidder": bid.bidder,
            "commitment": params.to_hex(bid.commitment), "accepted_at": bid.committed_at}


@router.post("/auction/{auction_id}/reveal", tags=["reveal"])
def submit_reveal(auction_id: str, body: RevealIn, request: Request):
    store, clock = _state(request)
    rev = reveal.submit_reveal(store, clock.now(), auction_id, body.bidder, body.value,
                               body.randomness, body.proof.model_dump())
    return {"bidder": rev.bidder, "value": rev.value,
            "current_leader": reveal.leader(store.get(auction_id))}


@router.get("/auction/{auction_id}/bids", tags=["reveal"])
def get_bids(auction_id: str, request: Request):
    store, clock = _state(request)
    return reveal.results(store, clock.now(), auction_id)

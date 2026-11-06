"""Pydantic request/response models (wire format). Shape validation only; cryptographic
validation happens in zkauction.crypto."""
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, StrictInt, field_validator

HEX512 = r"^[0-9a-f]{512}$"
ADDRESS = r"^0x[0-9a-f]{40}$"
Hex = Field(pattern=HEX512)


def _utc(v: Optional[datetime]) -> Optional[datetime]:
    """Naive datetimes are interpreted as UTC; aware ones are converted to UTC."""
    if v is None:
        return v
    try:
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError("datetime out of range") from None


class AuctionCreate(BaseModel):
    item_name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    bid_deadline: datetime
    reveal_deadline: Optional[datetime] = None

    _norm = field_validator("bid_deadline", "reveal_deadline")(_utc)


class AuctionOut(BaseModel):
    auction_id: str
    item_name: str
    description: str
    bid_deadline: datetime
    reveal_deadline: datetime
    created_at: datetime
    phase: str
    bid_range: List[int]
    sealed_count: int
    revealed_count: int


class SealedBidOut(BaseModel):
    bidder: str
    commitment: str
    committed_at: datetime


class AuctionDetail(AuctionOut):
    sealed_bids: List[SealedBidOut]


class BitProof(BaseModel):
    C: str = Hex
    A0: str = Hex
    A1: str = Hex
    e0: str = Hex
    e1: str = Hex
    z0: str = Hex
    z1: str = Hex


class RangeProof(BaseModel):
    bits: List[BitProof] = Field(min_length=1, max_length=64)


class BidAuth(BaseModel):
    pubkey: str = Hex
    R: str = Hex
    s: str = Hex


class NullifierProof(BaseModel):
    N: str = Hex
    R1: str = Hex
    R2: str = Hex
    s: str = Hex


class BidProof(BaseModel):
    range: RangeProof
    auth: BidAuth
    nullifier: NullifierProof


class BidIn(BaseModel):
    bidder: str = Field(pattern=ADDRESS, description="bidder address = 0x + SHA-256(pubkey)[:20]")
    commitment: str = Field(pattern=HEX512, description="Pedersen commitment G^v H^r mod P")
    proof: BidProof


class BidOut(BaseModel):
    auction_id: str
    bidder: str
    commitment: str
    accepted_at: datetime


class RevealAuth(BaseModel):
    R: str = Hex
    s: str = Hex


class RevealProof(BaseModel):
    commitment: str = Hex
    auth: RevealAuth


class RevealIn(BaseModel):
    bidder: str = Field(pattern=ADDRESS)
    value: StrictInt = Field(description="original bid value")
    randomness: str = Field(pattern=HEX512, description="opening randomness r")
    proof: RevealProof

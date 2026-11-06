from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from wallet.wallet import keygen
from zkauction.clock import FakeClock
from zkauction.main import create_app


@pytest.fixture(scope="session")
def wallets():
    """A few bidder identities, generated once per test session."""
    return {name: keygen() for name in ("alice", "bob", "carol", "dave")}


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def client(clock):
    return TestClient(create_app(clock=clock))


@pytest.fixture
def auction(client, clock):
    """An auction whose bidding phase ends 60 s from 'now' and reveal window 10 min later."""
    deadline = clock.now() + timedelta(seconds=60)
    r = client.post("/auction", json={
        "item_name": "Vintage watch",
        "description": "Sealed-bid test lot",
        "bid_deadline": deadline.isoformat(),
        "reveal_deadline": (deadline + timedelta(minutes=10)).isoformat(),
    })
    assert r.status_code == 201, r.text
    return r.json()

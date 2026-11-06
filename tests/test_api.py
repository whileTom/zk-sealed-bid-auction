"""End-to-end API tests: wallet (prover) -> HTTP -> phase services -> crypto verifiers."""
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from fastapi.testclient import TestClient

from wallet.wallet import keygen, make_bid, make_reveal
from zkauction.crypto.params import Q


def bid(client, auction_id, key, value):
    body, secret = make_bid(auction_id, key, value)
    return client.post("/auction/%s/bid" % auction_id, json=body), body, secret


def code(resp):
    return resp.json()["detail"]["code"]


# ---------------------------------------------------------------- auctions
def test_create_and_list(client, auction):
    assert auction["phase"] == "bidding" and auction["bid_range"] == [1, 1000]
    assert client.get("/auction").json()[0]["auction_id"] == auction["auction_id"]
    assert client.get("/auction/%s" % auction["auction_id"]).json()["sealed_bids"] == []


def test_create_rejects_past_deadline_and_missing_fields(client, clock):
    r = client.post("/auction", json={"item_name": "x", "description": "",
                                      "bid_deadline": (clock.now() - timedelta(seconds=1)).isoformat()})
    assert r.status_code == 422 and code(r) == "DEADLINE_IN_PAST"
    r = client.post("/auction", json={"item_name": "x"})
    assert r.status_code == 422 and code(r) == "VALIDATION_ERROR"


def test_naive_deadline_is_utc(client, clock):
    naive = (clock.now() + timedelta(hours=1)).replace(tzinfo=None).isoformat()
    r = client.post("/auction", json={"item_name": "x", "description": "", "bid_deadline": naive})
    assert r.status_code == 201
    assert r.json()["bid_deadline"].startswith(naive[:19])


def test_status_filter(client, clock, auction):
    assert len(client.get("/auction?status=open").json()) == 1
    clock.advance(61)
    assert client.get("/auction?status=open").json() == []
    assert len(client.get("/auction?status=reveal").json()) == 1


def test_unknown_auction_404(client, wallets):
    r, _, _ = bid(client, "nope", wallets["alice"], 10)
    assert r.status_code == 404 and code(r) == "AUCTION_NOT_FOUND"
    assert client.get("/auction/nope/bids").status_code == 404


# ---------------------------------------------------------------- bidding phase
def test_valid_bid_hides_amount(client, auction, wallets):
    aid = auction["auction_id"]
    r, body, secret = bid(client, aid, wallets["alice"], 437)
    assert r.status_code == 201, r.text
    detail = client.get("/auction/%s" % aid).json()
    assert detail["sealed_count"] == 1
    sealed = detail["sealed_bids"][0]
    assert set(sealed) == {"bidder", "commitment", "committed_at"}  # structurally no value field
    assert "value" not in r.json() and "randomness" not in r.json()


def test_duplicate_bidder_rejected(client, auction, wallets):
    aid = auction["auction_id"]
    assert bid(client, aid, wallets["alice"], 10)[0].status_code == 201
    r, _, _ = bid(client, aid, wallets["alice"], 20)
    assert r.status_code == 409 and code(r) == "DUPLICATE_BID"


def test_copied_bid_under_other_address_rejected(client, auction, wallets):
    aid = auction["auction_id"]
    r, body, _ = bid(client, aid, wallets["alice"], 300)
    assert r.status_code == 201
    stolen = copy.deepcopy(body)
    stolen["bidder"] = wallets["bob"]["address"]
    r = client.post("/auction/%s/bid" % aid, json=stolen)
    assert r.status_code in (400, 409)  # duplicate commitment caught first; proof is also bound to bidder


def test_invalid_proof_rejected(client, auction, wallets):
    aid = auction["auction_id"]
    body, _ = make_bid(aid, wallets["bob"], 99)
    body["proof"]["range"]["bits"][2]["z1"] = format(7, "0512x")
    r = client.post("/auction/%s/bid" % aid, json=body)
    assert r.status_code == 400 and code(r) == "INVALID_PROOF"
    body, _ = make_bid("some-other-auction", wallets["bob"], 99)  # replay from another auction
    r = client.post("/auction/%s/bid" % aid, json=body)
    assert r.status_code == 400


def test_malformed_hex_is_422(client, auction, wallets):
    body, _ = make_bid(auction["auction_id"], wallets["bob"], 50)
    body["commitment"] = "0x" + body["commitment"][2:]
    r = client.post("/auction/%s/bid" % auction["auction_id"], json=body)
    assert r.status_code == 422


def test_bid_after_deadline_rejected(client, clock, auction, wallets):
    clock.advance(60)  # exactly at the deadline
    r, _, _ = bid(client, auction["auction_id"], wallets["alice"], 10)
    assert r.status_code == 409 and code(r) == "BIDDING_CLOSED"


def test_bids_sealed_before_deadline(client, auction):
    r = client.get("/auction/%s/bids" % auction["auction_id"])
    assert r.status_code == 409 and code(r) == "BIDS_SEALED"


def test_concurrent_duplicate_bids_only_one_accepted(clock, wallets):
    client = TestClient(__import__("zkauction.main", fromlist=["create_app"]).create_app(clock=clock))
    deadline = clock.now() + timedelta(seconds=60)
    aid = client.post("/auction", json={"item_name": "x", "description": "",
                                        "bid_deadline": deadline.isoformat()}).json()["auction_id"]
    bodies = [make_bid(aid, wallets["carol"], v)[0] for v in (100, 200, 300)]
    with ThreadPoolExecutor(3) as ex:
        statuses = sorted(ex.map(lambda b: client.post("/auction/%s/bid" % aid, json=b).status_code, bodies))
    assert statuses == [201, 409, 409]


# ---------------------------------------------------------------- reveal phase
def test_full_flow_leader_and_winner(client, clock, auction, wallets):
    aid = auction["auction_id"]
    secrets_ = {}
    for name, v in (("alice", 300), ("bob", 700), ("carol", 700), ("dave", 50)):
        r, _, secrets_[name] = bid(client, aid, wallets[name], v)
        assert r.status_code == 201, r.text

    # reveal before the deadline is refused and changes nothing
    early = client.post("/auction/%s/reveal" % aid, json=make_reveal(aid, wallets["alice"], secrets_["alice"]))
    assert early.status_code == 409 and code(early) == "REVEAL_NOT_OPEN"
    assert "300" not in early.text

    clock.advance(61)
    res = client.get("/auction/%s/bids" % aid).json()
    assert res["current_leader"] is None and res["revealed"] == [] and len(res["unrevealed"]) == 4

    # reveal in a different order than bidding: carol (700) before bob (700)
    for name in ("carol", "alice", "bob"):
        r = client.post("/auction/%s/reveal" % aid, json=make_reveal(aid, wallets[name], secrets_[name]))
        assert r.status_code == 200, r.text

    res = client.get("/auction/%s/bids" % aid).json()
    # tie at 700 goes to the earliest sealed bid (bob bid before carol)
    assert res["current_leader"] == {"bidder": wallets["bob"]["address"], "value": 700}
    assert res["unrevealed"] == [wallets["dave"]["address"]] and res["final"] is False
    assert res["winner"] is None
    for row in res["revealed"]:  # each revealed bid is publicly re-verifiable
        from zkauction.crypto.pedersen import verify_opening
        assert verify_opening(int(row["commitment"], 16), row["value"], int(row["randomness"], 16))

    clock.advance(600)  # reveal window closes; dave forfeits
    res = client.get("/auction/%s/bids" % aid).json()
    assert res["phase"] == "closed" and res["final"] is True
    assert res["winner"] == {"bidder": wallets["bob"]["address"], "value": 700}
    late = client.post("/auction/%s/reveal" % aid, json=make_reveal(aid, wallets["dave"], secrets_["dave"]))
    assert late.status_code == 409 and code(late) == "REVEAL_CLOSED"


def test_reveal_negative_cases(client, clock, auction, wallets):
    aid = auction["auction_id"]
    r, _, secret = bid(client, aid, wallets["alice"], 512)
    assert r.status_code == 201
    clock.advance(61)
    url = "/auction/%s/reveal" % aid
    good = make_reveal(aid, wallets["alice"], secret)

    for value, expected in ((512 + Q, 400), (513, 400), (0, 400)):
        r = client.post(url, json=dict(good, value=value))
        assert r.status_code == expected and code(r) == "INVALID_OPENING", (value, r.text)
    for value in (True, "512", 512.0):
        assert client.post(url, json=dict(good, value=value)).status_code == 422
    wrong_r = format((int(good["randomness"], 16) + 1) % Q, "0512x")
    r = client.post(url, json=dict(good, randomness=wrong_r))
    assert r.status_code == 400 and code(r) == "INVALID_OPENING"
    other_c = dict(good["proof"], commitment=format(5, "0512x"))
    r = client.post(url, json=dict(good, proof=other_c))
    assert r.status_code == 400 and code(r) == "COMMITMENT_MISMATCH"
    bad_sig = {"commitment": good["proof"]["commitment"], "auth": dict(good["proof"]["auth"], s=format(9, "0512x"))}
    r = client.post(url, json=dict(good, proof=bad_sig))
    assert r.status_code == 400 and code(r) == "INVALID_PROOF"
    r = client.post(url, json=make_reveal(aid, wallets["bob"], secret))  # bob never bid
    assert r.status_code == 404 and code(r) == "BID_NOT_FOUND"

    # failed attempts changed nothing; the honest reveal still works, exactly once
    assert client.post(url, json=good).status_code == 200
    r = client.post(url, json=good)
    assert r.status_code == 409 and code(r) == "ALREADY_REVEALED"


def test_description_stored_verbatim(client, clock):
    payload = "<script>alert(1)</script>"
    r = client.post("/auction", json={"item_name": "x", "description": payload,
                                      "bid_deadline": (clock.now() + timedelta(seconds=30)).isoformat()})
    assert r.json()["description"] == payload  # the UI must render it with textContent

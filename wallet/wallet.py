"""Reference bidder wallet (prover side) in Python.

Used by the tests and scripts/demo.py, and usable as a CLI. frontend/zkp.js is the browser
port of exactly the same logic. The wallet runs on the bidder's machine: the bid value and
randomness never leave it until the reveal phase.

CLI:
  python -m wallet.wallet keygen --out alice.json
  python -m wallet.wallet bid --key alice.json --auction <id> --value 42 --out bid.json --secret secret.json
  python -m wallet.wallet reveal --key alice.json --auction <id> --secret secret.json --out reveal.json
Then POST bid.json / reveal.json to the API (e.g. curl -H "Content-Type: application/json" -d @bid.json ...).
"""
import argparse
import json

from zkauction.crypto import schnorr
from zkauction.crypto.params import BID_MAX, BID_MIN, from_hex, to_hex
from zkauction.crypto.pedersen import commit, random_scalar
from zkauction.crypto.range_proof import prove_range


def keygen() -> dict:
    sk, pk = schnorr.keygen()
    return {"sk": to_hex(sk), "pk": to_hex(pk), "address": schnorr.address_of(pk)}


def make_bid(auction_id: str, key: dict, value: int):
    """Return (request_body, secret). Keep `secret` private until the reveal phase."""
    sk, pk = from_hex(key["sk"]), from_hex(key["pk"])
    bidder = schnorr.address_of(pk)
    r = random_scalar()
    C = commit(value, r)
    bits = prove_range(value, r, auction_id, bidder, C, BID_MIN, BID_MAX)
    R, s = schnorr.sign(sk, pk, "bid", auction_id, bidder, C)
    body = {
        "bidder": bidder,
        "commitment": to_hex(C),
        "proof": {
            "range": {"bits": [{f: to_hex(v) for f, v in bp.items()} for bp in bits]},
            "auth": {"pubkey": to_hex(pk), "R": to_hex(R), "s": to_hex(s)},
        },
    }
    secret = {"auction_id": auction_id, "value": value, "randomness": to_hex(r), "commitment": to_hex(C)}
    return body, secret


def make_reveal(auction_id: str, key: dict, secret: dict) -> dict:
    sk, pk = from_hex(key["sk"]), from_hex(key["pk"])
    bidder = schnorr.address_of(pk)
    C, r, v = from_hex(secret["commitment"]), from_hex(secret["randomness"]), secret["value"]
    R, s = schnorr.sign(sk, pk, "reveal", auction_id, bidder, C, v, r)
    return {
        "bidder": bidder,
        "value": v,
        "randomness": secret["randomness"],
        "proof": {"commitment": secret["commitment"], "auth": {"R": to_hex(R), "s": to_hex(s)}},
    }


def _main():
    ap = argparse.ArgumentParser(description="zk-auction reference wallet")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    b = sub.add_parser("bid")
    b.add_argument("--key", required=True)
    b.add_argument("--auction", required=True)
    b.add_argument("--value", type=int, required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--secret", required=True)
    rv = sub.add_parser("reveal")
    rv.add_argument("--key", required=True)
    rv.add_argument("--auction", required=True)
    rv.add_argument("--secret", required=True)
    rv.add_argument("--out", required=True)
    a = ap.parse_args()

    def dump(path, obj):
        with open(path, "w", encoding="ascii") as f:
            json.dump(obj, f, indent=2)

    def load(path):
        with open(path, encoding="ascii") as f:
            return json.load(f)

    if a.cmd == "keygen":
        key = keygen()
        dump(a.out, key)
        print("address:", key["address"])
    elif a.cmd == "bid":
        body, secret = make_bid(a.auction, load(a.key), a.value)
        dump(a.out, body)
        dump(a.secret, secret)
        print("bid written to", a.out, "- keep", a.secret, "private until reveal")
    else:
        dump(a.out, make_reveal(a.auction, load(a.key), load(a.secret)))
        print("reveal written to", a.out)


if __name__ == "__main__":
    _main()

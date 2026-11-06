# zk-sealed-bid-auction

Minimal prototype of a decentralized sealed-bid auction with zero-knowledge proofs of bid validity.

Bidders submit a **Pedersen commitment** to their bid plus a **non-interactive zero-knowledge proof**
that the amount is in the allowed range (1-1000) and that they control the bidding address. The server
never sees an amount before the deadline. After the deadline, bidders open their commitments, the
server checks each opening against the commitment it stored at bid time, and publishes the current
leader (and the final winner once the reveal window closes). Every published opening can be
re-verified by anyone.

All cryptography is **real** (no mocked proofs). What is simulated is the infrastructure around it:
see "What is real vs simulated" below.

## Quick start

Requires Python 3.11+ (tested on 3.12, Windows 11). Node 18+ is optional (only for the cross-language test).

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1      bash:  source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn zkauction.main:app --port 8000
```

- UI: http://localhost:8000/ui/ (use `localhost`, not a LAN IP)
- Interactive API docs: http://localhost:8000/docs

## How to test

```bash
python -m pytest -q          # 46 tests, about 25 s (crypto, API, cross-language)
```

- `tests/test_crypto.py` - group parameters, Pedersen binding/hiding properties, exhaustive check of the
  range decomposition, range-proof roundtrips at the boundaries, tampering, replay into another
  auction/address, non-group elements, Schnorr signatures, reveal attacks (`value + q`, wrong
  randomness, mismatched commitment, forged signature).
- `tests/test_api.py` - the full HTTP flow with a fake clock: create, bid, duplicate bid (409),
  copied bid under another address, invalid proof (400), bid after deadline (409), bids sealed before
  the deadline (409), reveal before deadline, reveal attacks, double reveal, tie-break, final winner,
  late reveal, concurrent duplicate bids (exactly one accepted).
- `tests/test_cross_lang.py` - runs the browser prover (`frontend/zkp.js`) under Node and verifies
  its bid and reveal with the Python verifier (skipped if `node` is not installed).

**Manual walkthrough (browser):** open the UI, create identities "Alice" and "Bob", create an auction
ending in 60 seconds, bid as each identity (switch identity in the dropdown), wait for the deadline,
click "Reveal my bid" for each, and press "Verify" on the results rows.

**Manual walkthrough (curl + CLI wallet):** a ZK proof cannot be typed by hand, so use the reference wallet:

```bash
python -m wallet.wallet keygen --out alice.json
curl -s -X POST localhost:8000/auction -H "Content-Type: application/json" \
     -d '{"item_name":"Lamp","description":"demo","bid_deadline":"2030-01-01T00:00:00Z"}'
python -m wallet.wallet bid --key alice.json --auction <auction_id> --value 420 --out bid.json --secret secret.json
curl -s -X POST localhost:8000/auction/<auction_id>/bid -H "Content-Type: application/json" -d @bid.json
# after the deadline:
python -m wallet.wallet reveal --key alice.json --auction <auction_id> --secret secret.json --out reveal.json
curl -s -X POST localhost:8000/auction/<auction_id>/reveal -H "Content-Type: application/json" -d @reveal.json
curl -s localhost:8000/auction/<auction_id>/bids
```

## API

| Method | Path | Phase | Purpose |
|---|---|---|---|
| POST | `/auction` | - | Create: `item_name`, `description`, `bid_deadline` (ISO 8601; naive = UTC), optional `reveal_deadline` (default +10 min) |
| GET | `/auction?status=open\|reveal\|closed\|all` | any | List auctions |
| GET | `/auction/{id}` | any | Details + sealed commitments (never amounts) |
| GET | `/params` | any | Public group parameters |
| POST | `/auction/{id}/bid` | bidding | `{bidder, commitment, proof: {range: {bits: [...]}, auth: {pubkey, R, s}}}` |
| POST | `/auction/{id}/reveal` | reveal | `{bidder, value, randomness, proof: {commitment, auth: {R, s}}}` |
| GET | `/auction/{id}/bids` | reveal/closed | Revealed bids (with openings), unrevealed bidders, `current_leader`, `winner` |

Spec wording -> field: commitment -> `commitment`; bidder's address/ID -> `bidder`; ZKP -> `proof`;
original bid value -> `value`; opening randomness -> `randomness`; reveal consistency proof -> `proof`.

All numbers on the wire are 512-character lowercase hex. Errors are `{"detail": {"code", "message"}}`:
404 `AUCTION_NOT_FOUND` / `BID_NOT_FOUND`; 409 `BIDDING_CLOSED` / `REVEAL_NOT_OPEN` / `REVEAL_CLOSED` /
`BIDS_SEALED` / `DUPLICATE_BID` / `DUPLICATE_COMMITMENT` / `ALREADY_REVEALED`; 400 `INVALID_PROOF` /
`INVALID_OPENING` / `COMMITMENT_MISMATCH`; 422 `VALIDATION_ERROR` / `DEADLINE_IN_PAST`.

Phases: `bidding` (now < bid_deadline) -> `reveal` (until reveal_deadline) -> `closed`. Leader = highest
revealed value, ties go to the earliest sealed bid. Bidders who do not reveal forfeit.

## Architecture

```
browser / CLI wallet (prover)        FastAPI server (verifier + public bulletin board)
  frontend/zkp.js, wallet/wallet.py    zkauction/api.py          HTTP only
    commit, prove range, sign  ---->   zkauction/bidding.py      bidding phase: gates, uniqueness
    open + sign at reveal      ---->   zkauction/reveal.py       reveal phase: gates, leader/winner
                                       zkauction/crypto/         ALL proof checking
                                         bid_proof.verify_bid        <- [ZKP-VERIFY] bid phase
                                         reveal_proof.verify_reveal  <- [ZKP-VERIFY] reveal phase
                                         range_proof, schnorr, pedersen, params, transcript
                                       zkauction/store.py        in-memory state [SIMULATED chain]
```

The comment markers `[CRYPTO]`, `[ZKP-VERIFY]` and `[SIMULATED]` are grep-able and show exactly where
real primitives, proof validation and simulated infrastructure live.

## Cryptographic design

**Group.** The prime-order subgroup of Z_p^* for the RFC 3526 2048-bit safe prime p = 2q + 1 (about
112-bit security). G = 2. The second generator H is derived by hashing a public seed with SHA-256 and
squaring the result, so nobody knows log_G(H). Because p is a safe prime, subgroup membership of every
received element is checked with a Jacobi symbol (rejects small-subgroup elements like p - 1).

**Commitment.** C = G^v * H^r mod p with r uniform in [0, q). Perfectly hiding: C reveals nothing about
v. Binding: opening C to two values would reveal log_G(H).

**Range proof (v in [1, 1000]).** Bit decomposition with Cramer-Damgard-Schoenmakers OR-proofs:
1. x = v - 1 is written as sum b_i * w_i with bits b_i and weights w = [1, 2, 4, ..., 256, 488].
   These 10 weights represent exactly 0..999 (tested exhaustively), so 10 bit proofs suffice.
2. Each bit gets its own commitment C_i = G^b_i * H^r_i, with the r_i chosen so that
   prod C_i^w_i = C * G^-1. The verifier checks this product directly.
3. For each C_i the prover shows "C_i commits to 0 OR to 1" without saying which: a Schnorr proof of
   knowledge of log_H for C_i or for C_i / G, where the false branch is simulated. Fiat-Shamir makes it
   non-interactive; the two branch challenges must sum to the hash (mod 2^256), so at most one branch
   can be simulated.

The proof always has 10 bit proofs regardless of the amount, and real and simulated branches are
identically distributed, so it leaks nothing beyond "v is in range".

**Authorization.** A bidder identity is a key pair (sk, pk = G^sk); the address is the first 20 bytes of
SHA-256(pk). The bid carries a Schnorr signature over ("bid", auction_id, address, C), a zero-knowledge
proof of knowledge of sk. The server accepts at most one bid per address and per commitment in each
auction.

**Fiat-Shamir binding.** Every challenge hashes a domain tag, the auction id, the bidder address, the
commitment, the range and all bit commitments (type-tagged, length-prefixed encoding shared by Python
and JS). A proof therefore cannot be replayed in another auction, under another address, or for a
shifted commitment such as C * G.

**Reveal consistency.** The opening (value, randomness) is itself the proof that the reveal matches the
commitment: the server recomputes G^value * H^randomness and compares it with the commitment **stored at
bid time** (the request's `proof.commitment` must match it). `value` must be an integer in [1, 1000] and
`randomness` in [0, q); without this, `value + q` would open the same commitment (exponents wrap mod q)
and win the auction. A Schnorr signature over the reveal binds it to the bidder's key.

## What is real vs simulated

| Component | Status | Production replacement |
|---|---|---|
| Pedersen commitments, range proof, Schnorr signatures, reveal checks | Real | Elliptic-curve group (Ristretto255) and Bulletproofs for log-size range proofs |
| `zkauction/store.py` in-memory state | Simulated chain / bulletin board | Smart contract or signed, append-only log |
| Wallet keys in browser `localStorage` | Simulated wallet | Browser wallet or hardware key |
| "One bid per address" | Enforced by the verifier on the address proven in ZK | Anonymous credentials / nullifiers (Semaphore-style) for Sybil-resistant, anonymous bidding |
| Non-revealing bidders | Forfeit, nothing else | Deposits that are slashed on non-reveal |

Libraries considered: `pymerkletools` is not on PyPI and `merkletools` fails to build on Python 3.12
Windows; `py_ecc` only provides curve arithmetic (no commitments or range proofs). The primitives are
therefore implemented with the Python standard library (`pow`, `hashlib`, `secrets`) and JS `BigInt`,
which keeps the Python verifier and the browser prover byte-for-byte identical.

Measured on a Ryzen 7 6800H: proving about 0.6 s (Python and browser), verifying about 0.35 s per bid.

## Security notes and limitations

- Bids stay confidential before the deadline: the server only receives commitments and ZK proofs,
  `GET /auction/{id}/bids` returns 409 until the deadline, and errors never echo request bodies.
- The UI renders all server data with `textContent` and `/ui` is served with a strict Content-Security-Policy,
  because an XSS bug would leak the bids stored in `localStorage`.
- The server is trusted not to censor bids (a real chain removes that trust).
- Addresses are free to create, so "one bid per address" does not stop one person from using many
  addresses; deposits or identity would be needed.
- Big-integer arithmetic in Python/JS is not constant-time.

## Project layout

```
zkauction/            backend package (api, bidding, reveal, store, schemas, clock, errors, main)
zkauction/crypto/     params, transcript, pedersen, range_proof, schnorr, bid_proof, reveal_proof
wallet/wallet.py      reference prover + CLI
frontend/             index.html, app.js (UI), zkp.js (browser prover), style.css
scripts/js_prove.mjs  runs zkp.js under Node for the cross-language test
tests/                pytest suite
```

# zk-sealed-bid-auction

Minimal prototype of a decentralized sealed-bid auction with zero-knowledge proofs of bid validity.

Bidders submit a **Pedersen commitment** to their bid plus a **non-interactive zero-knowledge proof**
that the amount is in the allowed range (1-1000), that they control the bidding address, and that this
is their only bid in the auction (an auction-scoped nullifier). The server
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
python -m pytest -q          # 52 tests, about 30 s (crypto, API, cross-language)
```

- `tests/test_crypto.py` - group parameters, Pedersen binding/hiding properties, exhaustive check of the
  range decomposition, range-proof roundtrips at the boundaries, tampering, replay into another
  auction/address, non-group elements, Schnorr signatures, nullifier determinism and forged/replayed
  nullifiers, reveal attacks (`value + q`, wrong randomness, mismatched commitment, forged signature).
- `tests/test_api.py` - the full HTTP flow with a fake clock: create, bid, duplicate bid (409),
  copied bid under another address, invalid proof (400), bid after deadline (409), bids sealed before
  the deadline (409), reveal before deadline, reveal attacks, double reveal, tie-break, final winner,
  late reveal, concurrent duplicate bids (exactly one accepted), extreme deadlines (422, never 500),
  uniform error envelope.
- `tests/test_cross_lang.py` - runs the browser prover (`frontend/zkp.js`) under Node and verifies
  its bid and reveal with the Python verifier (skipped if `node` is not installed).

**Manual walkthrough (browser):** open the UI, create identities "Alice" and "Bob", create an auction
ending in 60 seconds, bid as each identity (switch identity in the dropdown), wait for the deadline,
click "Reveal my bid" for each, and press "Verify" on the results rows.

**Manual walkthrough (curl + CLI wallet):** a ZK proof cannot be typed by hand, so use the reference wallet.
Files go in `demo/` (git-ignored): `alice.json` holds a private key and `secret.json` the bid opening.

bash (Linux/macOS, or Git Bash/WSL on Windows):

```bash
mkdir -p demo
python -m wallet.wallet keygen --out demo/alice.json
# bidding closes 60 s from now so the reveal phase is reachable in the same session
DEADLINE=$(python -c "import datetime as d; print((d.datetime.now(d.timezone.utc)+d.timedelta(seconds=60)).isoformat())")
curl -s -X POST localhost:8000/auction -H "Content-Type: application/json" \
     -d "{\"item_name\":\"Lamp\",\"description\":\"demo\",\"bid_deadline\":\"$DEADLINE\"}"
python -m wallet.wallet bid --key demo/alice.json --auction <auction_id> --value 420 --out demo/bid.json --secret demo/secret.json
curl -s -X POST localhost:8000/auction/<auction_id>/bid -H "Content-Type: application/json" -d @demo/bid.json
# wait until the deadline has passed, then:
python -m wallet.wallet reveal --key demo/alice.json --auction <auction_id> --secret demo/secret.json --out demo/reveal.json
curl -s -X POST localhost:8000/auction/<auction_id>/reveal -H "Content-Type: application/json" -d @demo/reveal.json
curl -s localhost:8000/auction/<auction_id>/bids
```

Windows PowerShell (in PowerShell, `curl` is an alias for something else, so use `Invoke-RestMethod`):

```powershell
mkdir demo -Force | Out-Null
python -m wallet.wallet keygen --out demo/alice.json
$deadline = (Get-Date).ToUniversalTime().AddSeconds(60).ToString("o")
$a = Invoke-RestMethod -Method Post -Uri http://localhost:8000/auction -ContentType application/json `
     -Body (@{item_name="Lamp"; description="demo"; bid_deadline=$deadline} | ConvertTo-Json)
python -m wallet.wallet bid --key demo/alice.json --auction $a.auction_id --value 420 --out demo/bid.json --secret demo/secret.json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/auction/$($a.auction_id)/bid" -ContentType application/json -InFile demo/bid.json
# wait until the deadline has passed, then:
python -m wallet.wallet reveal --key demo/alice.json --auction $a.auction_id --secret demo/secret.json --out demo/reveal.json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/auction/$($a.auction_id)/reveal" -ContentType application/json -InFile demo/reveal.json
Invoke-RestMethod "http://localhost:8000/auction/$($a.auction_id)/bids" | ConvertTo-Json -Depth 5
```

## API

| Method | Path | Phase | Purpose |
|---|---|---|---|
| POST | `/auction` | - | Create: `item_name`, `description`, `bid_deadline` (ISO 8601; naive = UTC), optional `reveal_deadline` (default +10 min) |
| GET | `/auction?status=open\|reveal\|closed\|all` | any | List auctions |
| GET | `/auction/{id}` | any | Details + sealed commitments (never amounts) |
| GET | `/params` | any | Public group parameters |
| POST | `/auction/{id}/bid` | bidding | `{bidder, commitment, proof: {range: {bits: [...]}, auth: {pubkey, R, s}, nullifier: {N, R1, R2, s}}}` |
| POST | `/auction/{id}/reveal` | reveal | `{bidder, value, randomness, proof: {commitment, auth: {R, s}}}` |
| GET | `/auction/{id}/bids` | reveal/closed | `revealed` bids (with openings), `unrevealed` bidders, `current_leader`, `final`, `winner` |

`final` is true once the leader can no longer change (every sealed bid revealed, or the reveal window
closed); `winner` equals the leader when `final` is true and is `null` otherwise.

Spec wording -> field: commitment -> `commitment`; bidder's address/ID -> `bidder`; ZKP -> `proof`;
original bid value -> `value`; opening randomness -> `randomness`; reveal consistency proof -> `proof`.

Group elements, scalars and challenges are 512-character lowercase hex; `value` is a JSON integer;
`bidder` is `0x` + 40 lowercase hex. Every error uses `{"detail": {"code", "message"}}`:
404 `AUCTION_NOT_FOUND` / `BID_NOT_FOUND` / `NOT_FOUND`; 405 `METHOD_NOT_ALLOWED`; 409 `BIDDING_CLOSED` /
`REVEAL_NOT_OPEN` / `REVEAL_CLOSED` / `BIDS_SEALED` / `DUPLICATE_BID` / `DUPLICATE_COMMITMENT` /
`ALREADY_REVEALED`; 400 `INVALID_PROOF` / `INVALID_OPENING` / `COMMITMENT_MISMATCH` / `BAD_REQUEST`;
422 `VALIDATION_ERROR` / `DEADLINE_IN_PAST` / `DEADLINE_TOO_FAR` / `BAD_REVEAL_DEADLINE`.

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

**Authorization (one bid per address per auction).** A bidder identity is a key pair (sk, pk = G^sk);
the address is the first 20 bytes of SHA-256(pk). The bid proof contains:
- a Schnorr signature over ("bid", auction_id, address, C): a zero-knowledge proof of knowledge of sk,
  so only the owner of the address can bid with it;
- an **auction-scoped nullifier** N = H_a^sk, where H_a is hashed from the auction id, with a
  Chaum-Pedersen proof that log_G(pk) = log_{H_a}(N). A key has exactly one valid N per auction, so
  "at most one bid" is part of the proven statement: the verifier rejects any second bid whose N was
  already used (409 `DUPLICATE_BID`). Nullifiers of different auctions are unlinkable.

The server additionally rejects reused addresses and reused commitments (defense in depth).

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
| "One bid per address" | Real: nullifier + Chaum-Pedersen proof, checked by the verifier | Add ZK set membership (Semaphore-style) on top of the nullifier for anonymous, allowlisted bidding |
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
- The server is trusted not to censor bids (a real chain removes that trust). A bid's arrival time is
  stamped when the request reaches the server, before it waits for proof verification, so load cannot
  push an honest bid past the deadline. There is no rate limiting; a public deployment would add it,
  since each invalid proof still costs about 0.35 s of CPU to reject.
- Addresses are free to create, so "one bid per address" does not stop one person from using many
  addresses; deposits or identity would be needed.
- Big-integer arithmetic in Python/JS is not constant-time.

## Project layout

```
zkauction/            backend package (api, bidding, reveal, store, schemas, clock, errors, main)
zkauction/crypto/     params, transcript, pedersen, range_proof, schnorr, nullifier, bid_proof,
                      reveal_proof, errors
wallet/wallet.py      reference prover + CLI
frontend/             index.html, app.js (UI), zkp.js (browser prover), style.css
scripts/js_prove.mjs  runs zkp.js under Node for the cross-language test
tests/                pytest suite
```

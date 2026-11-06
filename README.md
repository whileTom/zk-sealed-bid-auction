# zk-sealed-bid-auction

Minimal prototype of a decentralized sealed-bid auction platform with zero-knowledge proofs of bid validity.

Bidders submit a Pedersen commitment to their bid together with a non-interactive zero-knowledge proof that
the amount is in the allowed range (1-1000) and that they are an authorized bidder (one bid per address per
auction). Amounts stay hidden until the bidding deadline. After the deadline, bidders open their commitments,
the server verifies each opening against the original commitment, and the leader is published.

## Status

Work in progress. Setup steps, the cryptographic design, and test instructions will be added as the
implementation lands.

## Planned API

| Method | Path                         | Phase           | Purpose                                                      |
|--------|------------------------------|-----------------|--------------------------------------------------------------|
| POST   | /auction                     | -               | Create an auction (item_name, description, bid_deadline)     |
| POST   | /auction/{auction_id}/bid    | before deadline | Submit a sealed bid: commitment, bidder address, ZK proof    |
| POST   | /auction/{auction_id}/reveal | after deadline  | Open the commitment: value, randomness, consistency proof    |
| GET    | /auction/{auction_id}/bids   | after deadline  | Revealed bids and the current leader                         |

## Planned stack

- Backend: Python, FastAPI, in-memory storage
- Crypto: Pedersen commitments, Fiat-Shamir range proofs, Schnorr-based bidder authorization
- Frontend: minimal HTML/JS, proofs generated client-side so bid amounts never leave the browser before reveal
- Tests: pytest

"""Unit tests for the cryptographic layer (no HTTP)."""
import copy
import secrets

import pytest

from wallet.wallet import keygen, make_bid, make_reveal
from zkauction.crypto import schnorr
from zkauction.crypto.bid_proof import verify_bid
from zkauction.crypto.errors import CommitmentMismatch, InvalidOpening, InvalidProof
from zkauction.crypto.params import (BID_MAX, BID_MIN, G, H, P, Q, E_MOD, from_hex, is_element,
                                     jacobi, to_hex)
from zkauction.crypto.pedersen import commit, random_scalar, verify_opening
from zkauction.crypto.range_proof import coeffs, decompose, prove_range, verify_range
from zkauction.crypto.reveal_proof import verify_reveal
from zkauction.crypto.transcript import hash_int


# ---------------------------------------------------------------- parameters
def test_group_parameters():
    assert P.bit_length() == 2048 and P % 8 == 7
    assert pow(G, Q, P) == 1 and pow(H, Q, P) == 1
    assert to_hex(H).startswith("491fccc8e75ee9be")  # golden value shared with zkp.js


def test_jacobi_matches_euler_criterion():
    for _ in range(20):
        x = secrets.randbelow(P - 2) + 2
        assert (jacobi(x, P) == 1) == (pow(x, Q, P) == 1)


def test_is_element_rejects_bad_values():
    for bad in (0, 1, P - 1, P, P + 4, -4, True):
        assert not is_element(bad)
    assert is_element(G) and is_element(H)


def test_from_hex_is_strict():
    good = to_hex(0xABCDEF)
    assert from_hex(good) == 0xABCDEF
    for bad in ("0x" + good[2:], good.upper(), good[1:], " " + good[1:], "-" + good[1:]):
        with pytest.raises(ValueError):
            from_hex(bad)


def test_transcript_is_type_tagged():
    assert hash_int(5) != hash_int("5")
    assert hash_int("a", "bc") != hash_int("ab", "c")
    with pytest.raises(TypeError):
        hash_int(True)


# ---------------------------------------------------------------- pedersen
def test_pedersen_open_and_bind():
    r = random_scalar()
    C = commit(500, r)
    assert verify_opening(C, 500, r)
    assert not verify_opening(C, 501, r)
    assert not verify_opening(C, 500, (r + 1) % Q)


def test_pedersen_rejects_mod_q_aliases():
    """Exponents wrap mod Q: v+Q and r+Q open the same C, so they must be rejected."""
    r = random_scalar()
    C = commit(5, r)
    assert commit(5 + Q, r) == C  # the algebra really aliases...
    assert not verify_opening(C, 5 + Q, r)  # ...so verify_opening enforces canonical ranges
    assert not verify_opening(C, 5, r + Q)
    assert not verify_opening(C, True, r)


def test_pedersen_homomorphic():
    r1, r2 = random_scalar(), random_scalar()
    assert commit(3, r1) * commit(4, r2) % P == commit(7, (r1 + r2) % Q)


# ---------------------------------------------------------------- decomposition
def test_coefficients_cover_exactly_the_range():
    coef = coeffs(BID_MIN, BID_MAX)
    assert coef == [1, 2, 4, 8, 16, 32, 64, 128, 256, 488]
    representable = {sum(c for i, c in enumerate(coef) if m >> i & 1) for m in range(1 << len(coef))}
    assert representable == set(range(BID_MAX - BID_MIN + 1))
    for x in range(BID_MAX - BID_MIN + 1):
        bits = decompose(x, coef)
        assert set(bits) <= {0, 1} and sum(b * c for b, c in zip(bits, coef)) == x


def test_coeffs_rejects_empty_range():
    with pytest.raises(ValueError):
        coeffs(5, 5)


# ---------------------------------------------------------------- range proof
def _ctx(v):
    r = random_scalar()
    C = commit(v, r)
    return r, C


@pytest.mark.parametrize("v", [1, 512, 1000])
def test_range_proof_roundtrip(v):
    r, C = _ctx(v)
    proof = prove_range(v, r, "auc", "0x" + "ab" * 20, C, BID_MIN, BID_MAX)
    verify_range(proof, "auc", "0x" + "ab" * 20, C, BID_MIN, BID_MAX)


@pytest.mark.parametrize("v", [0, 1001])
def test_prover_refuses_out_of_range(v):
    r, C = _ctx(v)
    with pytest.raises(ValueError):
        prove_range(v, r, "auc", "0x" + "ab" * 20, C, BID_MIN, BID_MAX)


def test_cheating_prover_with_bit_two_is_rejected():
    """Forge a 'proof' for v = 1001 by committing a bit value of 2: the OR-proof cannot hold."""
    v, bidder = 1001, "0x" + "cd" * 20
    r, C = _ctx(v)
    honest_r, honest_C = _ctx(1000)
    proof = prove_range(1000, honest_r, "auc", bidder, honest_C, BID_MIN, BID_MAX)
    with pytest.raises(InvalidProof):
        verify_range(proof, "auc", bidder, C, BID_MIN, BID_MAX)  # bits do not recombine to C


@pytest.fixture(scope="module")
def good_range_proof():
    v, bidder = 777, "0x" + "ef" * 20
    r, C = _ctx(v)
    return prove_range(v, r, "auc", bidder, C, BID_MIN, BID_MAX), bidder, C


@pytest.mark.parametrize("field", ["C", "A0", "e0", "z1"])
def test_tampered_bit_proof_rejected(good_range_proof, field):
    proof, bidder, C = good_range_proof
    bad = copy.deepcopy(proof)
    bad[4][field] = (bad[4][field] * 4) % P if field in ("C", "A0") else (bad[4][field] + 1) % E_MOD
    with pytest.raises(InvalidProof):
        verify_range(bad, "auc", bidder, C, BID_MIN, BID_MAX)


def test_range_proof_bound_to_context(good_range_proof):
    proof, bidder, C = good_range_proof
    with pytest.raises(InvalidProof):
        verify_range(proof, "other-auction", bidder, C, BID_MIN, BID_MAX)
    with pytest.raises(InvalidProof):
        verify_range(proof, "auc", "0x" + "00" * 20, C, BID_MIN, BID_MAX)


def test_wrong_bit_count_and_non_group_elements(good_range_proof):
    proof, bidder, C = good_range_proof
    with pytest.raises(InvalidProof):
        verify_range(proof[:-1], "auc", bidder, C, BID_MIN, BID_MAX)
    bad = copy.deepcopy(proof)
    bad[0]["A1"] = P - 1  # order-2 element
    with pytest.raises(InvalidProof):
        verify_range(bad, "auc", bidder, C, BID_MIN, BID_MAX)
    bad = copy.deepcopy(proof)
    bad[0]["e0"] = E_MOD  # challenge out of range
    with pytest.raises(InvalidProof):
        verify_range(bad, "auc", bidder, C, BID_MIN, BID_MAX)


def test_branch_challenges_do_not_reveal_bits():
    """Both branch challenges are uniform in [0, 2^256): neither branch is distinguishable."""
    r, C = _ctx(1000)
    proof = prove_range(1000, r, "auc", "0x" + "ab" * 20, C, BID_MIN, BID_MAX)
    assert all(0 <= bp["e0"] < E_MOD and 0 <= bp["e1"] < E_MOD for bp in proof)


# ---------------------------------------------------------------- schnorr / full bid / reveal
def test_schnorr_sign_verify():
    sk, pk = schnorr.keygen()
    R, s = schnorr.sign(sk, pk, "msg", 1)
    assert schnorr.verify(pk, R, s, "msg", 1)
    assert not schnorr.verify(pk, R, s, "msg", 2)
    assert not schnorr.verify(pk, R, s + Q, "msg", 1)
    _, other = schnorr.keygen()
    assert not schnorr.verify(other, R, s, "msg", 1)


@pytest.fixture(scope="module")
def bid_bundle():
    key = keygen()
    body, secret = make_bid("auc-1", key, 640)
    return key, body, secret


def test_full_bid_and_reveal(bid_bundle):
    key, body, secret = bid_bundle
    C, pk = verify_bid("auc-1", body["bidder"], body["commitment"], body["proof"])
    rv = make_reveal("auc-1", key, secret)
    assert verify_reveal("auc-1", body["bidder"], C, pk, rv["value"], rv["randomness"], rv["proof"])


def test_bid_rejected_for_other_address(bid_bundle):
    _, body, _ = bid_bundle
    with pytest.raises(InvalidProof):
        verify_bid("auc-1", keygen()["address"], body["commitment"], body["proof"])


def test_shifted_commitment_with_original_proof_rejected(bid_bundle):
    """C * G opens to v+1: reusing the proof for a shifted commitment must fail."""
    _, body, _ = bid_bundle
    shifted = to_hex(from_hex(body["commitment"]) * G % P)
    with pytest.raises(InvalidProof):
        verify_bid("auc-1", body["bidder"], shifted, body["proof"])


def test_reveal_negative_cases(bid_bundle):
    key, body, secret = bid_bundle
    C, pk = verify_bid("auc-1", body["bidder"], body["commitment"], body["proof"])
    rv = make_reveal("auc-1", key, secret)
    with pytest.raises(InvalidOpening):
        verify_reveal("auc-1", body["bidder"], C, pk, rv["value"] + Q, rv["randomness"], rv["proof"])
    with pytest.raises(InvalidOpening):
        verify_reveal("auc-1", body["bidder"], C, pk, rv["value"] + 1, rv["randomness"], rv["proof"])
    other = dict(rv["proof"], commitment=to_hex(commit(1000, 1)))
    with pytest.raises(CommitmentMismatch):
        verify_reveal("auc-1", body["bidder"], C, pk, rv["value"], rv["randomness"], other)
    bad_sig = {"commitment": rv["proof"]["commitment"], "auth": {"R": rv["proof"]["auth"]["R"], "s": to_hex(5)}}
    with pytest.raises(InvalidProof):
        verify_reveal("auc-1", body["bidder"], C, pk, rv["value"], rv["randomness"], bad_sig)

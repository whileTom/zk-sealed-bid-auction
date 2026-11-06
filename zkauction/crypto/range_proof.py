"""Non-interactive zero-knowledge range proof: the committed bid v is in [lo, hi].

[CRYPTO] Construction (bit decomposition + CDS OR-proofs, Fiat-Shamir):

1. Let x = v - lo and D = hi - lo. Write x = sum_i b_i * coef_i with bits b_i in {0, 1} and
   coef = [1, 2, 4, ..., 2^(k-2), D - (2^(k-1) - 1)]. For [1, 1000]: k = 10 and the last
   weight is 488. The representable set is [0, 2^(k-1) - 1] U [coef_{k-1}, D] = [0, D]
   exactly, so 10 bit proofs cover the range (instead of 20 for a two-sided proof).
2. Commit to each bit: C_i = G^b_i * H^r_i, with r_0 chosen so that sum coef_i * r_i = r.
   Then prod C_i^coef_i = G^x * H^r = C * G^-lo, which the verifier checks directly.
3. For each C_i prove "C_i commits to 0 OR to 1" without saying which (Cramer-Damgard-
   Schoenmakers OR-composition of two Schnorr proofs of knowledge of log_H):
       Y0 = C_i (= H^r_i if b = 0),  Y1 = C_i / G (= H^r_i if b = 1)
   The true branch is proven honestly; the other is simulated by picking its challenge and
   response first. The two branch challenges must sum to the Fiat-Shamir hash mod 2^256,
   so the prover can simulate at most one branch.

Zero knowledge: every C_i is a perfectly hiding commitment and real/simulated branches are
identically distributed, so the proof reveals nothing about v beyond v in [lo, hi]. The proof
always has exactly k bit proofs regardless of v.
"""
import secrets

from .errors import InvalidProof
from .params import E_MOD, G, G_INV, P, Q, hexp, gexp, is_element, is_scalar
from .transcript import hash_int

STMT_DOMAIN = "zk-auction/v1/range-stmt"
BIT_DOMAIN = "zk-auction/v1/range-bit"


def coeffs(lo: int, hi: int) -> list:
    D = hi - lo
    if not 1 <= D < 1 << 64:
        raise ValueError("range width must be in [1, 2^64)")
    k = D.bit_length()
    return [1 << i for i in range(k - 1)] + [D - ((1 << (k - 1)) - 1)]


def decompose(x: int, coef: list) -> list:
    """Bits b with sum(b_i * coef_i) == x, for 0 <= x <= sum(coef)."""
    k = len(coef)
    if x < 1 << (k - 1):
        top, rest = 0, x
    else:
        top, rest = 1, x - coef[-1]
    return [(rest >> i) & 1 for i in range(k - 1)] + [top]


def _statement(auction_id, bidder, C, lo, hi, bit_commitments) -> int:
    """Digest of the whole statement, bound into every bit challenge (strong Fiat-Shamir)."""
    return hash_int(STMT_DOMAIN, auction_id, bidder, C, lo, hi, *bit_commitments)


def prove_range(v: int, r: int, auction_id: str, bidder: str, C: int, lo: int, hi: int) -> list:
    """Prover side (runs in the bidder's wallet). Returns a list of k bit proofs (ints)."""
    coef = coeffs(lo, hi)
    k = len(coef)
    x = v - lo
    if not 0 <= x <= hi - lo:
        raise ValueError("bid out of range")
    bits = decompose(x, coef)

    rs = [0] + [secrets.randbelow(Q) for _ in range(k - 1)]
    rs[0] = (r - sum(coef[i] * rs[i] for i in range(1, k))) % Q
    Cs = [(G if bits[i] else 1) * hexp(rs[i]) % P for i in range(k)]
    S = _statement(auction_id, bidder, C, lo, hi, Cs)

    proof = []
    for i in range(k):
        Y = (Cs[i], Cs[i] * G_INV % P)
        b, s = bits[i], 1 - bits[i]
        e, z, A = [0, 0], [0, 0], [0, 0]
        # Simulated branch: choose challenge and response, solve for the commitment.
        e[s] = secrets.randbits(256)
        z[s] = secrets.randbelow(Q)
        A[s] = hexp(z[s]) * pow(Y[s], Q - e[s], P) % P  # H^z * Y^-e
        # Real branch: honest Schnorr commitment.
        w = secrets.randbelow(Q)
        A[b] = hexp(w)
        ch = hash_int(BIT_DOMAIN, S, i, A[0], A[1])
        e[b] = (ch - e[s]) % E_MOD
        z[b] = (w + e[b] * rs[i]) % Q
        proof.append({"C": Cs[i], "A0": A[0], "A1": A[1], "e0": e[0], "e1": e[1], "z0": z[0], "z1": z[1]})
    return proof


def verify_range(proof: list, auction_id: str, bidder: str, C: int, lo: int, hi: int) -> None:
    """[ZKP-VERIFY] Raise InvalidProof unless `proof` shows C commits to a value in [lo, hi].

    Cheap structural checks run first, exponentiations last.
    """
    coef = coeffs(lo, hi)
    k = len(coef)
    if not isinstance(proof, list) or len(proof) != k:
        raise InvalidProof("range proof must contain exactly %d bit proofs" % k)
    for bp in proof:
        if not (is_scalar(bp["z0"]) and is_scalar(bp["z1"])):
            raise InvalidProof("response out of range")
        if not (0 <= bp["e0"] < E_MOD and 0 <= bp["e1"] < E_MOD):
            raise InvalidProof("challenge out of range")
    if not is_element(C):
        raise InvalidProof("commitment is not a group element")
    for bp in proof:
        if not (is_element(bp["C"]) and is_element(bp["A0"]) and is_element(bp["A1"])):
            raise InvalidProof("bit proof contains a non-group element")

    # Bits must recombine to the bid commitment shifted by lo.
    acc = 1
    for i, bp in enumerate(proof):
        acc = acc * pow(bp["C"], coef[i], P) % P
    if acc != C * gexp(Q - lo) % P:
        raise InvalidProof("bit commitments do not match the bid commitment")

    S = _statement(auction_id, bidder, C, lo, hi, [bp["C"] for bp in proof])
    for i, bp in enumerate(proof):
        if (bp["e0"] + bp["e1"]) % E_MOD != hash_int(BIT_DOMAIN, S, i, bp["A0"], bp["A1"]):
            raise InvalidProof("bit %d: Fiat-Shamir challenge mismatch" % i)
    for i, bp in enumerate(proof):
        Y0, Y1 = bp["C"], bp["C"] * G_INV % P
        if hexp(bp["z0"]) != bp["A0"] * pow(Y0, bp["e0"], P) % P:
            raise InvalidProof("bit %d: branch 0 equation fails" % i)
        if hexp(bp["z1"]) != bp["A1"] * pow(Y1, bp["e1"], P) % P:
            raise InvalidProof("bit %d: branch 1 equation fails" % i)

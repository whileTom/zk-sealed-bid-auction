"""Pedersen commitments: C = G^v * H^r mod P.

[CRYPTO] Perfectly hiding (for uniform r, C is a uniform group element whatever v is) and
computationally binding (opening C to two different values would reveal log_G(H)).
"""
import secrets

from .params import BID_MAX, BID_MIN, P, Q, gexp, hexp, is_scalar


def random_scalar() -> int:
    return secrets.randbelow(Q)


def commit(v: int, r: int) -> int:
    return gexp(v) * hexp(r) % P


def verify_opening(C: int, v, r) -> bool:
    """[CRYPTO] Check that (v, r) opens C.

    The integer-range checks are essential: exponents only matter mod Q, so without them a
    bidder who committed to 500 could "reveal" 500 + Q (a 2048-bit number) and win.
    """
    if type(v) is not int or not BID_MIN <= v <= BID_MAX:
        return False
    if not is_scalar(r):
        return False
    return commit(v, r) == C

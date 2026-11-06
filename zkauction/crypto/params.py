"""Public group parameters and low-level group helpers.

[CRYPTO] All commitments, proofs and signatures in this project live in the prime-order
subgroup of Z_p^* where p is the RFC 3526 group 14 safe prime (2048 bit, p = 2q + 1).

- G = 2 generates the order-q subgroup (p = 7 mod 8, so 2 is a quadratic residue).
- H is a second generator derived by hashing a public seed ("nothing up my sleeve"), so
  nobody knows log_G(H). That is what makes Pedersen commitments binding.
- Because p is a safe prime, the order-q subgroup is exactly the set of quadratic residues,
  so subgroup membership is checked with a cheap Jacobi symbol instead of pow(x, q, p).

The same constants are hard-coded in frontend/zkp.js; tests check they stay identical.
"""
import hashlib

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
Q = (P - 1) // 2
G = 2
G_INV = (P + 1) // 2  # 2 * G_INV = P + 1 = 1 (mod P)

H_SEED = b"zk-auction/pedersen-h/v1"

# Bid range enforced by the range proof and again at reveal time.
BID_MIN = 1
BID_MAX = 1000

# Fiat-Shamir challenges for the bit OR-proofs are 256-bit (SHA-256 output) and are
# split modulo 2^256. Since 2^256 < Q, special soundness still holds.
E_MOD = 1 << 256

# Wire format: every group element / scalar / challenge is exactly 512 lowercase hex chars.
HEX_LEN = 512


def hash_to_group(seed: bytes) -> int:
    """Hash-to-group: expand the seed with SHA-256 in counter mode, reduce mod P, square.
    Squaring lands in the order-Q subgroup; nobody knows the result's discrete log."""
    stream = b"".join(
        hashlib.sha256(seed + j.to_bytes(4, "big")).digest() for j in range(9)
    )[:288]
    x = int.from_bytes(stream, "big") % P
    return x * x % P


H = hash_to_group(H_SEED)


def jacobi(a: int, n: int) -> int:
    """Jacobi symbol (a/n) for odd n > 0 (binary algorithm, no exponentiation)."""
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def is_element(x) -> bool:
    """True iff x is a non-identity element of the order-Q subgroup."""
    return type(x) is int and 1 < x < P and jacobi(x, P) == 1


def is_scalar(x) -> bool:
    return type(x) is int and 0 <= x < Q


class FixedBase:
    """Precomputed 4-bit window table for a fixed base: base^e costs ~512 multiplications
    instead of ~3000 for a generic pow(). Built once at import (about 0.2 s, ~2 MB)."""

    def __init__(self, base: int):
        self.rows = []
        b = base
        for _ in range(Q.bit_length() // 4 + 1):
            row = [1] * 16
            for d in range(1, 16):
                row[d] = row[d - 1] * b % P
            self.rows.append(row)
            b = row[15] * b % P  # base^(16^(i+1))

    def pow(self, e: int) -> int:
        e %= Q  # valid because the base has order Q
        acc, i = 1, 0
        while e:
            d = e & 15
            if d:
                acc = acc * self.rows[i][d] % P
            e >>= 4
            i += 1
        return acc


_G_TABLE = FixedBase(G)
_H_TABLE = FixedBase(H)


def gexp(e: int) -> int:
    return _G_TABLE.pow(e)


def hexp(e: int) -> int:
    return _H_TABLE.pow(e)


def to_hex(x: int) -> str:
    return format(x, "0%dx" % HEX_LEN)


def from_hex(s) -> int:
    """Strict canonical parse: exactly 512 lowercase hex chars (no 0x, sign, spaces)."""
    if not isinstance(s, str) or len(s) != HEX_LEN or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("expected %d lowercase hex characters" % HEX_LEN)
    return int(s, 16)


# Load-time sanity checks (explicit raises, not asserts, so they survive python -O).
if pow(G, Q, P) != 1 or pow(H, Q, P) != 1 or H in (0, 1, P - 1, G):
    raise RuntimeError("group parameters failed sanity checks")

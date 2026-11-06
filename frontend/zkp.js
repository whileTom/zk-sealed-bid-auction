// zkp.js - browser-side wallet and prover (port of wallet/wallet.py + zkauction/crypto).
//
// [CRYPTO] Everything here runs on the bidder's machine. The bid value and the commitment
// randomness never leave the browser until the reveal phase; the server only ever receives
// the Pedersen commitment and the zero-knowledge proofs.
//
// Must stay byte-for-byte compatible with the Python verifier:
//   - same group (RFC 3526 group 14, G = 2, H derived from the same seed),
//   - same Fiat-Shamir transcript encoding (type-tagged, length-prefixed, SHA-256),
//   - same wire format (512-char lowercase hex).
// tests/test_cross_lang.py runs this module under Node and verifies its proofs in Python.
//
// Uses only BigInt, TextEncoder and crypto.getRandomValues, so it works in browsers and Node.

const P_HEX =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF';

export const P = BigInt('0x' + P_HEX);
export const Q = (P - 1n) / 2n;
export const G = 2n;
export const BID_MIN = 1;
export const BID_MAX = 1000;
const E_MOD = 1n << 256n;
const HEX_LEN = 512;
const H_SEED = 'zk-auction/pedersen-h/v1';

// ------------------------------------------------------------------ SHA-256 (synchronous)
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** SHA-256 of a Uint8Array, returns a 32-byte Uint8Array. */
export function sha256(data) {
  const len = data.length;
  const padLen = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(data);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, Math.floor((len * 8) / 0x100000000));
  dv.setUint32(padLen - 4, (len * 8) >>> 0);
  const hs = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = hs;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    hs[0] = (hs[0] + a) | 0; hs[1] = (hs[1] + b) | 0; hs[2] = (hs[2] + c) | 0; hs[3] = (hs[3] + d) | 0;
    hs[4] = (hs[4] + e) | 0; hs[5] = (hs[5] + f) | 0; hs[6] = (hs[6] + g) | 0; hs[7] = (hs[7] + h) | 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  hs.forEach((x, i) => odv.setUint32(i * 4, x >>> 0));
  return out;
}

// ------------------------------------------------------------------ byte / bigint helpers
const utf8 = (s) => new TextEncoder().encode(s);

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

function intToBytes(x, len) {
  const hex = x.toString(16).padStart(len * 2, '0');
  if (hex.length > len * 2) throw new Error('integer too large');
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

const bytesToInt = (b) => BigInt('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('') || '0');
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** Non-negative remainder (JS % keeps the dividend's sign). */
const mod = (a, m) => ((a % m) + m) % m;

/** base^exp mod m with a 4-bit sliding window. */
export function modpow(base, exp, m = P) {
  if (exp < 0n) throw new Error('negative exponent');
  base = mod(base, m);
  const table = [1n];
  for (let i = 1; i < 16; i++) table.push((table[i - 1] * base) % m);
  let acc = 1n;
  for (const ch of exp.toString(16)) {
    acc = (acc * acc) % m; acc = (acc * acc) % m; acc = (acc * acc) % m; acc = (acc * acc) % m;
    const d = parseInt(ch, 16);
    if (d) acc = (acc * table[d]) % m;
  }
  return acc;
}

/** Modular inverse via extended Euclid. */
function modinv(a, m = P) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const qq = r0 / r1;
    [r0, r1] = [r1, r0 - qq * r1];
    [s0, s1] = [s1, s0 - qq * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

/** Uniform-enough scalar in [0, n): 288 random bytes reduced mod n (bias < 2^-250). */
const randBelow = (n) => bytesToInt(randomBytes(288)) % n;
const randBits256 = () => bytesToInt(randomBytes(32));

export const toHex = (x) => x.toString(16).padStart(HEX_LEN, '0');

export function fromHex(s) {
  if (typeof s !== 'string' || !/^[0-9a-f]{512}$/.test(s)) throw new Error('expected 512 lowercase hex chars');
  return BigInt('0x' + s);
}

// ------------------------------------------------------------------ group + transcript
/** Hash-to-group, identical to params.hash_to_group in Python. */
function hashToGroup(seedBytes) {
  const blocks = [];
  for (let j = 0; j < 9; j++) blocks.push(sha256(concat([seedBytes, u32be(j)])));
  const x = bytesToInt(concat(blocks).slice(0, 288)) % P;
  return (x * x) % P;
}

export const H = hashToGroup(utf8(H_SEED));

/** Fiat-Shamir hash: identical encoding to zkauction/crypto/transcript.py. */
export function hashInt(...parts) {
  const chunks = [];
  for (const part of parts) {
    let body;
    if (typeof part === 'bigint') {
      if (part < 0n || part >= 1n << 2048n) throw new Error('transcript int out of range');
      body = concat([new Uint8Array([0x49]), intToBytes(part, 256)]); // "I"
    } else if (typeof part === 'string') {
      body = concat([new Uint8Array([0x53]), utf8(part)]); // "S"
    } else {
      throw new Error('transcript parts must be bigint or string, got ' + typeof part);
    }
    chunks.push(u32be(body.length), body);
  }
  return bytesToInt(sha256(concat(chunks)));
}

export const commit = (v, r) => (modpow(G, v) * modpow(H, r)) % P;

export const addressOf = (pk) => '0x' + bytesToHex(sha256(intToBytes(pk, 256))).slice(0, 40);

// ------------------------------------------------------------------ range proof (prover)
export function coeffs(lo, hi) {
  const D = hi - lo;
  if (!Number.isInteger(D) || D < 1) throw new Error('empty range');
  if (D >= 2 ** 30) throw new Error('range too wide for 32-bit weights'); // JS bit ops are 32-bit
  const k = D.toString(2).length;
  const c = [];
  for (let i = 0; i < k - 1; i++) c.push(1 << i);
  c.push(D - ((1 << (k - 1)) - 1));
  return c;
}

function decompose(x, coef) {
  const k = coef.length;
  let top = 0, rest = x;
  if (x >= 1 << (k - 1)) { top = 1; rest = x - coef[k - 1]; }
  const bits = [];
  for (let i = 0; i < k - 1; i++) bits.push((rest >> i) & 1);
  bits.push(top);
  return bits;
}

/** [CRYPTO] Bit-decomposition range proof with CDS OR-proofs (see range_proof.py). */
function proveRange(v, r, auctionId, bidder, C, lo, hi) {
  const coef = coeffs(lo, hi);
  const k = coef.length;
  const x = v - lo;
  if (x < 0 || x > hi - lo) throw new Error('bid out of range');
  const bits = decompose(x, coef);

  const rs = [0n];
  for (let i = 1; i < k; i++) rs.push(randBelow(Q));
  let sum = 0n;
  for (let i = 1; i < k; i++) sum += BigInt(coef[i]) * rs[i];
  rs[0] = mod(r - sum, Q);
  const Cs = bits.map((b, i) => ((b ? G : 1n) * modpow(H, rs[i])) % P);
  const S = hashInt('zk-auction/v1/range-stmt', auctionId, bidder, C, BigInt(lo), BigInt(hi), ...Cs);

  const gInv = (P + 1n) / 2n;
  return Cs.map((Ci, i) => {
    const Y = [Ci, (Ci * gInv) % P];
    const b = bits[i], s = 1 - b;
    const e = [0n, 0n], z = [0n, 0n], A = [0n, 0n];
    // Simulated branch: A_s = H^z_s * Y_s^-e_s
    e[s] = randBits256();
    z[s] = randBelow(Q);
    A[s] = (modpow(H, z[s]) * modpow(modinv(Y[s]), e[s])) % P;
    // Real branch
    const w = randBelow(Q);
    A[b] = modpow(H, w);
    const ch = hashInt('zk-auction/v1/range-bit', S, BigInt(i), A[0], A[1]);
    e[b] = mod(ch - e[s], E_MOD);
    z[b] = mod(w + e[b] * rs[i], Q);
    return { C: toHex(Ci), A0: toHex(A[0]), A1: toHex(A[1]), e0: toHex(e[0]), e1: toHex(e[1]), z0: toHex(z[0]), z1: toHex(z[1]) };
  });
}

/** Schnorr signature (proof of knowledge of sk) over a statement. */
function sign(sk, pk, ...msg) {
  const k = randBelow(Q);
  const R = modpow(G, k);
  const e = hashInt('zk-auction/v1/sig', pk, R, ...msg) % Q;
  return { R: toHex(R), s: toHex(mod(k + e * sk, Q)) };
}

/** Auction-scoped nullifier N = H_a^sk with a Chaum-Pedersen proof log_G(pk) == log_Ha(N)
 *  (see zkauction/crypto/nullifier.py): one key yields exactly one valid N per auction. */
function proveNullifier(sk, pk, auctionId, bidder, C) {
  const Ha = hashToGroup(utf8('zk-auction/v1/nullifier/' + auctionId));
  const N = modpow(Ha, sk);
  const k = randBelow(Q);
  const R1 = modpow(G, k), R2 = modpow(Ha, k);
  const e = hashInt('zk-auction/v1/nullifier-dleq', auctionId, bidder, C, pk, N, R1, R2) % Q;
  return { N: toHex(N), R1: toHex(R1), R2: toHex(R2), s: toHex(mod(k + e * sk, Q)) };
}

// ------------------------------------------------------------------ public wallet API
/** Cross-check the server's parameters against our hard-coded / re-derived ones. */
export async function init() {
  if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
    throw new Error('crypto.getRandomValues is unavailable in this browser');
  }
  const res = await fetch('/params');
  if (!res.ok) throw new Error('GET /params failed: HTTP ' + res.status);
  const params = await res.json();
  if (params.p !== toHex(P) || params.g !== toHex(G) || params.h !== toHex(H)) {
    throw new Error('server group parameters do not match the client; refusing to build proofs');
  }
  if (params.bid_min !== BID_MIN || params.bid_max !== BID_MAX) {
    throw new Error('server bid range does not match the client');
  }
  return params;
}

/** [SIMULATED] wallet key generation; production would use a real wallet / hardware key. */
export function keygen() {
  const sk = 1n + randBelow(Q - 1n);
  const pk = modpow(G, sk);
  return { sk: toHex(sk), pk: toHex(pk), address: addressOf(pk) };
}

function checkValue(value) {
  const v = Number(value);
  if (!Number.isInteger(v) || v < BID_MIN || v > BID_MAX) throw new Error('bid must be an integer in [' + BID_MIN + ', ' + BID_MAX + ']');
  return v;
}

/** Build a sealed bid. Returns {request: POST body, secret: keep locally until reveal}. */
export async function makeBid({ auctionId, sk, value }) {
  const v = checkValue(value);
  const aid = String(auctionId);
  const skI = fromHex(sk);
  const pk = modpow(G, skI);
  const bidder = addressOf(pk);
  const r = randBelow(Q);
  const C = commit(BigInt(v), r);
  const bits = proveRange(v, r, aid, bidder, C, BID_MIN, BID_MAX);
  const auth = sign(skI, pk, 'bid', aid, bidder, C);
  const nullifier = proveNullifier(skI, pk, aid, bidder, C);
  return {
    request: { bidder, commitment: toHex(C), proof: { range: { bits }, auth: { pubkey: toHex(pk), R: auth.R, s: auth.s }, nullifier } },
    secret: { value: v, randomness: toHex(r), commitment: toHex(C) },
  };
}

/** Build the reveal body: opening (value, randomness) + signature over the reveal statement. */
export async function makeReveal({ auctionId, sk, value, randomness, commitment }) {
  const v = checkValue(value);
  const aid = String(auctionId);
  const skI = fromHex(sk);
  const pk = modpow(G, skI);
  const bidder = addressOf(pk);
  const C = fromHex(commitment);
  const r = fromHex(randomness);
  const auth = sign(skI, pk, 'reveal', aid, bidder, C, BigInt(v), r);
  return { bidder, value: v, randomness, proof: { commitment, auth } };
}

/** Anyone can check a published opening: G^value * H^randomness == commitment. */
export function verifyOpening(commitmentHex, value, randomnessHex) {
  // Same strictness as Python verify_opening: a real integer (no "1", true, [1], "0x1").
  if (typeof value !== 'number' || !Number.isInteger(value)) return false;
  const v = value;
  if (v < BID_MIN || v > BID_MAX) return false;
  const r = fromHex(randomnessHex);
  if (r >= Q) return false;
  return commit(BigInt(v), r) === fromHex(commitmentHex);
}

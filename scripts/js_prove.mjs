// Runs the browser prover (frontend/zkp.js) under Node and prints JSON for the Python tests.
// Usage: node scripts/js_prove.mjs <auction_id> <value>
import { createHash } from 'node:crypto';
import * as zkp from '../frontend/zkp.js';

const [auctionId = 'auc-js', value = '640'] = process.argv.slice(2);

// Self-test the pure-JS SHA-256 against Node's implementation on varied lengths.
for (const n of [0, 1, 3, 55, 56, 63, 64, 65, 300, 1000]) {
  const data = new Uint8Array(n).map((_, i) => (i * 31 + n) & 255);
  const ours = Buffer.from(zkp.sha256(data)).toString('hex');
  const ref = createHash('sha256').update(data).digest('hex');
  if (ours !== ref) throw new Error('sha256 mismatch at length ' + n);
}

const key = zkp.keygen();
const t0 = Date.now();
const { request, secret } = await zkp.makeBid({ auctionId, sk: key.sk, value: Number(value) });
const proveMs = Date.now() - t0;
const reveal = await zkp.makeReveal({ auctionId, sk: key.sk, ...secret });

console.log(JSON.stringify({
  h: zkp.toHex(zkp.H),
  vector: zkp.hashInt('abc', 5n, '').toString(16),
  key, request, secret, reveal, proveMs,
  opening_ok: zkp.verifyOpening(secret.commitment, secret.value, secret.randomness),
}));

// app.js - browser UI for the ZK sealed-bid auction prototype.
//
// SECURITY: every server-provided string is rendered through el()/textContent.
// innerHTML is never used. An XSS hole here would let a malicious item name
// read the secret bid openings (value + randomness) kept in localStorage.
//
// Data flow:
//   - zkp.js does all cryptography (keygen, commitment + proof, reveal, verify).
//   - The FastAPI server is same-origin, so all fetches use relative paths.
//   - Phase ("bidding" | "reveal" | "closed") is taken ONLY from the server.

// ---------------------------------------------------------------------------
// Constants and state
// ---------------------------------------------------------------------------

const WALLETS_KEY = 'zk-auction:wallets';
const RECEIPTS_KEY = 'zk-auction:receipts';
const ACTIVE_KEY = 'zk-auction:active';
const POLL_MS = 3000;
const TOAST_MS = 7000;
const PHASES = ['bidding', 'reveal', 'closed'];
const RESERVED_NAMES = ['__proto__', 'constructor', 'prototype'];

/** zkp module namespace, loaded dynamically so a broken zkp.js still lets the list render. */
let zkp = null;

const state = {
  zkReady: false,      // true once zkp.init() resolved
  params: null,        // params returned by zkp.init()
  activeName: null,    // name of the active demo wallet
  auctions: [],        // last GET /auction?status=all
  listError: null,
  selectedId: null,    // selected auction id (string)
  detail: null,        // last GET /auction/{id}
  detailError: null,
  bids: null,          // last GET /auction/{id}/bids (reveal/closed only)
  bidsError: null,
  busy: false,         // a proof / request is in flight
  busyText: '',
  bidDraft: '',        // keeps the typed bid if the form is rebuilt
  flash: {},           // receiptKey -> success message shown after sealing
  verify: {},          // "auctionId|bidder" -> "valid" | "invalid" | "error"
  polling: false,
  renderKeys: {},      // last render keys of panels that hold user input
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Create a DOM element safely.
 * props: className, text (textContent), title, type, disabled, value, etc.
 * children: strings (become text nodes) or nodes; null/false are skipped.
 */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === 'text') node.textContent = String(v);
    else if (k === 'className') node.className = v;
    else if (k === 'onclick') node.addEventListener('click', v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k in node) node[k] = v;
    else node.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** Remove all children of a node. */
function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** First 16 hex chars of a hex string (without 0x prefix). */
function hexPrefix(hex) {
  const s = String(hex || '').toLowerCase().replace(/^0x/, '');
  return s.slice(0, 16);
}

function sameHex(a, b) {
  return String(a || '').toLowerCase().replace(/^0x/, '') === String(b || '').toLowerCase().replace(/^0x/, '');
}

function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

/** Human countdown text for a deadline ISO string. */
function countdownText(iso) {
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '-';
  let s = Math.round((t - Date.now()) / 1000);
  if (s <= 0) return 'deadline passed';
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  const pad = (n) => String(n).padStart(2, '0');
  return (h > 0 ? h + 'h ' + pad(m) + 'm ' : m + 'm ') + pad(s) + 's left';
}

/** A span that the 1 s ticker keeps updated. */
function countdownEl(iso, prefix) {
  const span = el('span', { className: 'countdown', dataset: { deadline: iso || '', prefix: prefix || '' } });
  span.textContent = (prefix || '') + countdownText(iso);
  return span;
}

function tickCountdowns() {
  for (const span of document.querySelectorAll('.countdown')) {
    span.textContent = (span.dataset.prefix || '') + countdownText(span.dataset.deadline);
  }
}

/** Phase badge; class is whitelisted so the server cannot inject arbitrary classes. */
function phaseBadge(phase) {
  const cls = PHASES.includes(phase) ? phase : 'unknown';
  return el('span', { className: 'badge badge-' + cls, text: String(phase || 'unknown') });
}

// ---------------------------------------------------------------------------
// Toasts and banner
// ---------------------------------------------------------------------------

function toast(message, kind = 'info') {
  const node = el('div', { className: 'toast toast-' + kind, role: kind === 'error' ? 'alert' : 'status' }, String(message));
  node.addEventListener('click', () => node.remove());
  $('toasts').append(node);
  setTimeout(() => node.remove(), kind === 'error' ? TOAST_MS * 2 : TOAST_MS);
}

function showBanner(message) {
  const b = $('zk-banner');
  b.textContent = message;
  b.hidden = false;
}

// ---------------------------------------------------------------------------
// localStorage: wallets and receipts
// ---------------------------------------------------------------------------

function loadObj(key) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return {};
    const v = JSON.parse(raw);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

function saveObj(key, obj) {
  try {
    localStorage.setItem(key, JSON.stringify(obj));
  } catch (e) {
    toast('Could not write to localStorage: ' + e.message, 'error');
  }
}

const getWallets = () => loadObj(WALLETS_KEY);

function activeWallet() {
  const wallets = getWallets();
  if (state.activeName && Object.hasOwn(wallets, state.activeName)) return wallets[state.activeName];
  return null;
}

/** Receipt map key, exactly auctionId + "|" + address. */
const receiptKey = (auctionId, address) => String(auctionId) + '|' + address;

function getReceipt(key) {
  const all = loadObj(RECEIPTS_KEY);
  return Object.hasOwn(all, key) ? all[key] : null;
}

function putReceipt(key, receipt) {
  const all = loadObj(RECEIPTS_KEY);
  all[key] = receipt;
  saveObj(RECEIPTS_KEY, all);
}

function deleteReceipt(key) {
  const all = loadObj(RECEIPTS_KEY);
  delete all[key];
  saveObj(RECEIPTS_KEY, all);
}

/** Display label for a bidder address; marks local demo identities. */
function bidderLabel(addr) {
  const a = String(addr || '');
  const short = a.length > 18 ? a.slice(0, 10) + '...' + a.slice(-4) : a;
  const wallets = getWallets();
  for (const [name, w] of Object.entries(wallets)) {
    if (w && sameHex(w.address, a)) return name + ' (' + short + ')';
  }
  return short;
}

function bidderEl(addr) {
  return el('span', { className: 'addr', title: String(addr || ''), text: bidderLabel(addr) });
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

class ApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Turn any FastAPI error body into a readable message. */
function errorMessage(data, res) {
  const d = data && data.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) {
    return d.map((x) => (x && x.msg ? (Array.isArray(x.loc) ? x.loc.join('.') + ': ' : '') + x.msg : String(x))).join('; ');
  }
  if (d && typeof d === 'object') {
    return (d.code ? d.code + ': ' : '') + (d.message || JSON.stringify(d));
  }
  return 'HTTP ' + res.status + (res.statusText ? ' ' + res.statusText : '');
}

async function api(method, path, body) {
  const opts = { method, headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new ApiError('Network error: ' + e.message, 0, null);
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = null; }
  }
  if (!res.ok) {
    const code = data && data.detail && typeof data.detail === 'object' && !Array.isArray(data.detail) ? data.detail.code : null;
    throw new ApiError(errorMessage(data, res), res.status, code);
  }
  return data;
}

const auctionPath = (id) => '/auction/' + encodeURIComponent(String(id));

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

async function refresh() {
  if (state.polling) return;
  state.polling = true;
  try {
    try {
      const list = await api('GET', '/auction?status=all');
      state.auctions = Array.isArray(list) ? list : [];
      state.listError = null;
    } catch (e) {
      state.listError = 'Could not load auctions: ' + e.message;
    }
    if (state.selectedId !== null) await refreshDetail();
  } finally {
    state.polling = false;
  }
  render();
}

async function refreshDetail() {
  const id = state.selectedId;
  if (id === null) return;
  try {
    const d = await api('GET', auctionPath(id));
    if (state.selectedId !== id) return; // selection changed meanwhile
    state.detail = d;
    state.detailError = null;
    if (d.phase !== 'bidding') {
      try {
        const b = await api('GET', auctionPath(id) + '/bids');
        if (state.selectedId !== id) return;
        state.bids = b;
        state.bidsError = null;
      } catch (e) {
        state.bidsError = e.status === 409
          ? 'Bids are not available yet (server says the bid deadline has not passed).'
          : 'Could not load bids: ' + e.message;
      }
    } else {
      state.bids = null;
      state.bidsError = null;
    }
  } catch (e) {
    if (state.selectedId !== id) return;
    if (e.status === 404) {
      toast('Auction ' + id + ' no longer exists.', 'error');
      selectAuction(null);
    } else {
      state.detailError = 'Could not load auction: ' + e.message;
    }
  }
}

function selectAuction(id) {
  state.selectedId = id === null ? null : String(id);
  state.detail = null;
  state.detailError = null;
  state.bids = null;
  state.bidsError = null;
  state.bidDraft = '';
  state.renderKeys = {};
  render();
  if (state.selectedId !== null) refreshDetail().then(render);
}

// ---------------------------------------------------------------------------
// Rendering: identity bar
// ---------------------------------------------------------------------------

function renderIdentity() {
  const wallets = getWallets();
  const names = Object.keys(wallets).sort();
  if (state.activeName && !Object.hasOwn(wallets, state.activeName)) state.activeName = null;

  const select = $('wallet-select');
  const key = names.join('\n') + '|' + state.activeName;
  if (state.renderKeys.identity !== key) {
    state.renderKeys.identity = key;
    clear(select);
    select.append(el('option', { value: '', text: names.length ? '(choose identity)' : '(no identities yet)' }));
    for (const n of names) select.append(el('option', { value: n, text: n }));
    select.value = state.activeName || '';
  }

  const w = activeWallet();
  $('wallet-address').textContent = w ? String(w.address) : '(none selected)';
  $('wallet-create').disabled = !state.zkReady;
}

// ---------------------------------------------------------------------------
// Rendering: auction list
// ---------------------------------------------------------------------------

function renderList() {
  const errNode = $('list-error');
  errNode.hidden = !state.listError;
  errNode.textContent = state.listError || '';

  const groups = { bidding: [], reveal: [], closed: [] };
  for (const a of state.auctions) {
    if (a && Object.hasOwn(groups, a.phase)) groups[a.phase].push(a);
  }
  const ts = (iso) => new Date(iso).getTime() || 0;
  groups.bidding.sort((a, b) => ts(a.bid_deadline) - ts(b.bid_deadline));
  groups.reveal.sort((a, b) => ts(a.reveal_deadline) - ts(b.reveal_deadline));
  groups.closed.sort((a, b) => ts(b.reveal_deadline) - ts(a.reveal_deadline));

  for (const phase of PHASES) {
    const box = $('list-' + phase);
    clear(box);
    if (!groups[phase].length) {
      box.append(el('p', { className: 'muted small', text: 'None' }));
      continue;
    }
    for (const a of groups[phase]) box.append(auctionRow(a));
  }
}

function auctionRow(a) {
  const id = String(a.auction_id);
  let when;
  if (a.phase === 'bidding') when = countdownEl(a.bid_deadline, 'Bidding: ');
  else if (a.phase === 'reveal') when = countdownEl(a.reveal_deadline, 'Reveal: ');
  else when = el('span', { text: 'Ended ' + fmtTime(a.reveal_deadline) });

  return el('div', { className: 'auction-row' + (id === state.selectedId ? ' selected' : '') },
    el('div', { className: 'row-main' },
      el('strong', { text: a.item_name }),
      a.description ? el('p', { className: 'muted small desc', text: a.description }) : null,
      el('div', { className: 'row-meta small' },
        phaseBadge(a.phase),
        when,
        el('span', { text: 'sealed ' + (a.sealed_count ?? 0) + ' / revealed ' + (a.revealed_count ?? 0) }),
      ),
    ),
    el('button', { type: 'button', className: 'secondary', text: 'Open', onclick: () => selectAuction(id) }),
  );
}

// ---------------------------------------------------------------------------
// Rendering: detail panel
// ---------------------------------------------------------------------------

function renderDetail() {
  const has = state.selectedId !== null;
  $('detail-empty').hidden = has;
  $('detail-body').hidden = !has;
  if (!has) return;

  const d = state.detail;
  const header = $('d-header');
  clear(header);
  if (state.detailError) header.append(el('p', { className: 'error small', text: state.detailError }));
  if (!d) {
    header.append(el('p', { className: 'muted', text: 'Loading auction ' + state.selectedId + '...' }));
    for (const id of ['d-sealed', 'd-action', 'd-receipt', 'd-results']) clear($(id));
    state.renderKeys = { identity: state.renderKeys.identity };
    return;
  }

  reconcileReceipt(d);

  header.append(
    el('div', { className: 'detail-title' }, el('h3', { text: d.item_name }), phaseBadge(d.phase)),
    d.description ? el('p', { className: 'desc', text: d.description }) : null,
    el('dl', { className: 'facts small' },
      el('dt', { text: 'Auction id' }), el('dd', { text: d.auction_id }),
      el('dt', { text: 'Bid deadline' }),
      el('dd', {}, fmtTime(d.bid_deadline), ' ', d.phase === 'bidding' ? countdownEl(d.bid_deadline, '(') : null, d.phase === 'bidding' ? ')' : null),
      el('dt', { text: 'Reveal deadline' }),
      el('dd', {}, fmtTime(d.reveal_deadline), ' ', d.phase === 'reveal' ? countdownEl(d.reveal_deadline, '(') : null, d.phase === 'reveal' ? ')' : null),
      el('dt', { text: 'Bid range' }),
      el('dd', { text: Array.isArray(d.bid_range) ? d.bid_range[0] + ' - ' + d.bid_range[1] : '-' }),
      el('dt', { text: 'Counts' }),
      el('dd', { text: 'sealed ' + (d.sealed_count ?? 0) + ' / revealed ' + (d.revealed_count ?? 0) }),
    ),
  );

  renderSealed(d);
  renderAction(d);
  renderReceipt(d);
  renderResults(d);
}

/** Sealed commitments: bidder, commitment prefix, time. Never amounts. */
function renderSealed(d) {
  const box = $('d-sealed');
  clear(box);
  const sealed = Array.isArray(d.sealed_bids) ? d.sealed_bids : [];
  if (!sealed.length) {
    box.append(el('p', { className: 'muted small', text: 'No sealed bids yet.' }));
    return;
  }
  const tbody = el('tbody');
  for (const s of sealed) {
    tbody.append(el('tr', {},
      el('td', {}, bidderEl(s.bidder)),
      el('td', {}, el('code', { text: hexPrefix(s.commitment) + '...' })),
      el('td', { text: fmtTime(s.committed_at) }),
    ));
  }
  box.append(el('div', { className: 'table-wrap' },
    el('table', {},
      el('thead', {}, el('tr', {}, el('th', { text: 'Bidder' }), el('th', { text: 'Commitment' }), el('th', { text: 'Committed at' }))),
      tbody,
    )));
}

/**
 * Self-heal local receipts against server state:
 *  - "pending" receipt whose commitment is on the server -> "confirmed"
 *  - "confirmed" receipt that appears in revealed bids -> "revealed"
 */
function reconcileReceipt(d) {
  const w = activeWallet();
  if (!w || state.busy) return;
  const key = receiptKey(d.auction_id, w.address);
  const r = getReceipt(key);
  if (!r) return;
  if (r.status === 'pending' && Array.isArray(d.sealed_bids)) {
    if (d.sealed_bids.some((s) => sameHex(s.bidder, w.address) && sameHex(s.commitment, r.commitment))) {
      putReceipt(key, { ...r, status: 'confirmed' });
    } else if (!d.sealed_bids.some((s) => sameHex(s.bidder, w.address))) {
      // No submit is in flight (state.busy is false) and the server has no bid from this address:
      // the earlier request never arrived. Drop the stale receipt so the identity is not locked out.
      deleteReceipt(key);
      state.flash[key] = 'Your earlier bid never reached the server' +
        (d.phase === 'bidding' ? '; you can bid again.' : ' before the deadline, so it does not count.');
    }
  } else if (r.status === 'confirmed' && state.bids && Array.isArray(state.bids.revealed)) {
    if (state.bids.revealed.some((x) => sameHex(x.bidder, w.address) && sameHex(x.commitment, r.commitment))) {
      putReceipt(key, { ...r, status: 'revealed' });
    }
  }
}

/** Bid / reveal controls. Rebuilt only when something relevant changes so typed input survives polling. */
function renderAction(d) {
  const box = $('d-action');
  const w = activeWallet();
  const key = w ? receiptKey(d.auction_id, w.address) : null;
  const receipt = key ? getReceipt(key) : null;
  const renderKey = JSON.stringify([d.auction_id, d.phase, w && w.address, receipt && receipt.status,
    state.busy, state.busyText, state.zkReady, key && state.flash[key]]);
  if (state.renderKeys.action === renderKey) return;
  state.renderKeys.action = renderKey;
  clear(box);

  if (!w) {
    box.append(el('p', { className: 'muted', text: 'Create or select an identity to bid or reveal.' }));
    return;
  }
  if (!state.zkReady) {
    box.append(el('p', { className: 'error small', text: 'ZK module unavailable - bidding and revealing are disabled.' }));
  }

  if (d.phase === 'bidding') {
    if (receipt) {
      box.append(el('p', { className: 'ok', text: 'You already bid in this auction as ' + state.activeName + ' (status: ' + receipt.status + ').' }));
      if (state.flash[key]) box.append(el('p', { className: 'ok small', text: state.flash[key] }));
      return;
    }
    const range = bidRange(d);
    const input = el('input', {
      type: 'number', min: String(range[0]), max: String(range[1]), step: '1',
      value: state.bidDraft, placeholder: range[0] + '-' + range[1], disabled: state.busy || !state.zkReady,
    });
    input.addEventListener('input', () => { state.bidDraft = input.value; });
    const form = el('form', { className: 'inline-form' },
      el('label', { className: 'field' }, el('span', { text: 'Bid amount (' + range[0] + '-' + range[1] + ')' }), input),
      el('button', { type: 'submit', text: 'Seal and submit bid', disabled: state.busy || !state.zkReady }),
    );
    form.addEventListener('submit', (ev) => { ev.preventDefault(); submitBid(d, input.value); });
    box.append(form);
    if (state.busy) box.append(el('p', { className: 'busy', text: state.busyText }));
    box.append(el('p', { className: 'muted small', text: 'Only a Pedersen commitment and a range proof leave this browser. The amount stays secret until you reveal.' }));
    return;
  }

  if (d.phase === 'reveal') {
    const canReveal = !!receipt && receipt.status === 'confirmed' && state.zkReady && !state.busy;
    let hint;
    if (!receipt) hint = 'No bid receipt for ' + state.activeName + ' in this auction.';
    else if (receipt.status === 'revealed') hint = 'Your bid has been revealed.';
    else if (receipt.status !== 'confirmed') hint = 'Your receipt is "' + receipt.status + '" (not confirmed by the server), so it cannot be revealed.';
    else hint = 'Reveal before the reveal deadline or your bid will not count.';
    box.append(
      el('button', { type: 'button', text: 'Reveal my bid', disabled: !canReveal, onclick: () => submitReveal(d) }),
      el('p', { className: receipt && receipt.status === 'revealed' ? 'ok small' : 'muted small', text: hint }),
    );
    if (state.busy) box.append(el('p', { className: 'busy', text: state.busyText }));
    return;
  }

  // closed
  let msg = 'Auction closed.';
  if (receipt && receipt.status === 'revealed') msg += ' Your bid was revealed.';
  else if (receipt) msg += ' Your bid was not revealed in time and does not count.';
  box.append(el('p', { className: 'muted', text: msg }));
}

/** Bid range: prefer the auction's bid_range, then zkp params, else 1-1000. */
function bidRange(d) {
  if (Array.isArray(d.bid_range) && d.bid_range.length === 2) return [Number(d.bid_range[0]), Number(d.bid_range[1])];
  const p = state.params || {};
  const lo = Number(p.bid_min), hi = Number(p.bid_max);
  return Number.isFinite(lo) && Number.isFinite(hi) ? [lo, hi] : [1, 1000];
}

/** "Export receipt" details with the receipt JSON of the active identity. */
function renderReceipt(d) {
  const box = $('d-receipt');
  const w = activeWallet();
  const receipt = w ? getReceipt(receiptKey(d.auction_id, w.address)) : null;
  const json = receipt ? JSON.stringify(receipt, null, 2) : '';
  const renderKey = JSON.stringify([d.auction_id, w && w.address, json]);
  if (state.renderKeys.receipt === renderKey) return;
  state.renderKeys.receipt = renderKey;

  const prev = box.querySelector('details');
  const wasOpen = !!(prev && prev.open);
  clear(box);
  if (!w) return;
  const details = el('details', { className: 'receipt' },
    el('summary', { text: 'Export receipt' }),
    el('p', { className: 'warn small', text: 'Contains your secret opening (value + randomness). Anyone who sees it learns your bid before the deadline; revealing also needs your identity key, so keep both private.' }),
    el('textarea', { readOnly: true, rows: 8, value: json || 'No receipt for this identity in this auction.' }),
  );
  details.open = wasOpen;
  box.append(details);
}

/** Results (reveal/closed): leader/winner box, revealed table with Verify, unrevealed list. */
function renderResults(d) {
  const box = $('d-results');
  clear(box);
  if (d.phase === 'bidding') return;

  box.append(el('h3', { text: d.phase === 'closed' ? 'Final results' : 'Revealed bids' }));
  if (state.bidsError) box.append(el('p', { className: 'error small', text: state.bidsError }));
  const b = state.bids;
  if (!b) {
    if (!state.bidsError) box.append(el('p', { className: 'muted small', text: 'Loading bids...' }));
    return;
  }

  // Leader / winner highlight
  if (b.winner) {
    box.append(el('div', { className: 'leader winner' }, 'Winner: ', bidderEl(b.winner.bidder), ' with ' + b.winner.value));
  } else if (b.current_leader) {
    box.append(el('div', { className: 'leader' }, 'Current leader: ', bidderEl(b.current_leader.bidder), ' with ' + b.current_leader.value));
  } else {
    box.append(el('div', { className: 'leader none', text: b.final ? 'No winner (no valid reveals).' : 'No bids revealed yet.' }));
  }

  // Revealed table
  const revealed = Array.isArray(b.revealed) ? b.revealed : [];
  if (revealed.length) {
    const tbody = el('tbody');
    for (const r of revealed) {
      const vkey = String(d.auction_id) + '|' + r.bidder;
      const result = state.verify[vkey];
      const resultEl = el('span', {
        className: result === 'valid' ? 'ok' : result ? 'error' : 'muted',
        text: result === 'valid' ? 'valid opening' : result === 'invalid' ? 'INVALID' : result === 'error' ? 'verify error' : '',
      });
      const btn = el('button', {
        type: 'button', className: 'secondary small-btn', text: 'Verify', disabled: !state.zkReady,
        onclick: () => verifyRow(vkey, r),
      });
      tbody.append(el('tr', {},
        el('td', {}, bidderEl(r.bidder)),
        el('td', { className: 'num', text: r.value }),
        el('td', {}, el('code', { text: hexPrefix(r.commitment) + '...' })),
        el('td', { text: fmtTime(r.revealed_at) }),
        el('td', { className: 'verify-cell' }, btn, ' ', resultEl),
      ));
    }
    box.append(el('div', { className: 'table-wrap' },
      el('table', {},
        el('thead', {}, el('tr', {},
          el('th', { text: 'Bidder' }), el('th', { text: 'Value' }), el('th', { text: 'Commitment' }),
          el('th', { text: 'Revealed at' }), el('th', { text: 'Check' }))),
        tbody,
      )));
  } else {
    box.append(el('p', { className: 'muted small', text: 'No revealed bids.' }));
  }

  // Unrevealed bidders
  const unrevealed = Array.isArray(b.unrevealed) ? b.unrevealed : [];
  box.append(el('h4', { text: 'Not yet revealed (' + unrevealed.length + ')' }));
  if (unrevealed.length) {
    box.append(el('ul', { className: 'plain' }, unrevealed.map((u) => el('li', {}, bidderEl(u)))));
  } else {
    box.append(el('p', { className: 'muted small', text: 'None' }));
  }
}

function render() {
  renderIdentity();
  renderList();
  renderDetail();
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function setBusy(busy, text = '') {
  state.busy = busy;
  state.busyText = text;
  if (state.detail) renderAction(state.detail);
}

async function submitBid(d, rawValue) {
  const w = activeWallet();
  if (!w || state.busy || !state.zkReady) return;
  const [lo, hi] = bidRange(d);
  const value = Number(rawValue);
  if (!Number.isInteger(value) || value < lo || value > hi) {
    toast('Bid must be a whole number between ' + lo + ' and ' + hi + '.', 'error');
    return;
  }
  const auctionId = d.auction_id;
  const key = receiptKey(auctionId, w.address);
  if (getReceipt(key)) {
    toast('You already bid in this auction with this identity.', 'error');
    return;
  }

  let saved = false;
  let mine = null; // this tab's commitment; every later receipt write is tied to it
  const isMine = () => { const cur = getReceipt(key); return !!(cur && mine && cur.commitment === mine); };
  setBusy(true, 'Generating zero-knowledge proof...');
  await sleep(30); // let the browser paint the busy message before heavy CPU work
  try {
    const { request, secret } = await zkp.makeBid({ auctionId, sk: w.sk, value });

    // Another tab may have bid with this identity while we were proving: never overwrite it.
    if (getReceipt(key)) {
      toast('This identity already bid in this auction (another tab).', 'error');
      return;
    }
    mine = secret.commitment;
    // Save the opening BEFORE posting so a crash mid-request cannot lose it.
    putReceipt(key, {
      auction_id: auctionId,
      address: w.address,
      value: secret.value,
      randomness: secret.randomness,
      commitment: secret.commitment,
      status: 'pending',
    });
    saved = true;

    setBusy(true, 'Submitting sealed bid...');
    await api('POST', auctionPath(auctionId) + '/bid', request);

    if (isMine()) putReceipt(key, { ...getReceipt(key), status: 'confirmed' });
    state.bidDraft = '';
    state.flash[key] = 'Bid sealed. Commitment: ' + hexPrefix(secret.commitment) + '...';
    toast(state.flash[key], 'success');
  } catch (e) {
    // Only discard the opening when the server definitely rejected the bid. On a network error,
    // a 5xx, or DUPLICATE_* the server may already hold this commitment; keep the receipt
    // "pending" so reconcileReceipt() can confirm it (or clean it up if it never arrived).
    const maybeStored = e.status === 0 || e.status >= 500 ||
      e.code === 'DUPLICATE_BID' || e.code === 'DUPLICATE_COMMITMENT';
    if (saved && !maybeStored && isMine()) deleteReceipt(key);
    toast('Bid failed: ' + e.message + (saved && maybeStored ? ' (receipt kept until the server state is known)' : ''), 'error');
  } finally {
    setBusy(false);
  }
  await refreshDetail();
  render();
}

async function submitReveal(d) {
  const w = activeWallet();
  if (!w || state.busy || !state.zkReady) return;
  const auctionId = d.auction_id;
  const key = receiptKey(auctionId, w.address);
  const r = getReceipt(key);
  if (!r || r.status !== 'confirmed') {
    toast('No confirmed bid receipt to reveal.', 'error');
    return;
  }

  // Local sanity check: the stored opening must match the stored commitment.
  try {
    if (!zkp.verifyOpening(r.commitment, r.value, r.randomness)) {
      toast('Local receipt does not open its commitment; refusing to reveal.', 'error');
      return;
    }
  } catch (e) {
    toast('Could not check receipt locally: ' + e.message, 'error');
    return;
  }

  setBusy(true, 'Building reveal...');
  await sleep(30);
  try {
    const body = await zkp.makeReveal({
      auctionId, sk: w.sk, value: r.value, randomness: r.randomness, commitment: r.commitment,
    });
    const res = await api('POST', auctionPath(auctionId) + '/reveal', body);
    putReceipt(key, { ...getReceipt(key), status: 'revealed' });
    const leader = res && res.current_leader
      ? ' Current leader: ' + bidderLabel(res.current_leader.bidder) + ' with ' + res.current_leader.value + '.'
      : '';
    toast('Revealed bid of ' + (res ? res.value : r.value) + '.' + leader, 'success');
  } catch (e) {
    toast('Reveal failed: ' + e.message, 'error');
  } finally {
    setBusy(false);
  }
  await refreshDetail();
  render();
}

function verifyRow(vkey, r) {
  try {
    state.verify[vkey] = zkp.verifyOpening(r.commitment, r.value, r.randomness) ? 'valid' : 'invalid';
  } catch (e) {
    state.verify[vkey] = 'error';
    toast('Verify failed: ' + e.message, 'error');
  }
  if (state.detail) renderResults(state.detail);
}

function createIdentity(ev) {
  ev.preventDefault();
  if (!state.zkReady) return;
  const input = $('wallet-name');
  const name = input.value.trim();
  if (!name || name.length > 32) {
    toast('Name must be 1-32 characters.', 'error');
    return;
  }
  const wallets = getWallets();
  if (RESERVED_NAMES.includes(name) || Object.hasOwn(wallets, name)) {
    toast('Identity "' + name + '" already exists or is not allowed.', 'error');
    return;
  }
  try {
    const kp = zkp.keygen();
    wallets[name] = { sk: kp.sk, pk: kp.pk, address: kp.address };
    saveObj(WALLETS_KEY, wallets);
  } catch (e) {
    toast('Key generation failed: ' + e.message, 'error');
    return;
  }
  input.value = '';
  setActive(name);
  toast('Created identity ' + name + '.', 'success');
}

function setActive(name) {
  state.activeName = name || null;
  try {
    if (state.activeName) localStorage.setItem(ACTIVE_KEY, state.activeName);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch { /* ignore */ }
  state.bidDraft = '';
  state.renderKeys = {};
  render();
}

async function createAuction(ev) {
  ev.preventDefault();
  const item = $('c-item').value.trim();
  const description = $('c-desc').value.trim();
  const bidSecs = Number($('c-bid-secs').value);
  const revealSecs = Number($('c-reveal-secs').value);
  if (!item) { toast('Item name is required.', 'error'); return; }
  if (!Number.isFinite(bidSecs) || bidSecs < 15) { toast('Bidding must last at least 15 seconds.', 'error'); return; }
  if (!Number.isFinite(revealSecs) || revealSecs < 15) { toast('Reveal window must be at least 15 seconds.', 'error'); return; }

  // Absolute UTC instants computed from "now"; never datetime-local (timezone pitfalls).
  const bidMs = Date.now() + Math.round(bidSecs) * 1000;
  const body = {
    item_name: item,
    description,
    bid_deadline: new Date(bidMs).toISOString(),
    reveal_deadline: new Date(bidMs + Math.round(revealSecs) * 1000).toISOString(),
  };
  const btn = $('c-submit');
  btn.disabled = true;
  try {
    const created = await api('POST', '/auction', body);
    toast('Created auction "' + created.item_name + '".', 'success');
    $('c-item').value = '';
    $('c-desc').value = '';
    selectAuction(created.auction_id);
    refresh();
  } catch (e) {
    toast('Create failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function initZk() {
  try {
    zkp = await import('./zkp.js');
  } catch (e) {
    showBanner('Could not load zkp.js: ' + e.message + '. Identity creation, bidding, revealing and verification are disabled.');
    return;
  }
  try {
    state.params = await zkp.init();
    state.zkReady = true;
  } catch (e) {
    showBanner('ZK module failed to initialise: ' + e.message + '. Identity creation, bidding, revealing and verification are disabled.');
  }
}

async function main() {
  // Restore active identity (if it still exists).
  try {
    const saved = localStorage.getItem(ACTIVE_KEY);
    if (saved && Object.hasOwn(getWallets(), saved)) state.activeName = saved;
  } catch { /* ignore */ }

  $('wallet-form').addEventListener('submit', createIdentity);
  $('wallet-select').addEventListener('change', (ev) => setActive(ev.target.value));
  $('create-form').addEventListener('submit', createAuction);

  render();
  await initZk();
  state.renderKeys = {};
  render();

  await refresh();
  setInterval(refresh, POLL_MS);
  setInterval(tickCountdowns, 1000);
}

main();

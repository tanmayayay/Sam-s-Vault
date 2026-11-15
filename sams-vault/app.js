'use strict';
/*
 * Sam’s Vault: a private password manager that runs entirely in the browser.
 *
 * Security design
 *  - A random 256-bit "vault key" encrypts all entries with AES-256-GCM (Web Crypto API).
 *  - The vault key is stored only in wrapped (encrypted) form:
 *      - once with a key derived from the master password (PBKDF2-SHA256, 600,000 rounds)
 *      - once with a key derived from the 24-character emergency code
 *      - optionally once with a Face ID passkey secret (WebAuthn PRF extension)
 *  - The master password and emergency code are never stored.
 *  - Everything lives in this device's IndexedDB. The page's Content Security Policy
 *    forbids all network connections, so nothing can be sent anywhere.
 */

/* ================= Constants ================= */

const ITERATIONS = 600000;
const RC_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1
const IDLE_LOCK_MS = 5 * 60 * 1000;
const CATEGORIES = [
  { id: 'banking', title: 'Banking' },
  { id: 'email', title: 'Email' },
  { id: 'social', title: 'Social' },
  { id: 'shopping', title: 'Shopping' },
  { id: 'work', title: 'Work' },
  { id: 'other', title: 'Other' }
];
const AUTOLOCK = [
  { v: 0, t: 'Immediately' },
  { v: 60, t: 'After 1 minute' },
  { v: 300, t: 'After 5 minutes' }
];
const COMMON = new Set([
  'password', 'password1', 'password123', 'passw0rd', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'qwerty123', 'abc123', '111111', '000000', 'letmein', 'welcome',
  'iloveyou', 'admin', 'monkey', 'dragon', 'football', 'baseball', 'sunshine', 'princess',
  'master', 'login', 'secret', 'trustno1'
]);
const STRENGTH = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'];

/* ================= Bytes & helpers ================= */

const te = new TextEncoder();
const td = new TextDecoder();
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

function toB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function uid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return Array.from(rand(16), (b) => b.toString(16).padStart(2, '0')).join('');
}
const $ = (sel) => document.querySelector(sel);
const validCat = (id) => (CATEGORIES.some((c) => c.id === id) ? id : 'other');
const catTitle = (id) => CATEGORIES.find((c) => c.id === validCat(id)).title;
const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent) ||
  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const isStandalone = () => navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;

/* ================= Crypto ================= */

const Crypto = {
  async derive(secret, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', te.encode(String(secret).normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },
  async seal(key, bytes) {
    const iv = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv);
    out.set(ct, iv.length);
    return out;
  },
  async open(key, bytes) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12)));
  },
  importKey(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  },
  async keyFromPrf(prf) {
    const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('vault-faceid-v1') },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },
  recoveryCode() {
    const b = rand(24);
    let s = '';
    for (let i = 0; i < 24; i++) {
      if (i && i % 4 === 0) s += '-';
      s += RC_ALPHA[b[i] & 31];
    }
    return s;
  },
  normCode(s) {
    return String(s).toUpperCase().split('').filter((c) => RC_ALPHA.includes(c)).join('');
  }
};

/* ================= Storage (IndexedDB on this device) ================= */

const DB = {
  db: null,
  open() {
    if (this.db) return Promise.resolve(this.db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('vault', 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => { this.db = req.result; resolve(req.result); };
      req.onerror = () => reject(req.error);
    });
  },
  async run(mode, fn) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req && req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  },
  get(key) { return this.run('readonly', (s) => s.get(key)); },
  set(key, value) { return this.run('readwrite', (s) => s.put(value, key)); },
  del(key) { return this.run('readwrite', (s) => s.delete(key)); }
};

/* ================= Errors ================= */

class VaultError extends Error {
  constructor(code) {
    super(VaultError.messages[code] || 'Something went wrong. Please try again.');
    this.code = code;
  }
}
VaultError.messages = {
  wrongPassword: "That password isn't right. Please try again.",
  wrongCode: "That emergency code isn't right. Check each letter and number, then try again.",
  lockedOut: 'Too many wrong tries. Please wait until the timer runs out.',
  corrupted: 'Your passwords could not be opened. The saved data may be damaged.',
  cancelled: '',
  bioFailed: "Face ID didn't work this time. Please use your master password.",
  bioUnsupported: "Face ID unlock isn't supported on this phone. You can keep using your master password.",
  badBackup: "That file isn't a Sam’s Vault backup."
};

/* ================= Vault ================= */

const DEFAULT_META = { failed: 0, lockUntil: 0, autoLock: 60, lastBackup: 0 };

const Vault = {
  file: null,  // what's stored: wrapped keys + encrypted entries (all base64)
  key: null,   // CryptoKey, only while unlocked
  raw: null,   // vault key bytes, only while unlocked (needed to re-wrap)
  entries: [],
  meta: { ...DEFAULT_META },

  async load() {
    this.file = (await DB.get('vault')) || null;
    this.meta = { ...DEFAULT_META, ...((await DB.get('meta')) || {}) };
  },
  saveMeta() { return DB.set('meta', this.meta); },
  get unlocked() { return !!this.key; },
  lockedOutFor() { return Math.max(0, this.meta.lockUntil - Date.now()); },
  triesLeft() { const n = this.meta.failed; return n >= 2 && n < 5 ? 5 - n : null; },

  async create(password) {
    const raw = rand(32);
    const pSalt = rand(16);
    const rSalt = rand(16);
    const code = Crypto.recoveryCode();
    const [pk, rk] = await Promise.all([
      Crypto.derive(password, pSalt, ITERATIONS),
      Crypto.derive(Crypto.normCode(code), rSalt, ITERATIONS)
    ]);
    const key = await Crypto.importKey(raw);
    const file = {
      v: 1,
      iter: ITERATIONS,
      pSalt: toB64(pSalt),
      pWrap: toB64(await Crypto.seal(pk, raw)),
      rSalt: toB64(rSalt),
      rWrap: toB64(await Crypto.seal(rk, raw)),
      ct: toB64(await Crypto.seal(key, te.encode(JSON.stringify({ entries: [] })))),
      bio: null
    };
    await DB.set('vault', file);
    this.file = file;
    this.key = key;
    this.raw = raw;
    this.entries = [];
    this.meta = { ...DEFAULT_META };
    await this.saveMeta();
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    return code;
  },

  async unwrap(secret, saltB64, wrapB64) {
    const k = await Crypto.derive(secret, fromB64(saltB64), this.file.iter);
    try { return await Crypto.open(k, fromB64(wrapB64)); } catch { return null; }
  },

  async openWith(raw) {
    const key = await Crypto.importKey(raw);
    let data;
    try {
      data = JSON.parse(td.decode(await Crypto.open(key, fromB64(this.file.ct))));
    } catch {
      throw new VaultError('corrupted');
    }
    this.key = key;
    this.raw = raw;
    this.entries = sortEntries(Array.isArray(data.entries) ? data.entries : []);
  },

  async unlock(password) {
    if (this.lockedOutFor() > 0) throw new VaultError('lockedOut');
    const raw = await this.unwrap(password, this.file.pSalt, this.file.pWrap);
    if (!raw) { await this.fail(); throw new VaultError('wrongPassword'); }
    await this.openWith(raw);
    await this.resetFails();
  },

  async recover(code, newPassword) {
    if (this.lockedOutFor() > 0) throw new VaultError('lockedOut');
    const c = Crypto.normCode(code);
    if (c.length !== 24) throw new VaultError('wrongCode');
    const raw = await this.unwrap(c, this.file.rSalt, this.file.rWrap);
    if (!raw) { await this.fail(); throw new VaultError('wrongCode'); }
    await this.openWith(raw);
    await this.setPassword(newPassword);
    await this.resetFails();
  },

  async fail() {
    const n = (this.meta.failed || 0) + 1;
    const waits = { 5: 30, 6: 60, 7: 300, 8: 900 };
    const wait = n < 5 ? 0 : (waits[n] || 3600);
    this.meta.failed = n;
    if (wait) this.meta.lockUntil = Date.now() + wait * 1000;
    await this.saveMeta();
  },
  async resetFails() {
    this.meta.failed = 0;
    this.meta.lockUntil = 0;
    await this.saveMeta();
  },

  async verify(password) {
    return !!(await this.unwrap(password, this.file.pSalt, this.file.pWrap));
  },

  async setPassword(password) {
    const salt = rand(16);
    const k = await Crypto.derive(password, salt, this.file.iter);
    const file = { ...this.file, pSalt: toB64(salt), pWrap: toB64(await Crypto.seal(k, this.raw)) };
    await DB.set('vault', file);
    this.file = file;
  },

  async changePassword(current, password) {
    if (!(await this.verify(current))) throw new VaultError('wrongPassword');
    await this.setPassword(password);
  },

  async newRecoveryCode() {
    const code = Crypto.recoveryCode();
    const salt = rand(16);
    const k = await Crypto.derive(Crypto.normCode(code), salt, this.file.iter);
    const file = { ...this.file, rSalt: toB64(salt), rWrap: toB64(await Crypto.seal(k, this.raw)) };
    await DB.set('vault', file);
    this.file = file;
    return code;
  },

  async persist(list) {
    const ct = toB64(await Crypto.seal(this.key, te.encode(JSON.stringify({ entries: list }))));
    const file = { ...this.file, ct };
    await DB.set('vault', file);
    this.file = file;
    this.entries = sortEntries(list);
  },
  save(entry) { return this.persist(this.entries.filter((e) => e.id !== entry.id).concat([entry])); },
  remove(id) { return this.persist(this.entries.filter((e) => e.id !== id)); },

  lock() {
    if (this.raw) this.raw.fill(0);
    this.key = null;
    this.raw = null;
    this.entries = [];
  },

  async erase() {
    this.lock();
    await DB.del('vault');
    await DB.del('meta');
    this.file = null;
    this.meta = { ...DEFAULT_META };
  },

  /* ----- Face ID (WebAuthn passkey + PRF extension) ----- */

  async enableBio() {
    const prfSalt = rand(32);
    let cred;
    try {
      cred = await navigator.credentials.create({
        publicKey: {
          rp: { name: 'Sam’s Vault' },
          user: { id: rand(16), name: 'Sam’s Vault', displayName: 'Sam’s Vault' },
          challenge: rand(32),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: 60000
        }
      });
    } catch {
      throw new VaultError('cancelled');
    }
    const ext = cred.getClientExtensionResults() || {};
    if (ext.prf && ext.prf.enabled === false) throw new VaultError('bioUnsupported');
    let out = ext.prf && ext.prf.results && ext.prf.results.first;
    if (!out) out = await prfGet(new Uint8Array(cred.rawId), prfSalt); // some phones need a second Face ID scan
    const wrapKey = await Crypto.keyFromPrf(new Uint8Array(out));
    const bio = {
      id: toB64(new Uint8Array(cred.rawId)),
      salt: toB64(prfSalt),
      wrap: toB64(await Crypto.seal(wrapKey, this.raw))
    };
    const file = { ...this.file, bio };
    await DB.set('vault', file);
    this.file = file;
  },

  async disableBio() {
    const file = { ...this.file, bio: null };
    await DB.set('vault', file);
    this.file = file;
  },

  async unlockBio() {
    const b = this.file.bio;
    if (!b) throw new VaultError('bioFailed');
    const prf = await prfGet(fromB64(b.id), fromB64(b.salt));
    let raw;
    try {
      raw = await Crypto.open(await Crypto.keyFromPrf(prf), fromB64(b.wrap));
    } catch {
      throw new VaultError('bioFailed');
    }
    await this.openWith(raw);
    await this.resetFails();
  },

  /* ----- Backups (still encrypted with the master password / emergency code) ----- */

  backupText() {
    const f = this.file;
    return JSON.stringify({
      app: 'vault', exported: new Date().toISOString(),
      v: f.v, iter: f.iter, pSalt: f.pSalt, pWrap: f.pWrap, rSalt: f.rSalt, rWrap: f.rWrap, ct: f.ct
    }, null, 2);
  },

  async importBackup(text) {
    let o;
    try { o = JSON.parse(text); } catch { throw new VaultError('badBackup'); }
    const fields = ['pSalt', 'pWrap', 'rSalt', 'rWrap', 'ct'];
    if (!o || o.app !== 'vault' || !fields.every((k) => typeof o[k] === 'string') ||
        !Number.isInteger(o.iter) || o.iter < 100000 || o.iter > 10000000) {
      throw new VaultError('badBackup');
    }
    const file = { v: 1, iter: o.iter, pSalt: o.pSalt, pWrap: o.pWrap, rSalt: o.rSalt, rWrap: o.rWrap, ct: o.ct, bio: null };
    await DB.set('vault', file);
    this.file = file;
    this.meta = { ...DEFAULT_META };
    await this.saveMeta();
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  }
};

async function prfGet(rawId, salt) {
  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge: rand(32),
        allowCredentials: [{ type: 'public-key', id: rawId }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
        timeout: 60000
      }
    });
  } catch {
    throw new VaultError('cancelled');
  }
  const ext = assertion.getClientExtensionResults() || {};
  const first = ext.prf && ext.prf.results && ext.prf.results.first;
  if (!first) throw new VaultError('bioUnsupported');
  return new Uint8Array(first);
}

async function bioSupported() {
  try {
    return !!(window.PublicKeyCredential &&
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

/* ================= Password tools ================= */

function sortEntries(list) {
  return list.slice().sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
}

/** 0 = very weak … 4 = excellent */
function strength(pw) {
  if (!pw) return 0;
  if (COMMON.has(pw.toLowerCase())) return 0;
  let pool = 0;
  if (/\p{Ll}/u.test(pw)) pool += 26;
  if (/\p{Lu}/u.test(pw)) pool += 26;
  if (/\p{N}/u.test(pw)) pool += 10;
  if (/[^\p{L}\p{N}]/u.test(pw)) pool += 33;
  const chars = Array.from(pw);
  const effective = Math.min(chars.length, new Set(chars).size * 3);
  const bits = effective * Math.log2(Math.max(pool, 2));
  let level = bits < 30 ? 0 : bits < 45 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  const letters = pw.toLowerCase().replace(/[^\p{L}]/gu, '');
  if (letters.length >= 4 && COMMON.has(letters)) level = Math.min(level, 1);
  return level;
}

function randomIndex(n) {
  // Unbiased random integer in [0, n)
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  let x;
  do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
  return x % n;
}

function generatePassword(length, numbers, symbols) {
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ'];
  if (numbers) sets.push('23456789');
  if (symbols) sets.push('!@#$%&*?-_+=');
  const all = sets.join('');
  const chars = sets.map((s) => s[randomIndex(s.length)]);
  while (chars.length < length) chars.push(all[randomIndex(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

function reuseCount(entry) {
  if (!entry.password) return 0;
  return Vault.entries.filter((e) => e.id !== entry.id && e.password === entry.password).length;
}

function securityReport(entries) {
  const withPw = entries.filter((e) => e.password);
  const weak = withPw.filter((e) => strength(e.password) <= 1);
  const counts = {};
  withPw.forEach((e) => { counts[e.password] = (counts[e.password] || 0) + 1; });
  const reused = withPw.filter((e) => counts[e.password] > 1);
  const yearAgo = Date.now() - 365 * 24 * 3600 * 1000;
  const old = withPw.filter((e) => (e.changedAt || 0) < yearAgo);
  const serious = new Set([...weak, ...reused].map((e) => e.id));
  const oldOnly = old.filter((e) => !serious.has(e.id)).length;
  const score = withPw.length ? Math.max(0, Math.round(100 * (1 - (serious.size + oldOnly * 0.3) / withPw.length))) : 100;
  const issues = new Set([...weak, ...reused, ...old].map((e) => e.id)).size;
  return { total: withPw.length, weak, reused, old, score, issues };
}

function webUrl(text) {
  const t = String(text || '').trim();
  if (!t) return null;
  try {
    const u = new URL(/^https?:\/\//i.test(t) ? t : 'https://' + t);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
  } catch { return null; }
}

function relTime(ms) {
  if (!ms) return 'unknown';
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const diff = (ms - Date.now()) / 1000;
  const steps = [[60, 'second'], [60, 'minute'], [24, 'hour'], [30, 'day'], [12, 'month'], [Infinity, 'year']];
  let value = diff;
  for (const [size, unit] of steps) {
    if (Math.abs(value) < size) return rtf.format(Math.round(value), unit);
    value /= size;
  }
  return '';
}

/* ================= Safe HTML templating (auto-escapes everything) ================= */

class Raw { constructor(s) { this.s = s; } }
const raw = (s) => new Raw(s);
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function part(v) {
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(part).join('');
  if (v === false || v === null || v === undefined) return '';
  return esc(v);
}
function html(strings, ...vals) {
  let out = '';
  strings.forEach((s, i) => { out += s; if (i < vals.length) out += part(vals[i]); });
  return raw(out);
}

/* ================= Icons ================= */

const ICONS = {
  lock: '<rect x="5" y="11" width="14" height="10" rx="2.5"/><path d="M8 11V7.5a4 4 0 0 1 8 0V11"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15H4.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V5"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="m3 3 18 18"/><path d="M10.6 5.1Q11.3 5 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a10 10 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  star: '<path d="m12 3.5 2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"/>',
  sliders: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  shield: '<path d="M12 3 4.5 6v5.5c0 4.6 3.2 7.9 7.5 9.5 4.3-1.6 7.5-4.9 7.5-9.5V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
  wand: '<path d="m4 20 10-10"/><path d="m13 6 1-3 1 3 3 1-3 1-1 3-1-3-3-1zM19 12l.6-1.4L21 10l-1.4-.6L19 8l-.6 1.4L17 10l1.4.6z"/>',
  trash: '<path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13"/>',
  back: '<path d="m15 18-6-6 6-6"/>',
  chevron: '<path d="m9.5 6 6 6-6 6"/>',
  key: '<circle cx="8" cy="15" r="4.5"/><path d="m11.2 11.8 8.8-8.8M16.5 6.5l2.5 2.5M14.5 8.5l2 2"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  face: '<path d="M4 8.5V6.5A2.5 2.5 0 0 1 6.5 4h2M15.5 4h2A2.5 2.5 0 0 1 20 6.5v2M20 15.5v2a2.5 2.5 0 0 1-2.5 2.5h-2M8.5 20h-2A2.5 2.5 0 0 1 4 17.5v-2"/><path d="M9 9.5v1M15 9.5v1M12 9.5v3.5h-1M9.5 16a3.5 3.5 0 0 0 5 0"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.4-5.7L20 8.5"/><path d="M20 4v4.5h-4.5"/>',
  download: '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 20h14"/>',
  alert: '<path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4.5M12 17.2v.3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.2 2"/>',
  share: '<path d="M12 3v12M7.5 7.5 12 3l4.5 4.5M5 12v6.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V12"/>',
  home: '<path d="M4 11.5 12 4l8 7.5V19a1 1 0 0 1-1 1h-4.5v-5h-5v5H5a1 1 0 0 1-1-1z"/>'
};
const icon = (name, cls = '') => raw(`<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`);

/* ================= UI building blocks ================= */

const logo = (cls = '') => html`<img class="logo ${cls}" src="logo.svg" alt="" width="92" height="92">`;
const brand = () => html`<div class="brand">${logo('xl')}<span class="wordmark">Sam’s Vault</span></div>`;

function header(title, opts = {}) {
  const { backBtn = true, right = '' } = opts;
  return html`<header class="bar">
    <div class="bar-side">${backBtn ? html`<button class="icon-btn" data-action="back" aria-label="Back">${icon('back')}<span>Back</span></button>` : ''}</div>
    <h1 class="bar-title">${title}</h1>
    <div class="bar-side right">${right}</div>
  </header>`;
}

function pwField(id, label, value = '') {
  return html`<div class="field">
    <label class="field-label" for="${id}">${label}</label>
    <div class="pw-wrap">
      <input id="${id}" type="password" value="${value}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" enterkeyhint="go">
      <button type="button" class="icon-btn reveal" data-action="reveal" aria-label="Show password">${icon('eye')}</button>
    </div>
  </div>`;
}

function strengthBar(id) {
  return html`<div class="strength" id="${id}" data-level="-1" aria-live="polite"><div class="bars"><i></i><i></i><i></i><i></i><i></i></div><span></span></div>`;
}
function setStrength(id, pw) {
  const el = document.getElementById(id);
  if (!el) return 0;
  const lvl = strength(pw);
  el.dataset.level = pw ? String(lvl) : '-1';
  el.querySelector('span').textContent = pw ? `Strength: ${STRENGTH[lvl]}` : '';
  return lvl;
}
function staticStrength(lvl) {
  return html`<div class="strength" data-level="${lvl}"><div class="bars"><i></i><i></i><i></i><i></i><i></i></div><span>Strength: ${STRENGTH[lvl]}</span></div>`;
}

function avatar(entry, size = '') {
  const initial = Array.from((entry.name || '?').trim())[0] || '?';
  return html`<div class="avatar ${size} cat-${validCat(entry.category)}" aria-hidden="true">${initial.toUpperCase()}</div>`;
}

function feature(ic, title, text) {
  return html`<li class="feature"><span class="feature-icon">${icon(ic)}</span><div><b>${title}</b><p>${text}</p></div></li>`;
}

function navItem(to, ic, label, extra = '') {
  return html`<button class="item nav ${extra}" data-action="nav" data-to="${to}">${icon(ic, 'lead')}<span class="item-text">${label}</span>${icon('chevron', 'trail')}</button>`;
}

function codeGrid(code) {
  return html`<div class="code-grid" aria-label="${'Emergency code: ' + code.split('').join(' ')}">${code.split('-').map((g) => html`<span>${g}</span>`)}</div>`;
}

function setError(text) { const el = $('#err'); if (el) el.textContent = text || ''; }

function busy(btn, on, label) {
  if (!btn) return;
  if (on) {
    btn.dataset.label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>' + (label ? esc(label) : '');
  } else {
    btn.disabled = false;
    if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
  }
}

let toastTimer;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
}

let clipTimer;
async function copyText(text, label) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.className = 'offscreen';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length);
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
  }
  toast(ok ? `${label} copied` : 'Could not copy. Tap Show and copy it by hand.');
  if (navigator.vibrate) navigator.vibrate(10);
  // Best effort: clear the clipboard after a minute if the app is still open.
  clearTimeout(clipTimer);
  clipTimer = setTimeout(() => {
    if (document.hasFocus()) navigator.clipboard.writeText(' ').catch(() => {});
  }, 60000);
}

/* ================= Navigation ================= */

const app = document.getElementById('app');
const stack = [];
let current = null;
let viewTimer = null;
const state = { search: '', filter: null, bioSupported: false, hiddenAt: 0, lastActivity: Date.now() };

function go(name, params = {}) {
  if (stack.length) stack[stack.length - 1].scroll = window.scrollY;
  stack.push({ name, params });
  render();
}
function replace(name, params = {}) {
  stack.length = 0;
  stack.push({ name, params });
  render();
}
function back() {
  if (stack.length > 1) stack.pop();
  render(true);
}
function render(restoreScroll = false) {
  clearInterval(viewTimer);
  viewTimer = null;
  const top = stack[stack.length - 1];
  const view = Views[top.name];
  current = { name: top.name, params: top.params, view };
  app.innerHTML = view.render(top.params).s;
  app.dataset.view = top.name;
  window.scrollTo(0, restoreScroll && top.scroll ? top.scroll : 0);
  if (view.mount) view.mount(top.params);
}

function lockApp() {
  if (!Vault.file) return;
  Vault.lock();
  state.search = '';
  state.filter = null;
  replace('unlock');
}

/* ================= Global actions ================= */

const GlobalActions = {
  back: () => back(),
  nav: (t) => go(t.dataset.to),
  lock: () => lockApp(),
  reveal: (t) => {
    const input = t.closest('.pw-wrap').querySelector('input');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    t.innerHTML = icon(show ? 'eyeOff' : 'eye').s;
    t.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  },
  copy: (t) => {
    const e = Vault.entries.find((x) => x.id === t.dataset.id);
    if (!e) return;
    const field = t.dataset.field === 'username' ? 'username' : 'password';
    copyText(e[field], field === 'username' ? 'Username' : 'Password');
  }
};

/* ================= Views ================= */

const Views = {};

/* ----- Welcome ----- */
Views.welcome = {
  render() {
    const needInstall = isIOS() && !isStandalone();
    return html`<div class="page center">
      <div class="hero">${brand()}
        <h1 class="title">Your passwords,<br>safe in one place</h1>
        <p class="lead">Keep every login (bank, email, everything) locked and encrypted on this phone.</p>
      </div>
      ${needInstall ? html`<div class="card install">
        <b>${icon('home')} First, add Sam’s Vault to your Home Screen</b>
        <ol>
          <li>Tap the <b>Share</b> button ${icon('share', 'inline')} at the bottom of Safari.</li>
          <li>Scroll down and tap <b>Add to Home Screen</b>.</li>
          <li>Open <b>Sam’s Vault</b> from your Home Screen and set it up there.</li>
        </ol>
        <p class="muted small">Passwords saved here in Safari are kept separately from the Home Screen app.</p>
      </div>` : ''}
      <ul class="features">
        ${feature('lock', 'Only you can open it', 'Locked with a master password only you know.')}
        ${feature('shield', 'Encrypted on this phone', 'Nobody can read it, not even whoever set up this app.')}
        ${feature('face', 'Quick to open', 'Unlock with Face ID on supported iPhones.')}
      </ul>
    </div>
    <footer class="actions">
      <button class="btn primary" data-action="start">${needInstall ? 'Set up here anyway' : 'Get started'}</button>
      <button class="btn link" data-action="restore">Restore from a backup file</button>
      <input type="file" id="restore-file" accept=".json,application/json" hidden>
    </footer>`;
  },
  actions: {
    start: () => go('create'),
    restore: () => $('#restore-file').click()
  },
  async onChange(t) {
    if (t.id !== 'restore-file' || !t.files[0]) return;
    try {
      await Vault.importBackup(await t.files[0].text());
      toast('Backup restored. Unlock it with your master password.');
      replace('unlock');
    } catch (e) {
      toast(e.message);
    }
    t.value = '';
  }
};

/* ----- Create master password ----- */
Views.create = {
  render() {
    return html`${header('Set up')}
    <form class="page" id="create-form" autocomplete="off">
      <h2 class="title">Create your master password</h2>
      <p class="lead">This is the only password you'll need to remember. Nobody else can see it or reset it, not even the person who set up this app.</p>
      <div class="tip">${icon('info')}<span>Tip: a short sentence is easy to remember and hard to guess. Pick something only you would think of, with a number in it.</span></div>
      ${pwField('pw1', 'Master password')}
      ${pwField('pw2', 'Type it again')}
      ${strengthBar('st')}
      <ul class="reqs">
        <li id="r-len">${icon('check')}At least 10 characters</li>
        <li id="r-str">${icon('check')}Not too easy to guess</li>
        <li id="r-match">${icon('check')}Both entries match</li>
      </ul>
      <p class="error" id="err" role="alert"></p>
      <div class="actions"><button class="btn primary" id="go" type="submit" disabled>Continue</button></div>
    </form>`;
  },
  onInput() {
    const a = $('#pw1').value;
    const b = $('#pw2').value;
    const lvl = setStrength('st', a);
    const len = Array.from(a).length >= 10;
    const str = lvl >= 2;
    const match = b.length > 0 && a === b;
    $('#r-len').classList.toggle('met', len);
    $('#r-str').classList.toggle('met', str);
    $('#r-match').classList.toggle('met', match);
    $('#go').disabled = !(len && str && match);
  },
  async onSubmit() {
    const btn = $('#go');
    if (btn.disabled) return;
    busy(btn, true, 'Securing…');
    try {
      const code = await Vault.create($('#pw1').value);
      replace('recovery', { code });
    } catch {
      busy(btn, false);
      setError('Something went wrong. Please try again.');
    }
  }
};

/* ----- Emergency code (first setup) ----- */
Views.recovery = {
  render({ code }) {
    return html`<div class="page">
      <div class="hero small">${icon('key', 'hero-icon')}
        <h2 class="title">Your emergency code</h2>
        <p class="lead">If you ever forget your master password, this code is the only way back in. Write it on paper and keep it somewhere safe, like with your important documents.</p>
      </div>
      ${codeGrid(code)}
      <div class="tip warn">${icon('alert')}<span>Don't take a photo of it or save it on your phone. Anyone with this code and your phone could open your passwords.</span></div>
      <label class="check big"><input type="checkbox" id="ok"><span>I've written it down and put it somewhere safe</span></label>
    </div>
    <footer class="actions"><button class="btn primary" id="go" data-action="next" disabled>Continue</button></footer>`;
  },
  onChange(t) { if (t.id === 'ok') $('#go').disabled = !t.checked; },
  actions: {
    next: () => (state.bioSupported ? replace('bio') : replace('home'))
  }
};

/* ----- Offer Face ID ----- */
Views.bio = {
  render() {
    return html`<div class="page center">
      <div class="hero">${icon('face', 'hero-icon xl')}
        <h2 class="title">Unlock with Face ID?</h2>
        <p class="lead">Open your passwords in a second with Face ID. Your master password will still work any time.</p>
      </div>
      <p class="error" id="err" role="alert"></p>
    </div>
    <footer class="actions">
      <button class="btn primary" data-action="enable">Use Face ID</button>
      <button class="btn secondary" data-action="skip">Not now</button>
    </footer>`;
  },
  actions: {
    enable: async (t) => {
      busy(t, true);
      try {
        await Vault.enableBio();
        toast('Face ID is on');
        replace('home');
      } catch (e) {
        busy(t, false);
        if (e.code !== 'cancelled') setError(e.message);
      }
    },
    skip: () => replace('home')
  }
};

/* ----- Unlock ----- */
Views.unlock = {
  render() {
    const bio = !!(Vault.file && Vault.file.bio) && state.bioSupported;
    return html`<form class="page center" id="unlock-form" autocomplete="off">
      <div class="hero">${brand()}
        <h1 class="title">Welcome back</h1>
        <p class="lead">${bio ? 'Unlock to see your passwords.' : 'Enter your master password to see your passwords.'}</p>
      </div>
      <div id="lockout" class="banner warn" hidden></div>
      ${bio ? html`<button type="button" class="btn primary" data-action="bio">${icon('face')} Unlock with Face ID</button>
        <div class="or"><span>or use your master password</span></div>` : ''}
      ${pwField('pw', 'Master password')}
      <p class="error" id="err" role="alert"></p>
      <button class="btn ${bio ? 'secondary' : 'primary'}" id="go" type="submit">Unlock</button>
      <button type="button" class="btn link" data-action="forgot">Forgot your password?</button>
    </form>`;
  },
  mount() {
    const tick = () => {
      const el = $('#lockout');
      if (!el) return;
      const left = Math.ceil(Vault.lockedOutFor() / 1000);
      el.hidden = left <= 0;
      if (left > 0) {
        const m = Math.floor(left / 60);
        const s = left % 60;
        el.textContent = `Too many tries. Try again in ${m ? `${m} min ${s} sec` : `${s} sec`}.`;
      }
    };
    tick();
    viewTimer = setInterval(tick, 1000);
  },
  actions: {
    bio: async (t) => {
      setError('');
      busy(t, true);
      try {
        await Vault.unlockBio();
        replace('home');
      } catch (e) {
        busy(t, false);
        if (e.code !== 'cancelled') setError(e.message);
      }
    },
    forgot: () => go('reset')
  },
  async onSubmit() {
    const input = $('#pw');
    const btn = $('#go');
    if (!input.value || btn.disabled) return;
    setError('');
    busy(btn, true);
    try {
      await Vault.unlock(input.value);
      replace('home');
    } catch (e) {
      busy(btn, false);
      let msg = e.message;
      if (e.code === 'wrongPassword' && Vault.triesLeft()) {
        const n = Vault.triesLeft();
        msg += ` ${n} more ${n === 1 ? 'try' : 'tries'} before a short wait.`;
      }
      setError(msg);
      input.value = '';
    }
  }
};

/* ----- Forgot password: emergency code ----- */
Views.reset = {
  render() {
    return html`${header('Reset password')}
    <form class="page" id="reset-form" autocomplete="off">
      <p class="lead">Enter the emergency code you wrote down when you set up the app, then choose a new master password.</p>
      <div class="field">
        <label class="field-label" for="code">Emergency code</label>
        <input id="code" class="mono code-input" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false">
      </div>
      ${pwField('pw1', 'New master password')}
      ${pwField('pw2', 'Type it again')}
      ${strengthBar('st')}
      <p class="foot">At least 10 characters. A short sentence works well.</p>
      <p class="error" id="err" role="alert"></p>
      <button class="btn primary" id="go" type="submit" disabled>Reset password</button>
    </form>`;
  },
  onInput() {
    const a = $('#pw1').value;
    const lvl = setStrength('st', a);
    $('#go').disabled = !(Crypto.normCode($('#code').value).length === 24 &&
      Array.from(a).length >= 10 && lvl >= 2 && a === $('#pw2').value);
  },
  async onSubmit() {
    const btn = $('#go');
    if (btn.disabled) return;
    setError('');
    busy(btn, true);
    try {
      await Vault.recover($('#code').value, $('#pw1').value);
      toast('Your new master password is set');
      replace('home');
    } catch (e) {
      busy(btn, false);
      setError(e.message);
    }
  }
};

/* ----- Home (list) ----- */
Views.home = {
  render() {
    return html`<header class="home-head">
      <div class="home-top">
        <div class="home-title">${logo('sm')}<div><span class="wordmark">Sam’s Vault</span><h1>Passwords</h1></div></div>
        <button class="icon-btn pill" data-action="lock" aria-label="Lock">${icon('lock')}<span>Lock</span></button>
      </div>
      <label class="search">${icon('search')}
        <input id="search" type="search" placeholder="Search names, emails, websites" value="${state.search}" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" enterkeyhint="search">
      </label>
    </header>
    <div id="chips" class="chips"></div>
    <main id="list" class="list-wrap"></main>
    <nav class="tabbar">
      <button class="tab" data-action="nav" data-to="security">${icon('shield')}<span>Security</span></button>
      <button class="tab" data-action="nav" data-to="generator">${icon('wand')}<span>Generator</span></button>
      <button class="tab add" data-action="add" aria-label="Add a password"><span class="add-circle">${icon('plus')}</span><span>Add</span></button>
      <button class="tab" data-action="nav" data-to="settings">${icon('sliders')}<span>Settings</span></button>
    </nav>`;
  },
  mount() { Views.home.refresh(); },
  refresh() {
    const all = Vault.entries;
    const q = state.search.trim().toLowerCase();
    if (state.filter && !all.some((e) => validCat(e.category) === state.filter)) state.filter = null;

    const counts = {};
    all.forEach((e) => { const c = validCat(e.category); counts[c] = (counts[c] || 0) + 1; });
    $('#chips').innerHTML = all.length ? html`
      <button class="chip ${state.filter ? '' : 'on'}" data-action="filter" data-cat="">All</button>
      ${CATEGORIES.filter((c) => counts[c.id]).map((c) =>
        html`<button class="chip ${state.filter === c.id ? 'on' : ''}" data-action="filter" data-cat="${c.id}"><i class="dot cat-${c.id}"></i>${c.title}</button>`)}`.s : '';

    const matches = all.filter((e) =>
      (!state.filter || validCat(e.category) === state.filter) &&
      (!q || [e.name, e.username, e.website].some((f) => String(f || '').toLowerCase().includes(q))));
    const favorites = !q && !state.filter ? all.filter((e) => e.fav) : [];
    const needBackup = all.length >= 3 && Date.now() - (Vault.meta.lastBackup || 0) > 30 * 24 * 3600 * 1000;

    let body;
    if (!all.length) {
      body = html`<div class="empty">${icon('key', 'hero-icon')}
        <h2>No passwords yet</h2>
        <p>Tap <b>Add</b> below to save your first password.</p></div>`;
    } else if (!matches.length) {
      body = html`<div class="empty"><h2>No results</h2><p>Nothing matches “${state.search}”.</p></div>`;
    } else {
      body = html`
        ${needBackup ? html`<button class="banner info" data-action="backup">${icon('download')}<span><b>Save a backup</b><br>So you don't lose your passwords if this phone is lost.</span></button>` : ''}
        ${favorites.length ? html`<h3 class="section">Favorites</h3><div class="group">${favorites.map(row)}</div>` : ''}
        <h3 class="section">${state.filter ? catTitle(state.filter) : 'All passwords'} <span class="count">${matches.length}</span></h3>
        <div class="group">${matches.map(row)}</div>`;
    }
    $('#list').innerHTML = body.s;
  },
  onInput(t) {
    if (t.id === 'search') { state.search = t.value; Views.home.refresh(); }
  },
  actions: {
    filter: (t) => { state.filter = t.dataset.cat || null; Views.home.refresh(); },
    open: (t) => go('detail', { id: t.dataset.id }),
    add: () => go('edit', {}),
    backup: () => exportBackup()
  }
};

function row(e) {
  return html`<div class="row">
    <button class="row-main" data-action="open" data-id="${e.id}">
      ${avatar(e)}
      <span class="row-text"><b>${e.name}</b>${e.username ? html`<small>${e.username}</small>` : ''}</span>
      ${e.fav ? icon('star', 'fav-mark') : ''}
    </button>
    ${e.password ? html`<button class="icon-btn accent" data-action="copy" data-id="${e.id}" data-field="password" aria-label="${'Copy password for ' + e.name}">${icon('copy')}</button>` : ''}
  </div>`;
}

/* ----- Entry detail ----- */
Views.detail = {
  render({ id }) {
    const e = Vault.entries.find((x) => x.id === id);
    if (!e) return html`${header('')}<div class="page"><p class="lead">This password was deleted.</p></div>`;
    const lvl = strength(e.password);
    const reuse = reuseCount(e);
    const url = webUrl(e.website);
    return html`${header('', { right: html`
        <button class="icon-btn ${e.fav ? 'fav-on' : ''}" data-action="fav" aria-label="${e.fav ? 'Remove from favorites' : 'Add to favorites'}">${icon('star')}</button>
        <button class="text-btn" data-action="edit">Edit</button>` })}
    <div class="page">
      <div class="detail-head">${avatar(e, 'xl')}
        <h1 class="title">${e.name}</h1>
        <p class="muted">${catTitle(e.category)}</p>
      </div>
      ${(e.username || e.password) ? html`<div class="group">
        ${e.username ? html`<div class="item">
          <div class="item-text"><small>Username</small><span class="val">${e.username}</span></div>
          <button class="icon-btn accent" data-action="copy" data-id="${e.id}" data-field="username" aria-label="Copy username">${icon('copy')}</button>
        </div>` : ''}
        ${e.password ? html`<div class="item">
          <div class="item-text"><small>Password</small><span class="val mono" id="pwv">••••••••••</span></div>
          <button class="icon-btn" data-action="showpw" aria-label="Show password">${icon('eye')}</button>
          <button class="icon-btn accent" data-action="copy" data-id="${e.id}" data-field="password" aria-label="Copy password">${icon('copy')}</button>
        </div>` : ''}
      </div>` : ''}
      ${url ? html`<div class="group"><a class="item" href="${url}" target="_blank" rel="noopener noreferrer">
        <div class="item-text"><small>Website</small><span class="val">${e.website}</span></div>${icon('external', 'trail accent')}
      </a></div>` : ''}
      ${e.notes ? html`<h3 class="section">Notes</h3><div class="group"><div class="item notes">${e.notes}</div></div>` : ''}
      ${e.password ? html`<h3 class="section">Password health</h3><div class="group"><div class="item col">
        ${staticStrength(lvl)}
        ${reuse ? html`<p class="warn-text">${icon('alert')}<span>Also used for ${reuse} other ${reuse === 1 ? 'account' : 'accounts'}. It's safer to give each account its own password.</span></p>` : ''}
        <p class="muted small">Password last changed ${relTime(e.changedAt)}</p>
      </div></div>` : ''}
      <button class="btn danger-link" data-action="delete">${icon('trash')} Delete this password</button>
    </div>`;
  },
  actions: {
    showpw: (t) => {
      const e = Vault.entries.find((x) => x.id === current.params.id);
      const el = $('#pwv');
      const show = el.dataset.shown !== '1';
      el.textContent = show ? e.password : '••••••••••';
      el.dataset.shown = show ? '1' : '0';
      t.innerHTML = icon(show ? 'eyeOff' : 'eye').s;
      t.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    },
    fav: async () => {
      const e = Vault.entries.find((x) => x.id === current.params.id);
      await Vault.save({ ...e, fav: !e.fav });
      render();
    },
    edit: () => go('edit', { id: current.params.id }),
    delete: async () => {
      const e = Vault.entries.find((x) => x.id === current.params.id);
      if (!confirm(`Delete “${e.name}”? This can't be undone.`)) return;
      await Vault.remove(e.id);
      toast('Deleted');
      back();
    }
  }
};

/* ----- Add / edit ----- */
Views.edit = {
  render({ id }) {
    const e = id ? Vault.entries.find((x) => x.id === id) : null;
    const d = e || { name: '', username: '', password: '', website: '', notes: '', category: 'other', fav: false };
    return html`${header(e ? 'Edit' : 'New password', { right: html`<button class="text-btn bold" data-action="save">Save</button>` })}
    <form class="page" id="edit-form" autocomplete="off">
      <div class="field">
        <label class="field-label" for="f-name">Name</label>
        <input id="f-name" value="${d.name}" placeholder="For example: Chase Bank" autocomplete="off" autocapitalize="words" maxlength="120">
      </div>
      <div class="field">
        <label class="field-label" for="f-cat">Type</label>
        <select id="f-cat">${CATEGORIES.map((c) => html`<option value="${c.id}" ${c.id === validCat(d.category) ? raw('selected') : ''}>${c.title}</option>`)}</select>
      </div>
      <div class="field">
        <label class="field-label" for="f-user">Username or email</label>
        <input id="f-user" value="${d.username}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="email">
      </div>
      ${pwField('f-pw', 'Password', d.password)}
      <button type="button" class="btn secondary small" data-action="gen">${icon('wand')} Create a strong password for me</button>
      ${strengthBar('st')}
      <div class="field">
        <label class="field-label" for="f-web">Website (optional)</label>
        <input id="f-web" value="${d.website}" placeholder="example.com" inputmode="url" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
      </div>
      <div class="field">
        <label class="field-label" for="f-notes">Notes (optional)</label>
        <textarea id="f-notes" rows="4" placeholder="Account number, security questions…">${d.notes}</textarea>
      </div>
      <label class="check"><input type="checkbox" id="f-fav" ${d.fav ? raw('checked') : ''}><span>Show in Favorites</span></label>
      <p class="error" id="err" role="alert"></p>
      <button class="btn primary" type="submit">Save</button>
    </form>`;
  },
  snapshot() {
    return ['#f-name', '#f-cat', '#f-user', '#f-pw', '#f-web', '#f-notes'].map((s) => $(s).value).join('\u0000') + $('#f-fav').checked;
  },
  mount() {
    setStrength('st', $('#f-pw').value);
    Views.edit.initial = Views.edit.snapshot();
    if (!current.params.id) $('#f-name').focus();
  },
  onInput(t) { if (t.id === 'f-pw') setStrength('st', t.value); },
  actions: {
    back: () => {
      if (Views.edit.snapshot() !== Views.edit.initial && !confirm('Discard your changes?')) return;
      back();
    },
    gen: () => {
      const input = $('#f-pw');
      if (input.value && !confirm('Replace the current password with a new strong one?')) return;
      input.value = generatePassword(20, true, true);
      input.type = 'text';
      const btn = input.parentElement.querySelector('.reveal');
      btn.innerHTML = icon('eyeOff').s;
      btn.setAttribute('aria-label', 'Hide password');
      setStrength('st', input.value);
      toast('Strong password created. Save, then copy it to the website.');
    },
    save: () => Views.edit.onSubmit()
  },
  async onSubmit() {
    const name = $('#f-name').value.trim();
    if (!name) { setError('Please give it a name, like “Chase Bank”.'); $('#f-name').focus(); return; }
    const id = current.params.id;
    const old = id ? Vault.entries.find((x) => x.id === id) : null;
    const now = Date.now();
    const pw = $('#f-pw').value;
    const entry = {
      id: old ? old.id : uid(),
      name,
      category: validCat($('#f-cat').value),
      username: $('#f-user').value.trim(),
      password: pw,
      website: $('#f-web').value.trim(),
      notes: $('#f-notes').value,
      fav: $('#f-fav').checked,
      createdAt: old ? old.createdAt : now,
      updatedAt: now,
      changedAt: old && old.password === pw ? old.changedAt : now
    };
    try {
      await Vault.save(entry);
      toast('Saved');
      if (old) {
        back();
      } else {
        stack.pop();
        go('detail', { id: entry.id });
      }
    } catch {
      setError("Couldn't save. Please try again.");
    }
  }
};

/* ----- Password generator ----- */
Views.generator = {
  opts: { length: 20, numbers: true, symbols: true },
  render() {
    const o = Views.generator.opts;
    return html`${header('Generator')}
    <div class="page">
      <div class="group"><div class="item col center">
        <div class="gen-out mono" id="gen"></div>
        ${strengthBar('st')}
        <div class="row-btns">
          <button class="btn secondary" data-action="regen">${icon('refresh')} New one</button>
          <button class="btn primary" data-action="copygen">${icon('copy')} Copy</button>
        </div>
      </div></div>
      <h3 class="section">Options</h3>
      <div class="group">
        <div class="item col">
          <label class="field-label" for="len">Length: <b id="len-v">${o.length}</b> characters</label>
          <input type="range" id="len" min="12" max="40" step="1" value="${o.length}">
        </div>
        <label class="item"><span class="item-text">Include numbers</span><input type="checkbox" class="switch" id="nums" ${o.numbers ? raw('checked') : ''}></label>
        <label class="item"><span class="item-text">Include symbols</span><input type="checkbox" class="switch" id="syms" ${o.symbols ? raw('checked') : ''}></label>
      </div>
      <p class="foot">Tip: when you change a password on a website, make a new one here, copy it, and save it in Sam’s Vault too.</p>
    </div>`;
  },
  mount() { Views.generator.regen(); },
  regen() {
    const o = Views.generator.opts;
    const pw = generatePassword(o.length, o.numbers, o.symbols);
    $('#gen').textContent = pw;
    setStrength('st', pw);
  },
  onInput(t) {
    const o = Views.generator.opts;
    if (t.id === 'len') { o.length = Number(t.value); $('#len-v').textContent = t.value; Views.generator.regen(); }
  },
  onChange(t) {
    const o = Views.generator.opts;
    if (t.id === 'nums') o.numbers = t.checked;
    if (t.id === 'syms') o.symbols = t.checked;
    if (t.id === 'nums' || t.id === 'syms') Views.generator.regen();
  },
  actions: {
    regen: () => Views.generator.regen(),
    copygen: () => copyText($('#gen').textContent, 'Password')
  }
};

/* ----- Security check ----- */
Views.security = {
  render() {
    const r = securityReport(Vault.entries);
    const color = r.score >= 80 ? 'good' : r.score >= 50 ? 'ok' : 'bad';
    const C = 2 * Math.PI * 60;
    const headline = !r.total ? 'Nothing to check yet' : !r.issues ? 'Looking great!' :
      r.issues === 1 ? '1 password needs attention' : `${r.issues} passwords need attention`;
    const summary = !r.total ? 'Add some passwords and come back here.' : !r.issues
      ? 'No weak, repeated or old passwords found.' : 'Fixing these makes your accounts much harder to break into.';
    const section = (title, foot, list) => list.length ? html`
      <h3 class="section">${title} <span class="count">${list.length}</span></h3>
      <div class="group">${list.map((e) => html`<div class="row"><button class="row-main" data-action="open" data-id="${e.id}">${avatar(e)}<span class="row-text"><b>${e.name}</b>${e.username ? html`<small>${e.username}</small>` : ''}</span>${icon('chevron', 'trail')}</button></div>`)}</div>
      <p class="foot">${foot}</p>` : '';
    return html`${header('Security Check')}
    <div class="page">
      <div class="score">
        <svg viewBox="0 0 140 140" class="ring ${color}" aria-hidden="true">
          <circle cx="70" cy="70" r="60" class="track"/>
          <circle cx="70" cy="70" r="60" class="value" stroke-dasharray="${(C * r.score / 100).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 70 70)"/>
        </svg>
        <div class="score-num"><b>${r.score}</b><span>out of 100</span></div>
      </div>
      <h2 class="title center-text">${headline}</h2>
      <p class="lead center-text">${summary}</p>
      ${section('Weak passwords', 'These are easy to guess. Open each one, tap Edit, then “Create a strong password for me”. Remember to change it on the website too.', r.weak)}
      ${section('Used more than once', 'If one website is hacked, every account sharing that password is at risk.', r.reused)}
      ${section('Not changed in over a year', 'Changing important passwords now and then adds extra safety.', r.old)}
    </div>`;
  },
  actions: { open: (t) => go('detail', { id: t.dataset.id }) }
};

/* ----- Settings ----- */
Views.settings = {
  render() {
    const bioOn = !!Vault.file.bio;
    return html`${header('Settings')}
    <div class="page">
      <h3 class="section">Unlocking</h3>
      <div class="group">
        ${state.bioSupported ? html`<label class="item">${icon('face', 'lead')}<span class="item-text">Unlock with Face ID</span><input type="checkbox" class="switch" id="bio" ${bioOn ? raw('checked') : ''}></label>` : ''}
        <label class="item">${icon('clock', 'lead')}<span class="item-text">Auto-lock</span>
          <select id="autolock" class="inline-select">${AUTOLOCK.map((o) => html`<option value="${o.v}" ${o.v === Vault.meta.autoLock ? raw('selected') : ''}>${o.t}</option>`)}</select>
        </label>
      </div>
      <p class="foot">Sam’s Vault locks itself after you leave it, and after 5 minutes without use. Your master password always works.</p>

      <h3 class="section">Master password</h3>
      <div class="group">
        ${navItem('changepw', 'key', 'Change master password')}
        ${navItem('newcode', 'shield', 'Make a new emergency code')}
      </div>

      <h3 class="section">Backup</h3>
      <div class="group">
        <button class="item nav" data-action="backup">${icon('download', 'lead')}<span class="item-text">Save an encrypted backup</span>${icon('chevron', 'trail')}</button>
      </div>
      <p class="foot">${Vault.meta.lastBackup ? `Last backup: ${relTime(Vault.meta.lastBackup)}. ` : ''}The backup stays locked with your master password. Save it to Files or iCloud Drive so you can restore your passwords on a new phone.</p>

      <div class="group">${navItem('about', 'info', 'How your passwords are protected')}</div>
      <div class="group">${navItem('erase', 'trash', 'Erase all passwords', 'danger')}</div>
    </div>`;
  },
  actions: { backup: () => exportBackup() },
  async onChange(t) {
    if (t.id === 'autolock') {
      Vault.meta.autoLock = Number(t.value);
      await Vault.saveMeta();
      toast('Saved');
    }
    if (t.id === 'bio') {
      t.disabled = true;
      try {
        if (t.checked) { await Vault.enableBio(); toast('Face ID is on'); } else { await Vault.disableBio(); toast('Face ID is off'); }
      } catch (e) {
        t.checked = !t.checked;
        if (e.code !== 'cancelled') toast(e.message);
      }
      t.disabled = false;
    }
  }
};

async function exportBackup() {
  const text = Vault.backupText();
  const name = `sams-vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  const file = new File([text], name, { type: 'application/json' });
  try {
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: 'Sam’s Vault backup' });
    } else {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(file);
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    }
  } catch (e) {
    if (e && e.name === 'AbortError') return;
    toast("Couldn't save the backup. Please try again.");
    return;
  }
  Vault.meta.lastBackup = Date.now();
  await Vault.saveMeta();
  toast('Backup saved');
  if (current && current.name === 'home') Views.home.refresh();
}

/* ----- Change master password ----- */
Views.changepw = {
  render() {
    return html`${header('Change password')}
    <form class="page" id="cp-form" autocomplete="off">
      ${pwField('cur', 'Current master password')}
      ${pwField('pw1', 'New master password')}
      ${pwField('pw2', 'Type it again')}
      ${strengthBar('st')}
      <p class="foot">At least 10 characters. A short sentence works well.</p>
      <p class="error" id="err" role="alert"></p>
      <button class="btn primary" id="go" type="submit" disabled>Change password</button>
    </form>`;
  },
  onInput() {
    const a = $('#pw1').value;
    const lvl = setStrength('st', a);
    $('#go').disabled = !($('#cur').value && Array.from(a).length >= 10 && lvl >= 2 && a === $('#pw2').value);
  },
  async onSubmit() {
    const btn = $('#go');
    if (btn.disabled) return;
    setError('');
    busy(btn, true);
    try {
      await Vault.changePassword($('#cur').value, $('#pw1').value);
      toast('Master password changed');
      back();
    } catch (e) {
      busy(btn, false);
      setError(e.message);
    }
  }
};

/* ----- New emergency code ----- */
Views.newcode = {
  render({ code }) {
    if (code) {
      return html`${header('Emergency code', { backBtn: false })}
      <div class="page">
        <h2 class="title">Your new emergency code</h2>
        <p class="lead">Write this down and keep it somewhere safe. Your old code no longer works, so you can tear it up.</p>
        ${codeGrid(code)}
        <label class="check big"><input type="checkbox" id="ok"><span>I've written it down</span></label>
      </div>
      <footer class="actions"><button class="btn primary" id="go" data-action="done" disabled>Done</button></footer>`;
    }
    return html`${header('Emergency code')}
    <form class="page" id="nc-form" autocomplete="off">
      <p class="lead">To make a new emergency code, first enter your master password.</p>
      ${pwField('pw', 'Master password')}
      <p class="error" id="err" role="alert"></p>
      <button class="btn primary" id="go" type="submit">Continue</button>
    </form>`;
  },
  onChange(t) { if (t.id === 'ok') $('#go').disabled = !t.checked; },
  actions: { done: () => back() },
  async onSubmit() {
    const btn = $('#go');
    const pw = $('#pw').value;
    if (!pw) return;
    setError('');
    busy(btn, true);
    if (!(await Vault.verify(pw))) {
      busy(btn, false);
      setError(VaultError.messages.wrongPassword);
      $('#pw').value = '';
      return;
    }
    const code = await Vault.newRecoveryCode();
    stack[stack.length - 1].params = { code };
    render();
  }
};

/* ----- Erase ----- */
Views.erase = {
  render() {
    return html`${header('Erase all')}
    <form class="page" id="erase-form" autocomplete="off">
      <div class="tip warn">${icon('alert')}<span>This permanently deletes every password saved in Sam’s Vault on this phone. It can't be undone.</span></div>
      ${pwField('pw', 'Enter your master password to confirm')}
      <p class="error" id="err" role="alert"></p>
      <button class="btn danger" id="go" type="submit">Erase everything</button>
    </form>`;
  },
  async onSubmit() {
    const btn = $('#go');
    const pw = $('#pw').value;
    if (!pw) return;
    setError('');
    busy(btn, true);
    if (!(await Vault.verify(pw))) {
      busy(btn, false);
      setError(VaultError.messages.wrongPassword);
      return;
    }
    await Vault.erase();
    toast('Everything was erased');
    replace('welcome');
  }
};

/* ----- About security ----- */
Views.about = {
  render() {
    return html`${header('How it’s protected')}
    <div class="page">
      <ul class="features">
        ${feature('lock', 'Strong encryption', 'Everything is scrambled with AES-256, the standard banks use. Without your master password it is unreadable.')}
        ${feature('key', 'Your password is never stored', 'Sam’s Vault never saves your master password. It is turned into a key with 600,000 rounds of math, which makes guessing extremely slow.')}
        ${feature('shield', 'Stays on this phone', 'Your passwords are stored only on this phone, encrypted. The app is blocked from connecting to the internet, so nothing you type is ever sent anywhere.')}
        ${feature('face', 'Face ID', 'Face ID uses a passkey kept in your iCloud Keychain. Anyone whose face is set up on this iPhone could use it, so only use Face ID if you are the only face on this phone.')}
        ${feature('clock', 'Locks itself', 'Sam’s Vault hides its contents when you leave and locks automatically.')}
        ${feature('alert', 'Guessing is blocked', 'After 5 wrong tries Sam’s Vault makes you wait, and the wait gets longer each time.')}
        ${feature('copy', 'About copying', 'A copied password stays on the clipboard until you copy something else. Sam’s Vault tries to clear it after 1 minute while it is open.')}
        ${feature('download', 'Backups stay locked', 'Backup files are encrypted the same way. Restore one on a new phone with your master password or emergency code.')}
        ${feature('info', 'Only you can get back in', 'If you forget your master password, only your emergency code can open Sam’s Vault. Nobody else, including the person who set it up, can reset it.')}
      </ul>
    </div>`;
  }
};

/* ================= Event wiring ================= */

document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-action]');
  if (!t || !current) return;
  const name = t.dataset.action;
  const fn = (current.view.actions && current.view.actions[name]) || GlobalActions[name];
  if (fn) { e.preventDefault(); fn(t, e); }
});
document.addEventListener('input', (e) => { if (current && current.view.onInput) current.view.onInput(e.target, e); });
document.addEventListener('change', (e) => { if (current && current.view.onChange) current.view.onChange(e.target, e); });
document.addEventListener('submit', (e) => {
  e.preventDefault();
  if (current && current.view.onSubmit) current.view.onSubmit(e.target);
});

// Auto-lock: when the app is left, and after 5 minutes without use.
['pointerdown', 'keydown', 'touchstart'].forEach((ev) =>
  document.addEventListener(ev, () => { state.lastActivity = Date.now(); }, { passive: true }));
setInterval(() => {
  if (Vault.unlocked && Date.now() - state.lastActivity > IDLE_LOCK_MS) lockApp();
}, 15000);

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    document.body.classList.add('covered'); // hide contents from the app switcher
    state.hiddenAt = Date.now();
    if (Vault.unlocked && Vault.meta.autoLock === 0) lockApp();
  } else {
    document.body.classList.remove('covered');
    if (Vault.unlocked && state.hiddenAt && Date.now() - state.hiddenAt >= Vault.meta.autoLock * 1000) lockApp();
    state.hiddenAt = 0;
    state.lastActivity = Date.now();
  }
});
window.addEventListener('pagehide', () => document.body.classList.add('covered'));
window.addEventListener('pageshow', () => { if (!document.hidden) document.body.classList.remove('covered'); });

/* ================= Start ================= */

async function boot() {
  if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
    app.innerHTML = '<div class="page center"><h1 class="title">Sam’s Vault must be opened over https://</h1></div>';
    return;
  }
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  try {
    await Vault.load();
  } catch {
    app.innerHTML = '<div class="page center"><h1 class="title">Storage is blocked</h1><p class="lead">Turn off Private Browsing and open Sam’s Vault again.</p></div>';
    return;
  }
  state.bioSupported = await bioSupported();
  replace(Vault.file ? 'unlock' : 'welcome');
}

boot();

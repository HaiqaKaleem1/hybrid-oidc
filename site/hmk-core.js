/* hmk-core.js — pure computation core shared by the demo page (browser) and
 * tools/check_site_core.js (node cross-check against the C implementation).
 *
 * Field combiner: BigInt arithmetic mod p (visualization-grade, NOT the
 * shipped constant-time implementation — that is csrc/gf256.c).
 * linspread: byte-exact port of csrc/linspread.c (M = T^3 over F_2).
 * HMAC-SHA-256: WebCrypto (browser + node both expose crypto.subtle).
 */
"use strict";

const P = (1n << 256n) - (1n << 32n) + 977n;

/* ------------------------------------------------------------ utilities */
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hex16(buf) {
  return hex(buf).slice(0, 32) + "…";
}
function randBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
async function hmacSha256(keyBytes, msgBytes) {
  const key = await globalThis.crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, msgBytes));
}
function concat(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

/* ------------------------------------------- F_p combiner (BigInt model) */
function bytesToBigBE(buf) {
  let x = 0n;
  for (const b of buf) x = (x << 8n) | BigInt(b);
  return x;
}
function bigToBytes32BE(x) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
function fieldCombine(a, b) {
  let x = bytesToBigBE(a) % P;
  let y = bytesToBigBE(b) % P;
  if (x === 0n) x = 1n;           // F_p^* normalization (same rule as C core)
  if (y === 0n) y = 1n;
  return bigToBytes32BE((x * y) % P);
}

/* --------------------------------------- linspread (port of C sources) */
const TAPS = [[1, 13], [2, 11], [4, 31], [5, 47]];
const M64 = 0xffffffffffffffffn;

function rotl64(x, n) {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;
}
function roundT(words) {
  const y = new Array(8);
  for (let i = 0; i < 8; i++) {
    let v = words[i];
    for (const [off, r] of TAPS) v = (v ^ rotl64(words[(i + off) & 7], r)) & M64;
    y[i] = v;
  }
  return y;
}
function linspread(bytes) {
  let w = [];
  for (let i = 0; i < 8; i++) {
    let v = 0n;
    for (let j = 7; j >= 0; j--) v = (v << 8n) | BigInt(bytes[8 * i + j]); // LE words
    w.push(v);
  }
  for (let r = 0; r < 3; r++) w = roundT(w);   // M = T^3
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++)
    for (let j = 0; j < 8; j++)
      out[8 * i + j] = Number((w[i] >> BigInt(8 * j)) & 0xffn);
  return out;
}

/* ------------------------------------------------ comparison strategies */
function ctMemcmp(a, b) {           // full scan, no early exit
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function naiveVerify(a, b) {        // classic short-circuit (vulnerable)
  for (let i = 0; i < a.length; i++)
    if (a[i] !== b[i]) return false;
  return true;
}

/* Export for node cross-check; in the browser these become globals. */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    P, hex, hex16, randBytes, hmacSha256, concat,
    bytesToBigBE, bigToBytes32BE, fieldCombine,
    linspread, ctMemcmp, naiveVerify,
  };
}

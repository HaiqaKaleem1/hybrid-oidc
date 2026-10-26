#!/usr/bin/env node
/* check_site_core.js — cross-checks the browser demo core (site/hmk-core.js)
 * against independently computed vectors:
 *
 *   - linspread: outputs of the C implementation (csrc/linspread.c)
 *   - fieldCombine: Python arbitrary-precision reference (tools/gen_vectors.py
 *     recomputes the same class of vector; the value below is BE-encoded)
 *   - hmacSha256: RFC 4231 test case 1 via WebCrypto
 *   - ctMemcmp / naiveVerify sanity
 *
 * Usage: node tools/check_site_core.js
 */
"use strict";
const path = require("path");
const core = require(path.join(__dirname, "..", "site", "hmk-core.js"));

let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
  if (!ok) {
    console.log("  got  " + got);
    console.log("  want " + want);
    failures++;
  }
}

async function main() {
  // --- linspread vs C ----------------------------------------------------
  const in1 = new Uint8Array(64);
  for (let i = 0; i < 64; i++) in1[i] = i;
  check("linspread(00..3f) matches C core",
    core.hex(core.linspread(in1)),
    "93a734b38cb82bac586cff784773e0677743d057685ccf48fdc95adde2d645c2" +
    "6b5fcc4b7440d354a0940780bf8b189f8fbb28af90a437b00531a2251a2ebd3a");

  const in2 = new Uint8Array(64).fill(0x5a);
  check("linspread(5a×64) matches C core",
    core.hex(core.linspread(in2)),
    "3c".repeat(64));

  // --- fieldCombine vs Python -------------------------------------------
  const A = new Uint8Array(32);
  for (let i = 0; i < 32; i++) A[i] = i;
  const B = new Uint8Array(32);
  for (let i = 0; i < 32; i++) B[i] = 32 + i;
  check("fieldCombine matches Python reference",
    core.hex(core.fieldCombine(A, B)),
    "7875b86bbad0d8fe6c4dce1857b7628447d8610d077b947d616be801684a4d9f");

  // --- HMAC via WebCrypto vs RFC 4231 -----------------------------------
  const key = new Uint8Array(20).fill(0x0b);
  const msg = new TextEncoder().encode("Hi There");
  const mac = await core.hmacSha256(key, msg);
  check("hmacSha256 matches RFC 4231 tc1",
    core.hex(mac),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  // --- comparison helpers ------------------------------------------------
  const x = new Uint8Array([1, 2, 3, 4]);
  const y = new Uint8Array([1, 2, 3, 4]);
  const z = new Uint8Array([1, 9, 3, 4]);
  check("ctMemcmp equal -> true", String(core.ctMemcmp(x, y)), "true");
  check("ctMemcmp differ -> false", String(core.ctMemcmp(x, z)), "false");
  check("naiveVerify differ at byte1 -> false", String(core.naiveVerify(x, z)), "false");

  if (failures) {
    console.log(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nsite core: ALL CHECKS PASSED (matches C + Python references)");
}

main().catch((e) => { console.error(e); process.exit(1); });

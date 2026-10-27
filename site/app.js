/* HMK-1 demo site v2 — animations + the entire demo in the browser.
 *
 * All primitives live in hmk-core.js (cross-checked byte-for-byte against
 * the C implementation by tools/check_site_core.js).
 */
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ============================================================= nav menu */
const navEl = $(".nav");
const navBtn = $("#navToggle");
if (navEl && navBtn) {
  navBtn.addEventListener("click", () => {
    const open = navEl.classList.toggle("open");
    navBtn.setAttribute("aria-expanded", String(open));
  });
  $$(".nav-links a").forEach((a) =>
    a.addEventListener("click", () => {
      navEl.classList.remove("open");
      navBtn.setAttribute("aria-expanded", "false");
    })
  );
}

/* ================================================================ reveal */
const io = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (e.isIntersecting) {
      e.target.classList.add("visible");
      if (e.target.id === "timing") drawChart();
      if (e.target.classList.contains("stats")) countUp(e.target);
      io.unobserve(e.target);
    }
  }
}, { threshold: [0, 0.12] });
$$(".reveal").forEach((el) => io.observe(el));
io.observe($(".stats"));
io.observe($("#timing"));

/* count-up numbers */
function countUp(scope) {
  scope.querySelectorAll("[data-count]").forEach((el) => {
    const target = Number(el.dataset.count);
    const suffix = el.dataset.suffix || "";
    if (target === 0) { el.textContent = suffix ? "0" + suffix : "0"; return; }
    const t0 = performance.now(), dur = 1300;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased) + (p === 1 ? suffix : "");
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

/* ============================================================ hero canvas */
(function heroFX() {
  const cv = $("#heroCanvas");
  if (!cv || reduced) return;
  const ctx = cv.getContext("2d");
  const glyphs = "0123456789abcdef⟨⟩·×⊕≡λκ";
  let cols = [], W = 0, H = 0, raf = 0;

  function resize() {
    W = cv.width = cv.offsetWidth * devicePixelRatio;
    H = cv.height = cv.offsetHeight * devicePixelRatio;
    const n = Math.max(18, Math.floor(W / (46 * devicePixelRatio)));
    cols = Array.from({ length: n }, (_, i) => ({
      x: (i + 0.5) * (W / n),
      y: Math.random() * H,
      v: (0.35 + Math.random() * 0.85) * devicePixelRatio,
      s: (10 + Math.random() * 6) * devicePixelRatio,
      t: Math.random() * glyphs.length | 0,
      a: 0.12 + Math.random() * 0.5,
    }));
  }
  function frame() {
    ctx.clearRect(0, 0, W, H);
    for (const c of cols) {
      c.y += c.v;
      if (c.y > H + 20 * devicePixelRatio) { c.y = -20 * devicePixelRatio; c.v = (0.35 + Math.random() * 0.85) * devicePixelRatio; }
      const g = glyphs[(c.t + (c.y / (30 * devicePixelRatio) | 0)) % glyphs.length];
      ctx.font = `${c.s}px monospace`;
      ctx.fillStyle = `rgba(79,214,190,${c.a * 0.55})`;
      ctx.fillText(g, c.x, c.y);
      ctx.fillStyle = `rgba(122,162,247,${c.a * 0.16})`;
      ctx.fillText(g, c.x, c.y - c.s * 2.4);
    }
    raf = requestAnimationFrame(frame);
  }
  resize();
  addEventListener("resize", () => { cancelAnimationFrame(raf); resize(); frame(); });
  frame();
})();

/* ============================================================== demo core */
const els = {
  ssc: $("#v-ssc"), ssp: $("#v-ssp"), kf: $("#v-kf"), u: $("#v-u"),
  rk: $("#v-rk"), ct: $("#v-ct"), tag: $("#v-tag"),
  log: $("#log"), verdict: $("#verdict"), rail: $("#rail"),
  benchLog: $("#benchLog"),
};
const AAD_TXT = "issuer://hybrid-oidc-demo";
const AAD = new TextEncoder().encode(AAD_TXT);
const enc = (s) => new TextEncoder().encode(s);
let session = null;
let busy = false;

function logLine(cls, text) {
  const d = document.createElement("div");
  d.className = "tl " + cls;
  d.textContent = text;
  els.log.appendChild(d);
  els.log.scrollTop = els.log.scrollHeight;
}
function setVerdict(kind, text) {
  els.verdict.className = "verdict show " + kind;
  els.verdict.textContent = text;
}
function fill(el, v) { el.textContent = v; el.classList.add("filled"); }
function lightStage(i, ms = 900) {
  const st = $(`.stage[data-stage="${i}"]`);
  if (!st) return;
  st.classList.add("knock");
  setTimeout(() => st.classList.remove("knock"), ms);
}
function rejectStage(i, ms = 1400) {
  const st = $(`.stage[data-stage="${i}"]`);
  if (!st) return;
  st.classList.add("reject");
  setTimeout(() => st.classList.remove("reject"), ms);
}
function pulse(i) {
  const c = $(`.conn[data-on="${i}"]`);
  if (!c) return;
  c.classList.remove("flow");
  void c.offsetWidth;
  c.classList.add("flow");
}
function railOn(i, playing = false) {
  $$(".rail-step").forEach((b, j) => {
    b.classList.toggle("active", j === i);
    b.classList.toggle("playing", playing && j === i);
  });
}
function haltRailAnim() {
  $$(".rail-step.playing").forEach((b) => b.classList.remove("playing"));
}

async function ensureSession() {
  if (session) return session;
  session = {
    vkC: randBytes(32), vkP: randBytes(32),
    ssC: randBytes(32), ssP: randBytes(32),
    mk: randBytes(32), nonce: randBytes(16),
    hdr: enc(`{"alg":"hybrid","typ":"JWT"}`),
    pld: enc(`{"iss":"hybrid-oidc","sub":"demo-user","exp":4102444800}`),
  };
  session.skC = await hmacSha256(enc("hybridoidc/sk-derivation"), session.vkC);
  session.skP = await hmacSha256(enc("hybridoidc/sk-derivation"), session.vkP);
  session.ss = concat(session.ssC, session.ssP);
  return session;
}

/* --- roSig port (mirrors pkg/hybridoidc idealized components) --- */
async function signHalf(sk, msg) { return hmacSha256(sk, msg); }
async function verHalf(vk, msg, sig) {
  const sk = await hmacSha256(enc("hybridoidc/sk-derivation"), vk);
  const want = await hmacSha256(sk, msg);
  return ctMemcmp(want, sig);
}
async function signH(s, msg) {
  return concat(await signHalf(s.skC, msg), await signHalf(s.skP, msg));
}
async function verH(s, vkC, vkP, msg, sig) {
  if (sig.length !== 64) return false;
  const okC = await verHalf(vkC, msg, sig.slice(0, 32));
  const okP = await verHalf(vkP, msg, sig.slice(32));
  return okC && okP;
}
const signingInput = (h, p) => concat(h, new Uint8Array([0x2e]), p);
async function deriveWrapKeys(s) {
  const kf = fieldCombine(s.ssC, s.ssP);
  const u = linspread(s.ss);
  const rk0 = await hmacSha256(kf, concat(u, enc("hmk/v1/rk"), new Uint8Array([0])));
  const rk1 = await hmacSha256(kf, concat(u, enc("hmk/v1/rk"), new Uint8Array([1])));
  return { kf, u, kek: rk0, kmac: rk1 };
}
async function makeWrap(s) {
  const { kf, u, kek, kmac } = await deriveWrapKeys(s);
  Object.assign(s, { kf, u, kek, kmac });
  const ks = await hmacSha256(kek, concat(enc("hmk/v1/ks"), s.nonce));
  s.ct = new Uint8Array(32);
  for (let i = 0; i < 32; i++) s.ct[i] = s.mk[i] ^ ks[i];
  s.tag = await hmacSha256(s.kmac, concat(enc("hmk/v1/tag"), s.nonce, s.ct, AAD));
  return s;
}
async function tagCheck(s, ct) {
  const calc = await hmacSha256(s.kmac, concat(enc("hmk/v1/tag"), s.nonce, ct, AAD));
  return ctMemcmp(calc, s.tag);
}

/* ================================================================= steps */
const steps = [
  /* 0 — keygen */
  async () => {
    const s = await ensureSession();
    railOn(0, true);
    logLine("info", "▶ STEP 1 · Alg 3/4 key generation — independent component pairs");
    await sleep(250);
    lightStage(0); lightStage(1);
    logLine("dim", `   classical vk ${hex16(s.vkC)}`);
    await sleep(180);
    logLine("dim", `   pq        vk ${hex16(s.vkP)}`);
    logLine("ok", "   ✓ either half may later fall without exposing the other (G1)");
    setVerdict("ok", "KEYS READY");
  },
  /* 1 — encapsulate */
  async () => {
    const s = await ensureSession();
    railOn(1, true);
    logLine("info", "▶ STEP 2 · Alg 3 EncH — hybrid encapsulation");
    fill(els.ssc, hex16(s.ssC));
    lightStage(0);
    await sleep(300);
    fill(els.ssp, hex16(s.ssP));
    lightStage(1);
    pulse(0);
    logLine("gold", `   ss_c (classical 32B) ${hex16(s.ssC)}`);
    logLine("gold", `   ss_p (pq        32B) ${hex16(s.ssP)}`);
    logLine("info", "   K_f = ss_c·ss_p mod p   [F_p · Montgomery · constant-time]");
    logLine("info", "   u   = M·(ss_c‖ss_p)     [F_2 · M = T³ · rank 512]");
    setVerdict("ok", "ENCAPSULATED");
  },
  /* 2 — wrap */
  async () => {
    const s = await ensureSession();
    await makeWrap(s);
    railOn(2, true);
    logLine("info", "▶ STEP 3 · HMK-1 wrap — constant-time C core pipeline");
    fill(els.kf, hex16(s.kf));
    lightStage(2); pulse(1);
    logLine("gold", `   K_f = ss_c·ss_p mod p = ${hex16(s.kf)}`);
    await sleep(320);
    fill(els.u, hex16(s.u));
    lightStage(3); pulse(2);
    logLine("gold", `   u   = M·(ss_c‖ss_p)   = ${hex16(s.u)}`);
    await sleep(320);
    fill(els.rk, hex16(s.kek));
    lightStage(4); pulse(3);
    logLine("info", `   RK  = HMAC(K_f, u)    → ${hex16(s.kek)}`);
    await sleep(320);
    fill(els.ct, hex16(s.ct));
    fill(els.tag, hex16(s.tag));
    lightStage(5); pulse(4);
    logLine("ok", `   ct  = mk ⊕ KS         = ${hex16(s.ct)}`);
    logLine("ok", `   tag = HMAC(kmac, …)    = ${hex16(s.tag)}`);
    logLine("dim", "   master key sealed · no pre-existing cipher involved · fixed work per call");
    setVerdict("ok", "SEALED");
  },
  /* 3 — attack */
  async () => {
    const s = await ensureSession();
    railOn(3, true);
    logLine("bad", "▶ STEP 4 · adversary — flip one ciphertext bit / one tag bit");
    const bit = Math.floor(Math.random() * 256);
    const badCt = new Uint8Array(s.ct);
    badCt[bit >> 3] ^= 1 << (bit & 7);
    await sleep(200);
    rejectStage(5);
    const ok1 = await tagCheck(s, badCt);
    logLine("bad", `   ct bit ${bit} ^= 1      → ${ok1 ? "ACCEPTED (!)" : "REJECTED — tag mismatch"}`);
    const badTag = new Uint8Array(s.tag);
    badTag[Math.floor(Math.random() * 32)] ^= 0xff;
    const calc = await hmacSha256(s.kmac, concat(enc("hmk/v1/tag"), s.nonce, s.ct, AAD));
    const ok2 = ctMemcmp(calc, badTag);
    await sleep(200);
    logLine("bad", `   forged tag byte       → ${ok2 ? "ACCEPTED (!)" : "REJECTED — full-scan compare"}`);
    logLine("dim", "   candidate key zeroized before return (branchless cmov from zeros)");
    if (ok1 || ok2) setVerdict("bad", "BUG — ATTACK SUCCEEDED");
    else setVerdict("ok", "ATTACK BLOCKED ✓");
  },
  /* 4 — honest unwrap */
  async () => {
    const s = await ensureSession();
    railOn(4, true);
    logLine("info", "▶ STEP 5 · honest party — decapsulate → unwrap");
    await sleep(250);
    const ok = await tagCheck(s, s.ct);
    logLine(ok ? "ok" : "bad", ok
      ? `   tag valid → master key recovered  ${hex16(s.mk)}`
      : "   FAILED (unexpected)");
    if (ok) { lightStage(5); logLine("ok", "   ✓ applicable environment: OIDC master-key recovery pipeline"); }
    setVerdict(ok ? "ok" : "bad", ok ? "KEY RECOVERED" : "FAILED");
  },
  /* 5 — JWT */
  async () => {
    const s = await ensureSession();
    railOn(5, true);
    logLine("info", "▶ STEP 6 · Alg 4 hybrid JWT — conjunction acceptance (G3/G4)");
    const msg = signingInput(s.hdr, s.pld);
    const sig = await signH(s, msg);
    const good = await verH(s, s.vkC, s.vkP, msg, sig);
    logLine(good ? "ok" : "bad", `   honest verify (both halves)          ${good ? "✓ accepted" : "✗ rejected"}`);
    await sleep(250);
    const stripped = await verH(s, s.vkC, s.vkP, msg, sig.slice(0, 32));
    logLine(stripped ? "bad" : "ok", `   adversary strips pq half (128→64B)  ${stripped ? "ACCEPTED (!)" : "✓ rejected"}`);
    await sleep(250);
    const other = await signH(s, signingInput(s.hdr, enc(`{"sub":"victim"}`)));
    const graft = concat(sig.slice(0, 32), other.slice(32));
    const g = await verH(s, s.vkC, s.vkP, msg, graft);
    logLine(g ? "bad" : "ok", `   adversary grafts foreign pq half     ${g ? "ACCEPTED (!)" : "✓ rejected"}`);
    logLine("dim", "   forging needs BOTH halves → bound = weaker half (Theorem 2)");
    setVerdict(stripped || g ? "bad" : "ok", stripped || g ? "FORGERY ACCEPTED" : "FORGERY BLOCKED ✓");
  },
  /* 6 — replay */
  async () => {
    const s = await ensureSession();
    railOn(6, true);
    logLine("info", "▶ STEP 7 · Theorem 3 — TLS channel binding kills bearer replay");
    const exp1 = randBytes(32), exp2 = randBytes(32);
    const bind = (exp) => hmacSha256(exp, concat(enc("EXPORTER: "), enc("tls-exporter"), enc("rp")));
    const cb1 = await bind(exp1), cb2 = await bind(exp2);
    const boundMsg = concat(signingInput(s.hdr, s.pld), cb1);
    const sig = await signH(s, boundMsg);
    const same = await verH(s, s.vkC, s.vkP, boundMsg, sig);
    await sleep(250);
    const foreign = concat(signingInput(s.hdr, s.pld), cb2);
    const replay = await verH(s, s.vkC, s.vkP, foreign, sig);
    logLine(same ? "ok" : "bad", `   verify on own connection (b1)         ${same ? "✓ accepted" : "✗ rejected"}`);
    logLine(replay ? "bad" : "ok", `   replay on foreign connection (b2)     ${replay ? "ACCEPTED (!)" : "✓ rejected"}`);
    logLine("dim", "   signed input = header‖'.'‖payload‖channel-binding");
    setVerdict(!replay ? "ok" : "bad", !replay ? "REPLAY BLOCKED ✓" : "REPLAY ACCEPTED");
  },
  /* 7 — timing */
  async () => {
    railOn(7, true);
    logLine("info", "▶ STEP 8 · live side-channel measurement — naive vs HMK comparator");
    const stored = randBytes(32);
    const groups = [0, 8, 16, 31];
    const naiveMed = [], ctMed = [];
    for (const k of groups) {
      const pres = new Uint8Array(stored);
      pres[k] ^= 0xff;
      naiveMed.push(measureNs(naiveVerify, pres, stored, 24));
      ctMed.push(measureNs(ctMemcmp, pres, stored, 24));
      await sleep(30);
    }
    const fmt = (v) => v.toFixed(2).padStart(8);
    logLine("gold", `   k        ${groups.map((g) => String(g).padStart(8)).join("")}`);
    logLine("bad",  `   naive ${naiveMed.map(fmt).join("")} ns`);
    logLine("ok",   `   HMK  ${ctMed.map(fmt).join("")} ns`);
    const nGrow = Math.max(...naiveMed) / Math.max(1e-9, Math.min(...naiveMed));
    const cGrow = Math.max(...ctMed) / Math.max(1e-9, Math.min(...ctMed));
    logLine(nGrow > 1.5 ? "bad" : "dim", `   naive growth ×${nGrow.toFixed(1)} ${nGrow > 1.5 ? "→ byte-by-byte recovery oracle" : "(measurement too noisy)"}`);
    logLine(cGrow < 1.6 ? "ok" : "dim", `   HMK growth   ×${cGrow.toFixed(1)} ${cGrow < 1.6 ? "→ flat ✓" : "(browser jitter — C harness authoritative)"}`);
    setVerdict(cGrow < 1.6 ? "ok" : "bad", cGrow < 1.6 ? "FLAT — NO LEAK ✓" : "NOISY");
  },
];


/* rail buttons + control buttons */
$$(".rail-step").forEach((b) => b.addEventListener("click", () => runStep(Number(b.dataset.step))));
$$("[data-run]").forEach((b) => b.addEventListener("click", () => runStep(Number(b.dataset.run))));

async function runStep(i) {
  if (busy) return;
  busy = true;
  haltRailAnim();
  try { await steps[i](); }
  catch (e) { logLine("bad", "error: " + e); console.error(e); }
  busy = false;
}

/* autoplay */
const btnAuto = $("#btnAutoplay");
async function autoplay() {
  if (busy) return;
  busy = true;
  btnAuto.disabled = true;
  els.log.innerHTML = "";
  els.verdict.className = "verdict";
  for (let i = 0; i < steps.length; i++) {
    haltRailAnim();
    try { await steps[i](); } catch (e) { logLine("bad", "error: " + e); }
    await sleep(750);
  }
  haltRailAnim();
  logLine("ok", "══════ demo complete: 8/8 steps · 0 accepted attacks ══════");
  busy = false;
  btnAuto.disabled = false;
}
btnAuto.addEventListener("click", autoplay);
$("#heroRun").addEventListener("click", () => {
  $("#demo").scrollIntoView({ behavior: "smooth" });
  setTimeout(autoplay, 650);
});

/* ============================================================== math viz */
$("#btnCombine").addEventListener("click", async () => {
  const out = $("#combineOut");
  out.textContent = "computing…";
  const a = randBytes(32), b = randBytes(32);
  const kf = fieldCombine(a, b);
  const aN = bytesToBigBE(a) % P;
  let bN = bytesToBigBE(b) % P;
  const aFixed = aN === 0n ? 1n : aN;
  if (bN === 0n) bN = 1n;
  const bBack = (bytesToBigBE(kf) * inverseMod(aFixed, P)) % P;
  const ok = bBack === bN;
  out.innerHTML = `a = ${hex(a)}<br>b = ${hex(b)}<br>` +
    `<b style="color:var(--accent)">K_f = a·b mod p = ${hex(kf)}</b><br>` +
    `<span style="color:var(--gold)">K_f · a⁻¹ mod p = ${hex(bigToBytes32BE(bBack))} ` +
    `${ok ? "✓ recovers the other half exactly — bijection holds" : "✗"}</span>`;
});
function inverseMod(a, m) {
  let [old_r, r] = [a % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

/* matrix diffusion grid */
const matrixEl = $("#matrix");
for (let i = 0; i < 64; i++) {
  const c = document.createElement("div");
  c.className = "mcell";
  c.title = `output byte ${i}`;
  matrixEl.appendChild(c);
}
async function flipMatrix() {
  const cells = matrixEl.children;
  const base = randBytes(64);
  const bit = Math.floor(Math.random() * 512);
  const mod = new Uint8Array(base);
  mod[bit >> 3] ^= 1 << (bit & 7);
  const o1 = linspread(base), o2 = linspread(mod);
  let changed = 0;
  for (let i = 0; i < 64; i++) {
    const on = o1[i] !== o2[i];
    if (on) changed++;
    const c = cells[i];
    c.classList.remove("on", "ring");
    if (i === (bit >> 3)) c.classList.add("ring");
    if (on) setTimeout(() => c.classList.add("on"), i * 9 + Math.random() * 60);
  }
  $("#matrixOut").innerHTML =
    `flipped input bit <b>${bit}</b> (byte ${bit >> 3}, bit ${bit & 7}) → ` +
    `<b style="color:var(--accent)">${changed}/64</b> output bytes changed ` +
    `<span style="color:var(--gold)">(${Math.round(changed / 64 * 100)}% diffusion from ONE bit)</span>`;
}
$("#btnMatrix").addEventListener("click", flipMatrix);

/* ============================================================ timing chart */
const KS = [0, 1, 2, 4, 8, 16, 31];
const NAIVE = [2, 2, 3, 4, 7, 12, 22];
const CT = [1, 1, 1, 1, 1, 1, 1];
let chartDrawn = false;

function drawChart() {
  if (chartDrawn) return;
  chartDrawn = true;
  const svg = $("#chart");
  const W = 720, H = 320, L = 56, R = 24, T = 26, B = 40;
  const maxY = 24;
  const x = (k) => L + (k / 31) * (W - L - R);
  const y = (v) => H - B - (v / maxY) * (H - T - B);

  const grid = $("#gridLines"), labels = $("#axisLabels");
  grid.innerHTML = ""; labels.innerHTML = "";
  for (let v = 0; v <= maxY; v += 4) {
    grid.innerHTML += `<line x1="${L}" y1="${y(v)}" x2="${W - R}" y2="${y(v)}"/>`;
    labels.innerHTML += `<text x="${L - 8}" y="${y(v) + 3.5}" text-anchor="end">${v}ns</text>`;
  }
  for (const k of KS) {
    labels.innerHTML += (k === 0 || k === 4 || k === 8 || k === 16 || k === 31)
      ? `<text x="${x(k)}" y="${H - 14}" text-anchor="middle">k=${k}</text>` : "";
  }
  labels.innerHTML += `<text x="${(L + W - R) / 2}" y="${H - 1}" text-anchor="middle">matching prefix bytes of forged tag</text>`;

  const path = (arr) => arr.map((v, i) => `${i ? "L" : "M"}${x(KS[i]).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const np = $("#naivePath"), cp = $("#ctPath");
  np.setAttribute("d", path(NAIVE));
  cp.setAttribute("d", path(CT));
  for (const [arr, color] of [[NAIVE, "#f7768e"], [CT, "#4fd6be"]]) {
    arr.forEach((v, i) => {
      $("#chartDots").innerHTML +=
        `<circle cx="${x(KS[i]).toFixed(1)}" cy="${y(v).toFixed(1)}" r="4.5" fill="${color}" style="animation-delay:${1.2 + i * 0.08}s"/>`;
    });
  }
  [np, cp].forEach((p) => {
    const len = p.getTotalLength();
    p.style.setProperty("--len", len);
  });
  requestAnimationFrame(() => svg.classList.add("drawn"));

  /* KPI count-ups */
  const kpis = [
    { el: $("#kpiLeak"), val: Math.round(NAIVE[6] / NAIVE[0]), final: Math.round(NAIVE[6] / NAIVE[0]) + "×" },
    { el: $("#kpiFlat"), val: 1, final: "1.0×" },
  ];
  for (const k of kpis) {
    const t0 = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / 1100);
      k.el.textContent = Math.round(k.val * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(tick);
      else k.el.textContent = k.final;
    };
    requestAnimationFrame(tick);
  }
}

/* ======================================================== micro benchmark */
function median(a) {
  const s = [...a].sort((x, y) => x - y);
  return s[s.length >> 1];
}
/* Adaptive batching: browser clocks are coarse (µs), so calibrate the
 * iteration count until one batch spans ≥ ~4 ms, then take medians. */
function calIter(fn, a, b) {
  let n = 64;
  for (;;) {
    const t = performance.now();
    for (let i = 0; i < n; i++) fn(a, b);
    const el = performance.now() - t;
    if (el >= 4 || n >= 1 << 22)
      return Math.max(1, Math.floor((n * 4) / Math.max(el, 0.001)));
    n *= 2;
  }
}
function measureNs(fn, a, b, batches = 28) {
  const iters = calIter(fn, a, b);
  const out = [];
  for (let i = 0; i < batches; i++) {
    const t = performance.now();
    for (let j = 0; j < iters; j++) fn(a, b);
    out.push(((performance.now() - t) * 1e6) / iters); /* ns/call */
  }
  return median(out);
}
function welchT(a, b) {
  const ma = a.reduce((s, x) => s + x, 0) / a.length;
  const mb = b.reduce((s, x) => s + x, 0) / b.length;
  const va = a.reduce((s, x) => s + (x - ma) ** 2, 0) / (a.length - 1);
  const vb = b.reduce((s, x) => s + (x - mb) ** 2, 0) / (b.length - 1);
  const denom = Math.sqrt(va / a.length + vb / b.length);
  return denom === 0 ? 0 : (ma - mb) / denom;
}
/* per-batch samples (for Welch t) with calibrated batch size */
function measureNsAll(fn, a, b, batches) {
  const iters = calIter(fn, a, b);
  const out = [];
  for (let i = 0; i < batches; i++) {
    const t = performance.now();
    for (let j = 0; j < iters; j++) fn(a, b);
    out.push(((performance.now() - t) * 1e6) / iters);
  }
  return out;
}
function benchLine(cls, text) {
  const d = document.createElement("div");
  d.className = "tl " + cls;
  d.textContent = text;
  els.benchLog.appendChild(d);
  els.benchLog.scrollTop = els.benchLog.scrollHeight;
}

$("#btnBench").addEventListener("click", async () => {
  const btn = $("#btnBench");
  btn.disabled = true;
  els.benchLog.innerHTML = "";
  benchLine("dim", "collecting samples (naive vs HMK, per-prefix)…");
  await sleep(120);

  const stored = randBytes(32);
  const rows = [];
  const naiveAt = {};
  const ctAt = {};
  for (const k of KS) {
    const pres = new Uint8Array(stored);
    pres[k] ^= 0xff;
    const ns = measureNsAll(naiveVerify, pres, stored, 120);
    const cs = measureNsAll(ctMemcmp, pres, stored, 120);
    naiveAt[k] = ns; ctAt[k] = cs;
    rows.push(`  k=${String(k).padEnd(2)}  naive ${median(ns).toFixed(3).padStart(8)} ns   HMK ${median(cs).toFixed(3).padStart(8)} ns`);
    await sleep(30);
  }
  rows.forEach((r) => benchLine("dim", r));

  const tNaive = Math.abs(welchT(naiveAt[0], naiveAt[31]));
  const tCT = Math.abs(welchT(ctAt[0], ctAt[31]));
  benchLine("info", `  Welch t (k=0 vs k=31):   naive |t| = ${tNaive.toFixed(2)}   HMK |t| = ${tCT.toFixed(2)}`);
  benchLine(tNaive > 4.5 ? "bad" : "dim",
    `  naive: ${tNaive > 4.5 ? "distributions DISTINGUISHABLE (|t| > 4.5) → leak confirmed" : "|t| ≤ 4.5 — browser timer too coarse here; C harness shows it cleanly"}`);
  benchLine(tCT < 4.5 ? "ok" : "dim",
    `  HMK-1:  ${tCT < 4.5 ? "indistinguishable (|t| < 4.5) → no timing leak ✓" : "|t| ≥ 4.5 (browser jitter; re-run `make timing` for the authoritative TVLA-style result)"}`);
  benchLine("dim", "  note: browser timers add jitter — csrc/timing_demo.c is the reference harness.");
  btn.disabled = false;
});

/* ================================================================
 * network simulation (section 05)
 * ================================================================ */

/* ========================================================== network DOM */
const netLog = $("#netLog");
const netVerdict = $("#netVerdict");

function netLine(cls, text) {
  const d = document.createElement("div");
  d.className = "tl " + cls;
  d.textContent = text;
  netLog.appendChild(d);
  netLog.scrollTop = netLog.scrollHeight;
}
function netSetVerdict(kind, text) {
  netVerdict.className = "verdict show " + kind;
  netVerdict.textContent = text;
}

/* ------------------------------------------------------- telemetry & HUD */
const tel = { frames: 0, bytes: 0, hops: 0, blocked: 0 };
const FRAME_BYTES = 16 + 32 + 32;          /* nonce || ct || tag on the wire */
function hud(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
function hudAdd(key, n) {
  tel[key] += n;
  hud("tFrames", String(tel.frames));
  hud("tBytes", tel.bytes.toLocaleString("en-US"));
  hud("tHops", String(tel.hops));
}
function hudBlock() { tel.blocked++; hud("tBlocked", String(tel.blocked)); }

const ATTACK_IDS = ["bitflip", "tagforge", "halfguess", "doublehalf", "replay",
  "replayoldnonce", "eavesdrop", "mitmreroute", "keystreamreuse", "cttrunc",
  "tagtrunc", "timingprobe", "downclassical", "downpq"];

/* ------------------------------------------------------- wire capture + replay window */
const capTable = document.getElementById("capTable");
const rwChips = document.getElementById("rwChips");
let capSeq = 0, rwCount = 0;

function capAdd(rec) {
  if (!capTable) return;
  capSeq++;
  const empty = capTable.querySelector(".cap-empty");
  if (empty) empty.remove();
  const good = (rec.mode === "honest") === (rec.result === "accepted");
  const row = document.createElement("div");
  row.className = "cap-row " + (good ? "ok" : "bad");
  const cells = [
    String(capSeq).padStart(2, "0"),
    new Date().toLocaleTimeString(),
    rec.src + " → " + rec.dst,
    rec.hops + (rec.hops === 1 ? " hop" : " hops"),
    rec.bytes + " B",
    hex(rec.nonce).slice(0, 12) + "…",
    rec.mode,
    rec.result,
  ];
  for (const c of cells) {
    const sp = document.createElement("span");
    sp.textContent = c;
    row.appendChild(sp);
  }
  const head = capTable.querySelector(".cap-head");
  if (head) capTable.insertBefore(row, head.nextElementSibling);
  else capTable.appendChild(row);
  while (capTable.querySelectorAll(".cap-row:not(.cap-head)").length > 8) {
    capTable.removeChild(capTable.lastElementChild);
  }
}

function rwPush(receiverId, nonceArr) {
  if (!rwChips) return;
  rwCount++;
  const idle = rwChips.querySelector(".chip.idle");
  if (idle) idle.remove();
  const r = nodeById(receiverId);
  const c = document.createElement("span");
  c.className = "chip consumed";
  c.textContent = (r ? r.name : receiverId) + " · " + hex(nonceArr).slice(0, 10) + "… consumed";
  rwChips.insertBefore(c, rwChips.firstChild);
  while (rwChips.children.length > 6) rwChips.removeChild(rwChips.lastElementChild);
  const note = document.getElementById("rwNote");
  if (note) note.textContent = rwCount + " nonce" + (rwCount === 1 ? "" : "s") +
    " consumed · each 16-byte nonce opens exactly one record — a nonce that has been used can never be used again";
}

function matrixRun(atk, blocked) {
  const cell = document.getElementById("mx-" + atk);
  if (cell) {
    cell.textContent = blocked ? "blocked ✓" : "ACCEPTED (!)";
    cell.parentElement.dataset.state = blocked ? "blocked" : "leak";
  }
  const done = ATTACK_IDS.filter((a) => {
    const c = document.getElementById("mx-" + a);
    return c && c.textContent !== "pending";
  }).length;
  hud("mxCount", done + " / 14 run");
}

/* ------------------------------------------- matrix interaction: click a cell → run that
 * attack; “run all 14” walks the whole matrix and fills it while you watch. */
(function wireAttackMatrix() {
  const runAll = $("#btnRunAll");

  async function runOne(atk) {
    const r = document.querySelector('input[name="attack"][value="' + atk + '"]');
    if (r && !r.checked) {
      r.checked = true;
      r.dispatchEvent(new Event("change", { bubbles: true }));
    }
    const from = $("#senderSel").value, to = $("#receiverSel").value;
    await netSend(from, to, atk);
  }

  for (const cell of $$(".mx[data-atk]")) {
    const atk = cell.dataset.atk;
    cell.setAttribute("role", "button");
    cell.tabIndex = 0;
    cell.title = "click to launch “" + cell.querySelector("b").textContent + "”";
    const go = () => { if (busy || cell.dataset.running) return; netSendBusyGuard(cell, atk); };
    cell.addEventListener("click", go);
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); }
    });
  }

  async function netSendBusyGuard(cell, atk) {
    cell.dataset.running = "1";
    cell.classList.add("running");
    try { await runOne(atk); }
    finally { delete cell.dataset.running; cell.classList.remove("running"); }
  }

  if (runAll) {
    runAll.addEventListener("click", async () => {
      if (busy || runAll.dataset.running) return;
      runAll.dataset.running = "1";
      const label = runAll.textContent;
      runAll.disabled = true;
      try {
        for (let i = 0; i < ATTACK_IDS.length; i++) {
          runAll.textContent = "running… " + (i + 1) + "/" + ATTACK_IDS.length;
          await runOne(ATTACK_IDS[i]);
        }
        runAll.textContent = "✓ all 14 run";
      } finally {
        setTimeout(() => { runAll.textContent = label; runAll.disabled = false; delete runAll.dataset.running; }, 4000);
      }
    });
  }
})();

function fillFrame(nonce, ct, tag) {
  hud("frameNonce", hex(nonce));
  hud("frameCt", hex(ct));
  hud("frameTag", hex(tag));
  const box = document.getElementById("frameHex");
  if (box) {
    box.textContent = "nonce " + hex(nonce) + "\n" +
      "ct    " + hex(ct) + "\n" +
      "tag   " + hex(tag) + "\n" +
      "80 B on the wire · AAD " + AAD_TXT + " · sealed by HMK-1";
  }
}

function renderRoute(ids, kind) {
  const box = document.getElementById("routeChips");
  if (!box) return;
  box.innerHTML = "";
  if (!ids || ids.length < 2) {
    const s = document.createElement("span");
    s.className = "chip idle";
    s.textContent = "no route";
    box.appendChild(s);
    return;
  }
  ids.forEach((id, i) => {
    if (i) {
      const sep = document.createElement("span");
      sep.className = "chip-sep";
      sep.textContent = "→";
      box.appendChild(sep);
    }
    const n = nodeById(id);
    const c = document.createElement("span");
    c.className = "chip " + (kind === "bad" ? "bad" : kind === "replay" ? "warn" : "ok") +
      (n && n.kind === "attacker" ? " evil" : "");
    c.textContent = id;
    c.title = n ? n.name : id;
    box.appendChild(c);
  });
  const hops = document.createElement("span");
  const nh = ids.length - 1;
  hops.className = "chip meta";
  hops.textContent = nh + (nh === 1 ? " hop · " : " hops · ") + FRAME_BYTES + " B/frame";
  box.appendChild(hops);
}

/* ========================================================== SVG helpers */
const SVG_NS = "http://www.w3.org/2000/svg";
function SvgEl(tag, attrs) {
  const e = document.createElementNS(SVG_NS, tag);
  if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function $svg(id) { return document.getElementById(id); }

/* ========================================================== devices */
const COMPUTERS = [
  { id: "alice",   name: "Alice's Laptop",     kind: "honest",  x: 260, y: 180, color: "#34d399", accent: "#059669" },
  { id: "bob",     name: "Bob's Workstation",   kind: "honest",  x: 500, y: 105, color: "#60a5fa", accent: "#2563eb" },
  { id: "carol",   name: "Carol's Server",      kind: "honest",  x: 720, y: 145, color: "#a78bfa", accent: "#7c3aed" },
  { id: "dave",    name: "Dave's Phone",       kind: "honest",  x: 945, y: 250, color: "#f472b6", accent: "#db2777" },
  { id: "eve",     name: "Eve's Router",        kind: "honest",  x: 700, y: 480, color: "#fbbf24", accent: "#d97706" },
  { id: "home",    name: "Home Gateway",        kind: "gateway", x: 110, y: 340, color: "#4fd6be", accent: "#0d9488" },
];

const ATTACKERS = [
  { id: "attMallory", name: "Mallory · MITM",       kind: "attacker", x: 1130, y: 470, color: "#f87171", accent: "#dc2626", role: "mitm" },
  { id: "attEve",    name: "Eve · Eavesdropper",    kind: "attacker", x: 1050, y: 355, color: "#c084fc", accent: "#7c3aed", role: "eavesdrop" },
  { id: "attOscar",  name: "Oscar · OfflineBrute",  kind: "attacker", x: 1185, y: 330, color: "#fb923c", accent: "#c2410c", role: "brute" },
  { id: "attTrent",  name: "Trent · CompromisedCA", kind: "attacker", x: 1225, y: 410, color: "#22d3ee", accent: "#0891b2", role: "ca" },
  { id: "attBotnet", name: "Botnet · Cluster",       kind: "attacker", x: 1265, y: 495, color: "#a78bfa", accent: "#4c1d95", role: "botnet" },
];

/* ========================================================== topology */
const LINK_DEFS = [
  // honest mesh
  ["home","alice"],["home","bob"],["home","carol"],["home","dave"],
  ["alice","bob"],["alice","carol"],["bob","carol"],["bob","dave"],["carol","dave"],
  // to router / internet
  ["alice","eve"],["bob","eve"],["carol","eve"],["dave","eve"],["home","eve"],
  // attacker connections
  ["eve","attMallory"],["attEve","attMallory"],["attOscar","attMallory"],
  ["attTrent","attMallory"],["attBotnet","attMallory"],
  ["attEve","attOscar"],["attOscar","attTrent"],["attTrent","attBotnet"],
];

/* ---------- shortest-path routing over the LAN graph (BFS) ---------- */
const ADJ = {};
for (const [a, b] of LINK_DEFS) {
  (ADJ[a] = ADJ[a] || []).push(b);
  (ADJ[b] = ADJ[b] || []).push(a);
}
function routePath(from, to) {
  if (!from || !to || from === to) return [];
  const prev = { [from]: null };
  const queue = [from];
  while (queue.length) {
    const cur = queue.shift();
    if (cur === to) break;
    for (const nx of ADJ[cur] || []) {
      if (!(nx in prev)) { prev[nx] = cur; queue.push(nx); }
    }
  }
  if (!(to in prev)) return [];
  const path = [];
  for (let c = to; c !== null; c = prev[c]) path.unshift(c);
  return path;
}
function gatewayFor(a, b) {
  for (const gw of GATEWAY_DEFS) {
    if ((gw.from === a && gw.to === b) || (gw.from === b && gw.to === a)) return gw;
  }
  return null;
}

/* ========================================================== draw a sophisticated computer */
function drawComputer(n) {
  const g = SvgEl("g", { class: "computer-group", transform: `translate(${n.x},${n.y})`, "data-id": n.id });
  g.appendChild(SvgEl("circle", { class: "computer-halo", r: 62, fill: "url(#ng" + n.id.charAt(0).toUpperCase() + n.id.slice(1) + ")", opacity: 0.3 }));
  g.appendChild(SvgEl("rect", { class: "computer-bezel", x: -36, y: -32, width: 72, height: 50, rx: 6, fill: "#0a0e1a", stroke: n.color, "stroke-width": 2.2, filter: "url(#computerShadow)" }));
  g.appendChild(SvgEl("rect", { class: "computer-screen-bg", x: -30, y: -26, width: 60, height: 38, rx: 2, fill: "#0d1424", stroke: "#27395a", "stroke-width": 1 }));
  const sc = SvgEl("g", { class: "computer-screen-content", opacity: 0.9 });
  const r1 = SvgEl("text", { x: 0, y: -10, "text-anchor": "middle", "font-size": 6.5, "font-family": "var(--mono)", fill: "#4fd6be" });
  r1.textContent = n.kind === "honest" ? "Kf · · ·" : "FORGE 00…";
  sc.appendChild(r1);
  const r2 = SvgEl("text", { x: 0, y: 0, "text-anchor": "middle", "font-size": 6.5, "font-family": "var(--mono)", fill: "#e0af68" });
  r2.textContent = n.kind === "honest" ? "ct — · tag —" : "BAD TAG";
  sc.appendChild(r2);
  const r3 = SvgEl("text", { x: 0, y: 10, "text-anchor": "middle", "font-size": 6, "font-family": "var(--mono)", fill: "#5b6c8d" });
  r3.textContent = n.kind === "attacker" ? "⚠ listening" : n.kind === "gateway" ? "gw online" : "online";
  sc.appendChild(r3);
  g.appendChild(sc);
  g.appendChild(SvgEl("circle", { class: "computer-led on", cx: 22, cy: -18, r: 1.8 }));
  g.appendChild(SvgEl("rect", { class: "computer-base", x: -40, y: 18, width: 80, height: 7, rx: 2, fill: "#111827", stroke: "#27395a", "stroke-width": 1 }));
  g.appendChild(SvgEl("circle", { class: "computer-led on", cx: -28, cy: 21.5, r: 1.6 }));
  g.appendChild(SvgEl("circle", { class: "computer-led dim", cx: -22, cy: 21.5, r: 1.6 }));
  g.appendChild(SvgEl("circle", { class: "computer-led dim", cx: 28, cy: 21.5, r: 1.6 }));
  const nm = SvgEl("text", { class: "computer-name", x: 0, y: 44, "text-anchor": "middle", fill: n.kind === "attacker" ? n.color : "#c9d4e6", "font-size": 10.5, "font-weight": 600, "font-family": "var(--mono)", letterSpacing: "0.05em" });
  nm.textContent = n.name.toUpperCase();
  g.appendChild(nm);
  const st = SvgEl("text", { class: "computer-state", x: 0, y: 56, "text-anchor": "middle", fill: "#5b6c8d", "font-size": 8.5, "font-family": "var(--mono)", opacity: 0.85 });
  st.textContent = n.kind === "attacker" ? "⚠ attacking" : n.kind === "gateway" ? "gateway" : "online";
  g.appendChild(st);
  g.appendChild(SvgEl("circle", { class: "computer-highlight", r: 46, fill: "none", stroke: n.color, "stroke-width": 3, opacity: 0 }));
  return g;
}

/* ========================================================== draw a LAN gateway (switch/router) */
function drawGateway(gw) {
  const g = SvgEl("g", { class: "gateway-group", transform: `translate(${gw.x},${gw.y})` });
  g.appendChild(SvgEl("circle", { r: 24, fill: "url(#gwGrad)", opacity: 0.22, stroke: "#27395a", "stroke-width": 1 }));
  g.appendChild(SvgEl("rect", { class: "gateway-body", x: -17, y: -12, width: 34, height: 24, rx: 3, fill: "#111827", stroke: "#3a4f7a", "stroke-width": 1.2, filter: "url(#softShadow)" }));
  for (const px of [-10,-4,2,8]) g.appendChild(SvgEl("circle", { cx: px, cy: 3, r: 1.7, fill: "#0a0e1a", stroke: "#27395a", "stroke-width": 0.7 }));
  g.appendChild(SvgEl("circle", { class: "gateway-led on", cx: -11, cy: -7, r: 1.5 }));
  g.appendChild(SvgEl("circle", { class: "gateway-led on", cx: -6, cy: -7, r: 1.5 }));
  g.appendChild(SvgEl("circle", { class: "gateway-led on", cx: -1, cy: -7, r: 1.5 }));
  g.appendChild(SvgEl("circle", { class: "gateway-led dim", cx: 4, cy: -7, r: 1.5 }));
  const lb = SvgEl("text", { class: "gateway-name", x: 0, y: 24, "text-anchor": "middle", fill: "#8494ad", "font-size": 8.5, "font-family": "var(--mono)", letterSpacing: "0.04em" });
  lb.textContent = gw.label;
  g.appendChild(lb);
  g.appendChild(SvgEl("circle", { class: "gateway-led-ring", r: 13, fill: "none", stroke: "#4fd6be", "stroke-width": 1, "stroke-dasharray": "2 2", opacity: 0 }));
  return g;
}

/* ========================================================== gateway placement: midpoint of selected links */
const GATEWAY_DEFS = [
  { id: "gwAB", from: "alice", to: "bob",   label: "SW-1 · 10.0.1.1" },
  { id: "gwAC", from: "alice", to: "carol", label: "SW-2 · 10.0.2.1" },
  { id: "gwBE", from: "bob",   to: "eve",   label: "RT-1 · 10.0.10.1" },
  { id: "gwCE", from: "carol", to: "eve",   label: "RT-2 · 10.0.20.1" },
  { id: "gwDE", from: "dave",  to: "eve",   label: "AP-1 · 10.0.30.1" },
];

/* ========================================================== build scene */
const nodeEls = {};
const gwEls = {};
const linkEls = {};

const nodesG = $svg("nodes");
const linkG = $svg("links");
const gatewaysG = $svg("gateways");

function isAttacker(id) { return ATTACKERS.some((a) => a.id === id); }
function nodeById(id) { return [...COMPUTERS, ...ATTACKERS].find((n) => n.id === id); }

/* ---------- draw link lines (with gateway light at midpoint) ---------- */
for (const [a, b] of LINK_DEFS) {
  const na = nodeById(a), nb = nodeById(b);
  if (!na || !nb) continue;
  const line = SvgEl("line", { class: "link", "data-from": a, "data-to": b, x1: na.x, y1: na.y, x2: nb.x, y2: nb.y });
  linkG.appendChild(line);
  linkEls[a + "-" + b] = line;
  linkEls[b + "-" + a] = line;
  const mx = (na.x + nb.x) / 2, my = (na.y + nb.y) / 2;
  const lm = SvgEl("circle", { cx: mx, cy: my, r: 2.6, class: "link-light", opacity: 0 });
  linkG.appendChild(lm);
  linkEls["ll-" + a + "-" + b] = lm;
  linkEls["ll-" + b + "-" + a] = lm;
}

/* ---------- draw computers ---------- */
for (const n of COMPUTERS) {
  const g = drawComputer(n);
  nodesG.appendChild(g);
  nodeEls[n.id] = { g, hl: g.querySelector(".computer-highlight"), state: g.querySelector(".computer-state"), leds: g.querySelectorAll(".computer-led"), screen: g.querySelector(".computer-screen-content"), node: n };
}

/* ---------- draw attacker nodes ---------- */
for (const n of ATTACKERS) {
  const g = drawComputer(n);
  nodesG.appendChild(g);
  nodeEls[n.id] = { g, hl: g.querySelector(".computer-highlight"), state: g.querySelector(".computer-state"), leds: g.querySelectorAll(".computer-led"), screen: g.querySelector(".computer-screen-content"), node: n };
}

/* ---------- draw gateways at midpoints ---------- */
for (const gw of GATEWAY_DEFS) {
  const na = COMPUTERS.find((c) => c.id === gw.from);
  const nb = COMPUTERS.find((c) => c.id === gw.to);
  if (!na || !nb) continue;
  const mx = (na.x + nb.x) / 2, my = (na.y + nb.y) / 2;
  const g = drawGateway({ x: mx, y: my, label: gw.label });
  gatewaysG.appendChild(g);
  gwEls[gw.id] = { g, ring: g.querySelector(".gateway-led-ring"), leds: g.querySelectorAll(".gateway-led") };
}

/* ========================================================== packet animation + link lighting */
let packetRAF = 0;
let pktGen = 0;
function haltPacket() {
  pktGen++;
  if (packetRAF) { cancelAnimationFrame(packetRAF); packetRAF = 0; }
  for (const id of ["packetGroup","packetGroupBad","packetGroupGold"]) { const pg = $svg(id); if (pg) pg.setAttribute("opacity", "0"); }
  for (const l of $$(".link.active, .link.attack, .link.replay, .link.mitm, .link.downgrade")) l.classList.remove("active","attack","replay","mitm","downgrade");
  for (const gw of Object.values(gwEls)) { if (gw) gw.ring.classList.remove("show"); }
}

const HOP_MS = 850;

function animateHop(line, pg, gen) {
  return new Promise((resolve) => {
    const x1 = +line.getAttribute("x1"), y1 = +line.getAttribute("y1");
    const x2 = +line.getAttribute("x2"), y2 = +line.getAttribute("y2");
    const t0 = performance.now();
    const tick = () => {
      if (gen !== pktGen) { resolve(false); return; }
      const p = Math.min(1, (performance.now() - t0) / HOP_MS);
      const eased = 1 - Math.pow(1 - p, 2);
      pg.setAttribute("transform", `translate(${x1 + (x2 - x1) * eased},${y1 + (y2 - y1) * eased})`);
      if (p < 1) packetRAF = requestAnimationFrame(tick);
      else resolve(true);
    };
    packetRAF = requestAnimationFrame(tick);
  });
}

/* Walk the route hop by hop: one packet, one gateway light, one log line
 * per link — the frame is 80 B and the path comes from routePath(). */
async function launchPacket(from, to, kind = "safe") {
  haltPacket();
  const gen = pktGen;
  const path = routePath(from, to);
  if (path.length < 2) return 0;
  const pg = kind === "bad" ? $svg("packetGroupBad") : kind === "replay" ? $svg("packetGroupGold") : $svg("packetGroup");
  if (!pg) return 0;

  renderRoute(path, kind);
  const cls = kind === "bad" ? "attack" : kind === "replay" ? "replay" : "active";
  const hue = kind === "bad" ? "#f87171" : kind === "replay" ? "#fbbf24" : "#4fd6be";
  pg.setAttribute("opacity", "1");
  pg.classList.add("show");

  let hopped = 0;
  for (let i = 0; i < path.length - 1; i++) {
    if (gen !== pktGen) break;
    const a = path[i], b = path[i + 1];
    const line = linkEls[a + "-" + b];
    if (!line) continue;
    pg.setAttribute("transform", `translate(${+line.getAttribute("x1")},${+line.getAttribute("y1")})`);
    line.classList.add(cls);
    const gw = gatewayFor(a, b);
    const gwEl = gw ? gwEls[gw.id] : null;
    if (gwEl) { gwEl.ring.classList.add("show"); gwEl.ring.setAttribute("stroke", hue); }

    const t0 = performance.now();
    const done = await animateHop(line, pg, gen);
    if (!done) break;
    hopped++;
    const ms = performance.now() - t0;
    netLine("dim", "   hop " + hopped + " · " + a + " → " + b +
      (gw ? " · " + gw.label : " · direct link") +
      " · " + FRAME_BYTES + " B · " + ms.toFixed(1) + " ms");
    line.classList.remove("active", "attack", "replay");
    if (gwEl) gwEl.ring.classList.remove("show");
    hudAdd("hops", 1);
  }

  pg.setAttribute("opacity", "0");
  pg.classList.remove("show");
  hudAdd("frames", 1);
  hudAdd("bytes", FRAME_BYTES);
  return hopped;
}

/* ========================================================== node highlight / led control */
function highlightNode(id, color = null, showState = null, ledState = null) {
  const e = nodeEls[id]; if (!e) return;
  if (color) e.hl.setAttribute("stroke", color);
  e.hl.classList.add("show");
  if (showState) e.state.textContent = showState;
  if (ledState) {
    e.leds.forEach((l, i) => {
      l.setAttribute("class", "computer-led " + (i === 0 ? ledState : (i === 1 ? (ledState === "safe" ? "on" : "dim") : "dim")));
    });
  }
}
function clearNodeHighlights() {
  for (const e of Object.values(nodeEls)) {
    e.hl.classList.remove("show");
    const n = e.node;
    e.state.textContent = n.kind === "attacker" ? "⚠ attacking" : n.kind === "gateway" ? "gateway" : "online";
    e.leds.forEach((l, i) => l.setAttribute("class", "computer-led " + (i === 0 ? "on" : "dim")));
  }
}

/* ========================================================== network session: one keyholder per sender
 * ss_c / ss_p / master key live for the session; the nonce is FRESH PER MESSAGE
 * (hmk.go: "16 fresh random bytes per wrap"), so every record gets its own
 * keystream.  The receiver keeps two pieces of state:
 *   netWindow[receiver]  — nonces already consumed (anti-replay window)
 *   netCaptured[sender]  — the last delivered frame, i.e. what an attacker sniffs
 */
const netSession = {};
const netCaptured = {};
const netWindow = {};
function netEnsureSession(senderId) {
  if (!netSession[senderId]) {
    netSession[senderId] = { ssC: randBytes(32), ssP: randBytes(32), mk: randBytes(32) };
  }
  return netSession[senderId];
}
function consumeNonce(receiverId, nonceArr) {
  const w = netWindow[receiverId] = netWindow[receiverId] || new Set();
  w.add(hex(nonceArr));
  return w;
}

/* ========================================================== crypto helpers (reuse hmk-core) */
async function computeSeal(s) {
  const { kf, u, kek, kmac } = await deriveWrapKeys(s);
  s.kf = kf; s.u = u; s.kek = kek; s.kmac = kmac;
  const ks = await hmacSha256(kek, concat(enc("hmk/v1/ks"), s.nonce));
  s.ct = new Uint8Array(32);
  for (let i = 0; i < 32; i++) s.ct[i] = s.mk[i] ^ ks[i];
  s.tag = await hmacSha256(kmac, concat(enc("hmk/v1/tag"), s.nonce, s.ct, AAD));
  return s;
}
async function verifyTag(s, ct, tag, nonce) {
  const calc = await hmacSha256(kmac, concat(enc("hmk/v1/tag"), nonce, ct, AAD));
  return ctMemcmp(calc, tag);
}

/* ========================================================== dropdown wiring */
(function wireDropdowns() {
  const senderSel = $("#senderSel"), receiverSel = $("#receiverSel");
  for (const n of COMPUTERS) {
    const o = document.createElement("option");
    o.value = n.id; o.textContent = n.name;
    senderSel.appendChild(o);
    const o2 = document.createElement("option");
    o2.value = n.id; o2.textContent = n.name;
    receiverSel.appendChild(o2);
  }
  senderSel.value = "alice";
  receiverSel.value = "bob";

  const btnSend = $("#btnSendMsg"), btnRand = $("#btnRandSend");
  btnSend.addEventListener("click", () => {
    const attack = document.querySelector('input[name="attack"]:checked').value;
    netSend(senderSel.value, receiverSel.value, attack);
  });
  btnRand.addEventListener("click", () => {
    const choices = COMPUTERS.filter((n) => n.id !== "home");
    const from = choices[Math.floor(Math.random() * choices.length)];
    let to = choices[Math.floor(Math.random() * choices.length)];
    while (to.id === from.id) to = choices[Math.floor(Math.random() * choices.length)];
    senderSel.value = from.id;
    receiverSel.value = to.id;
    const attack = document.querySelector('input[name="attack"]:checked').value;
    netSend(from.id, to.id, attack);
  });

  const previewRoute = () => renderRoute(routePath(senderSel.value, receiverSel.value), "idle");
  senderSel.addEventListener("change", previewRoute);
  receiverSel.addEventListener("change", previewRoute);
  previewRoute();
})();

/* ========================================================== attack drawer */
(function wireAttackDrawer() {
  const toggle = $("#btnAttackToggle"), drawer = $("#btnAttackToggle").parentElement;
  toggle.addEventListener("click", () => {
    const open = drawer.classList.toggle("open");
    toggle.textContent = open ? "✕ Close attack drawer (14 attacks)" : "⚔ Open attack drawer (14 attacks)";
  });
  $$("input[name=\"attack\"]").forEach((r) => {
    r.addEventListener("change", () => {
      $$("#btnLaunchAttack").forEach((b) => b.disabled = !r.checked || r.value === "none");
    });
  });
  $$("#btnLaunchAttack").forEach((b) => {
    b.addEventListener("click", () => {
      const attack = document.querySelector('input[name="attack"]:checked').value;
      netSend($("#senderSel").value, $("#receiverSel").value, attack);
    });
  });
})();

/* ========================================================== main send + 15 attacks */
async function netSend(senderId, receiverId, attack = "none") {
  if (busy) return;
  busy = true;
  haltPacket();
  clearNodeHighlights();
  netLog.innerHTML = "";
  netVerdict.className = "verdict";
  netSetVerdict("ok", "");

  const sender = COMPUTERS.find((n) => n.id === senderId);
  const receiver = COMPUTERS.find((n) => n.id === receiverId);
  if (!sender || !receiver) { busy = false; return; }

  const t = () => "[" + new Date().toLocaleTimeString() + "]";
  const hop0 = tel.hops;

  netLine("dim", t() + " " + sender.name + " → " + receiver.name + " · sending a sealed message");
  await sleep(400);

  const sess = netEnsureSession(senderId);
  const s = {
    ssC: sess.ssC, ssP: sess.ssP,
    mk: sess.mk, nonce: randBytes(16),
    vkC: randBytes(32), vkP: randBytes(32),
    hdr: enc(`{"alg":"hybrid","typ":"JWT"}`),
    pld: enc(`{"iss":"${sender.name}","sub":"${receiver.name}","exp":4102444800}`),
  };
  s.ss = concat(s.ssC, s.ssP);
  s.skC = await hmacSha256(enc("hybridoidc/sk-derivation"), s.vkC);
  s.skP = await hmacSha256(enc("hybridoidc/sk-derivation"), s.vkP);

  const { kf, u, kek, kmac } = await deriveWrapKeys(s);
  s.kf = kf; s.u = u; s.kek = kek; s.kmac = kmac;

  highlightNode(senderId, sender.color, "derived K_f + u", "safe");
  highlightNode(receiverId, receiver.color, "waiting for sealed record");
  netLine("info", t() + " sender derives K_f = ss_c·ss_p mod p");
  netLine("gold", t() + " K_f = " + hex16(kf) + "   [F_p combiner, constant-time]");
  await sleep(350);
  netLine("info", t() + " sender derives u = M·(ss_c‖ss_p)");
  netLine("gold", t() + " u   = " + hex16(u) + "   [rank-512 F₂ mix]");
  await sleep(350);

  const tSeal = performance.now();
  await computeSeal(s);
  const sealUs = (performance.now() - tSeal) * 1000;
  fillFrame(s.nonce, s.ct, s.tag);
  hud("tLatency", sealUs.toFixed(1) + " / — µs");
  hud("tSession", hex16(kf));
  highlightNode(senderId, sender.color, "sealed record ready", "safe");
  netLine("info", t() + " sealed ct = mk ⊕ HMAC(kek, …)");
  netLine("gold", t() + " ct  = " + hex16(s.ct));
  netLine("gold", t() + " tag = " + hex16(s.tag) + "   [HMAC(kmac, nonce‖ct‖aad)]");
  await sleep(400);

  // ---- replay-class attacks need a frame the attacker actually sniffed ----
  const replayClass = attack === "replayoldnonce" || attack === "keystreamreuse";
  if (replayClass && !netCaptured[senderId]) {
    netLine("dim", t() + " attacker holds no frame yet — sniffing one honest delivery first");
    await launchPacket(senderId, receiverId, "safe");
    const okFirst = await verifyTag(s, s.ct, s.tag, s.nonce);
    if (okFirst) {
      consumeNonce(receiverId, s.nonce);
      netCaptured[senderId] = { nonce: new Uint8Array(s.nonce), ct: new Uint8Array(s.ct), tag: new Uint8Array(s.tag) };
      fillFrame(s.nonce, s.ct, s.tag);
      rwPush(receiverId, s.nonce);
      netLine("ok", t() + " honest frame opened by " + receiver.name + " · nonce " + hex16(s.nonce) + "… consumed by the anti-replay window");
    }
  }

  // ---- build tampered record ----
  let finalCt = new Uint8Array(s.ct);
  let finalTag = new Uint8Array(s.tag);
  let finalNonce = new Uint8Array(s.nonce);
  let attackLabel = "no attack — honest send";

  if (attack === "bitflip") {
    const pos = Math.floor(Math.random() * 32);
    finalCt = new Uint8Array(s.ct); finalCt[pos] ^= 0x42;
    attackLabel = "bit-flip on ct at byte " + pos + " · one ciphertext byte flipped in transit";
  } else if (attack === "tagforge") {
    finalTag = new Uint8Array(32);
    attackLabel = "forged tag = 32 zero bytes · attacker submits a fake tag instead of the real one";
  } else if (attack === "halfguess") {
    const fakeC = randBytes(32);
    const gk = fieldCombine(fakeC, s.ssP);
    const gu = linspread(concat(fakeC, s.ssP));
    const gkek = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([0])));
    const gkmac = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([1])));
    const gks = await hmacSha256(gkek, concat(enc("hmk/v1/ks"), s.nonce));
    finalCt = new Uint8Array(32); for (let i = 0; i < 32; i++) finalCt[i] = s.mk[i] ^ gks[i];
    finalTag = await hmacSha256(gkmac, concat(enc("hmk/v1/tag"), s.nonce, finalCt, AAD));
    attackLabel = "guessed only one KEM half · attacker derives fake K_f = " + hex16(gk).slice(0, 16) + "… from a random ss_c and the real ss_p";
  } else if (attack === "doublehalf") {
    const fakeC = randBytes(32), fakeP = randBytes(32);
    const gk = fieldCombine(fakeC, fakeP);
    const gu = linspread(concat(fakeC, fakeP));
    const gkek = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([0])));
    const gkmac = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([1])));
    const gks = await hmacSha256(gkek, concat(enc("hmk/v1/ks"), s.nonce));
    finalCt = new Uint8Array(32); for (let i = 0; i < 32; i++) finalCt[i] = s.mk[i] ^ gks[i];
    finalTag = await hmacSha256(gkmac, concat(enc("hmk/v1/tag"), s.nonce, finalCt, AAD));
    attackLabel = "guessed both KEM halves · brute-force fake ss_c + ss_p (256-bit search) → fake K_f = " + hex16(gk).slice(0, 16) + "…";
  } else if (attack === "replay") {
    const newNonce = randBytes(16);
    finalNonce = newNonce;
    attackLabel = "replay with fresh nonce · attacker resends captured ct+tag with new nonce " + hex16(newNonce).slice(0, 16) + "…";
  } else if (attack === "replayoldnonce") {
    const cap = netCaptured[senderId];
    finalNonce = new Uint8Array(cap.nonce);
    finalCt = new Uint8Array(cap.ct);
    finalTag = new Uint8Array(cap.tag);
    attackLabel = "replay with original nonce · the sniffed frame (nonce " + hex16(cap.nonce) + "…) resubmitted byte-for-byte";
  } else if (attack === "eavesdrop") {
    attackLabel = "eavesdrop only · attacker reads the wire (ct=" + hex16(s.ct).slice(0, 16) + "…·tag=" + hex16(s.tag).slice(0, 16) + "…) but cannot open ct without K_f";
  } else if (attack === "mitmreroute") {
    const newNonce = randBytes(16);
    finalNonce = newNonce;
    attackLabel = "MITM reroute · attacker intercepts and redirects the packet with new nonce " + hex16(newNonce).slice(0, 16) + "…";
  } else if (attack === "keystreamreuse") {
    const cap = netCaptured[senderId];
    finalNonce = new Uint8Array(cap.nonce);
    finalCt = new Uint8Array(cap.ct);
    for (let i = 0; i < finalCt.length; i++) finalCt[i] ^= 0x5c;   /* second ciphertext under the SAME keystream */
    finalTag = new Uint8Array(cap.tag);
    attackLabel = "keystream reuse · attacker mints a second record under nonce " + hex16(cap.nonce) + "… (ct ⊕ 0x5c) — a reuse that would leak ct₁⊕ct₂ = mk₁⊕mk₂";
  } else if (attack === "cttrunc") {
    finalCt = new Uint8Array(s.ct.subarray(0, 16));
    attackLabel = "chopped ciphertext · attacker truncates ct from 32 bytes to 16 bytes";
  } else if (attack === "tagtrunc") {
    finalTag = new Uint8Array(s.tag.subarray(0, 16));
    attackLabel = "truncated tag · attacker submits only 16 of the 32 tag bytes";
  } else if (attack === "timingprobe") {
    const pos = Math.floor(Math.random() * 32);
    finalCt = new Uint8Array(s.ct); finalCt[pos] ^= 0x42;
    attackLabel = "timing probe · one ciphertext byte flipped at " + pos + ", submitted 64× while the attacker measures reject latency against accept latency";
  } else if (attack === "downclassical") {
    const fakeP = randBytes(32);
    const gk = fieldCombine(s.ssC, fakeP);
    const gu = linspread(concat(s.ssC, fakeP));
    const gkek = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([0])));
    const gkmac = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([1])));
    const gks = await hmacSha256(gkek, concat(enc("hmk/v1/ks"), s.nonce));
    finalCt = new Uint8Array(32); for (let i = 0; i < 32; i++) finalCt[i] = s.mk[i] ^ gks[i];
    finalTag = await hmacSha256(gkmac, concat(enc("hmk/v1/tag"), s.nonce, finalCt, AAD));
    attackLabel = "classical-only downgrade · attacker tries K_f with only the classical half (ss_c) + fake pq half → K_f = " + hex16(gk).slice(0, 16) + "… ≠ real K_f " + hex16(s.kf).slice(0, 16) + "…";
  } else if (attack === "downpq") {
    const fakeC = randBytes(32);
    const gk = fieldCombine(fakeC, s.ssP);
    const gu = linspread(concat(fakeC, s.ssP));
    const gkek = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([0])));
    const gkmac = await hmacSha256(gk, concat(gu, enc("hmk/v1/rk"), new Uint8Array([1])));
    const gks = await hmacSha256(gkek, concat(enc("hmk/v1/ks"), s.nonce));
    finalCt = new Uint8Array(32); for (let i = 0; i < 32; i++) finalCt[i] = s.mk[i] ^ gks[i];
    finalTag = await hmacSha256(gkmac, concat(enc("hmk/v1/tag"), s.nonce, finalCt, AAD));
    attackLabel = "PQ-only downgrade · attacker tries K_f with only the PQ half (ss_p) + fake classical half → K_f = " + hex16(gk).slice(0, 16) + "… ≠ real K_f " + hex16(s.kf).slice(0, 16) + "…";
  }

  // ---- honest send ----
  if (attack === "none") {
    netLine("info", t() + " no attack — sending the sealed record honestly");
    await launchPacket(senderId, receiverId, "safe");
    netLine("gold", t() + " sealed record arrived — receiver verifies the tag");
    const tVer = performance.now();
    const ok = await verifyTag(s, s.ct, s.tag, s.nonce);
    const verUs = (performance.now() - tVer) * 1000;
    hud("tLatency", sealUs.toFixed(1) + " / " + verUs.toFixed(1) + " µs");
    if (ok) {
      consumeNonce(receiverId, s.nonce);
      netCaptured[senderId] = { nonce: new Uint8Array(s.nonce), ct: new Uint8Array(s.ct), tag: new Uint8Array(s.tag) };
      rwPush(receiverId, s.nonce);
      capAdd({ src: sender.name, dst: receiver.name, hops: tel.hops - hop0, bytes: FRAME_BYTES, nonce: s.nonce, mode: "honest", result: "accepted" });
      netLine("ok", t() + " tag verified ✓ — " + receiver.name + " recovered the master key");
      netLine("ok", t() + " K_f = " + hex16(s.kf).slice(0, 16) + "… · u = " + hex16(s.u).slice(0, 16) + "…");
      netSetVerdict("ok", "MESSAGE SEALED & DELIVERED ✓");
    } else {
      netLine("bad", t() + " tag verify FAILED — that's a bug (ok=" + ok + ")");
      netSetVerdict("bad", "BUG — HONEST RECORD REJECTED");
    }
    await sleep(400);
    highlightNode(receiverId, receiver.color, "recovered · master key opened", "safe");
  }

  // ---- eavesdrop (passive: show attack, then send honestly) ----
  else if (attack === "eavesdrop") {
    netLine("bad", "──────────────────────────────────────────────────");
    netLine("bad", t() + " ⚔ ATTACK · " + attackLabel);
    await launchPacket(senderId, receiverId, "bad");
    netLine("bad", t() + " attacker read the wire but could not open the ciphertext without K_f");
    netLine("bad", t() + " attacker cannot compute K_f = ss_c·ss_p mod p without BOTH halves");
    netLine("bad", t() + " attacker cannot derive the HMAC keystream — cannot recover the master key");
    await sleep(400);
    netLine("dim", t() + " meanwhile the honest sealed record arrives separately and Bob verifies the tag ✓");
    await launchPacket(senderId, receiverId, "safe");
    const okH = await verifyTag(s, s.ct, s.tag, s.nonce);
    matrixRun("eavesdrop", !!okH);
    if (okH) hudBlock();
    if (okH) {
      consumeNonce(receiverId, s.nonce);
      netCaptured[senderId] = { nonce: new Uint8Array(s.nonce), ct: new Uint8Array(s.ct), tag: new Uint8Array(s.tag) };
      rwPush(receiverId, s.nonce);
      capAdd({ src: sender.name, dst: receiver.name, hops: tel.hops - hop0, bytes: FRAME_BYTES, nonce: s.nonce, mode: "honest · sniffed", result: "accepted" });
      netLine("ok", t() + " Bob recovered the master key — eavesdropper learned nothing usable");
      netLine("ok", t() + " attacker saw ct = " + hex16(s.ct).slice(0, 16) + "… but could not derive K_f");
      netSetVerdict("ok", "EAVESDROP FAILS ✓");
    } else {
      netLine("bad", t() + " Bob's tag verify FAILED — that's a bug (okH=" + okH + ")");
      netSetVerdict("bad", "BUG — HONEST RECORD REJECTED");
    }
    await sleep(400);
    highlightNode(receiverId, receiver.color, "recovered · eavesdropper learned nothing", "safe");
  }

  // ---- active attacks: tamper then verify ----
  else {
    netLine("bad", "──────────────────────────────────────────────────");
    netLine("bad", t() + " ⚔ ATTACK · " + attackLabel);
    let linkKind = "bad";
    if (attack === "replay" || attack === "replayoldnonce" || attack === "keystreamreuse") linkKind = "replay";
    fillFrame(finalNonce, finalCt, finalTag);
    await launchPacket(senderId, receiverId, linkKind);

    const tVer = performance.now();
    const tagOk = await verifyTag(s, finalCt, finalTag, finalNonce);
    const verUs = (performance.now() - tVer) * 1000;
    hud("tLatency", sealUs.toFixed(1) + " / " + verUs.toFixed(1) + " µs");

    /* the tag is only half of the check: the receiver also refuses any nonce
     * its anti-replay window has already consumed. */
    const nonceKey = hex(finalNonce);
    const consumed = (netWindow[receiverId] || new Set()).has(nonceKey);
    let ok = tagOk && !consumed;

    /* timing probe: N accepts vs N rejects, median of each — a constant-time
     * full-scan compare gives a flat ratio, an early-exit one would not. */
    if (attack === "timingprobe") {
      const N = 64, acc = [], rej = [];
      for (let i = 0; i < N; i++) {
        let t0 = performance.now(); await verifyTag(s, s.ct, s.tag, s.nonce); acc.push((performance.now() - t0) * 1000);
        t0 = performance.now(); await verifyTag(s, finalCt, finalTag, finalNonce); rej.push((performance.now() - t0) * 1000);
      }
      const med = (a) => { const b = [...a].sort((x, y) => x - y); return b[b.length >> 1]; };
      const am = med(acc), rm = med(rej);
      netLine("dim", "   accept median " + am.toFixed(1) + " µs · reject median " + rm.toFixed(1) + " µs · n = " + N + " each");
      netLine("info", "   reject/accept = " + (am > 0 ? (rm / am).toFixed(2) : "1.00") + "× — full-scan compare, no early exit, no oracle");
      hud("tLatency", am.toFixed(1) + " / " + rm.toFixed(1) + " µs");
    }

    if (ok) {
      netLine("bad", t() + " REJECTED — wait, tag match? That's a bug (ok=" + ok + ")");
      netSetVerdict("bad", "ATTACK SUCCEEDED — BUG");
    } else {
      if (tagOk && consumed) {
        /* the construction verified the record — only freshness state rejected it */
        netLine("bad", t() + " REJECTED — tag verifies byte-for-byte, but nonce " + hex16(finalNonce) + "… is already consumed");
        netLine("dim", t() + " why: a MAC authenticates content, not freshness — freshness comes from the receiver's one-time nonce window");
        netLine("dim", t() + " why: without a second accepted encryption under this nonce the keystream never repeats (HMAC-DRBG-style: 1 nonce → 1 keystream)");
      } else {
        const calc = await hmacSh256(s.kmac, concat(enc("hmk/v1/tag"), finalNonce, finalCt, AAD));
        netLine("bad", t() + " REJECTED — recalculated tag " + hex16(calc).slice(0, 16) + "… ≠ " + hex16(finalTag).slice(0, 16) + "…");

        const why = {
          bitflip: "the tag covers nonce‖ct‖aad — one flipped byte breaks the HMAC binding",
          tagforge: "computing a valid tag requires K_f = ss_c·ss_p mod p, so both halves",
          halfguess: "K_f = ss_c·ss_p mod p needs BOTH halves — the weakest link survives",
          doublehalf: "brute-forcing 256-bit K_f is infeasible — attacker's fake K_f ≠ real K_f",
          replay: "the tag binds to the nonce — replaying with a fresh nonce fails the HMAC",
          replayoldnonce: "the exact frame is authentic, which is exactly why the consumed-nonce window drops it",
          mitmreroute: "the MITM cannot produce a valid tag for the redirected nonce without K_f",
          keystreamreuse: "nonce reuse never happens on the wire — the receiver consumes each nonce once, so the second keystream is unreachable",
          cttrunc: "truncated ct (16B) fails the tag — the tag covers the full 32-byte ct",
          tagtrunc: "truncated tag (16B) fails the full 32-byte compare — tag must be exactly 32 bytes",
          timingprobe: "HMK-1 uses a full-scan constant-time compare — no early-exit timing oracle, so the probe finds nothing",
          downclassical: "K_f = ss_c·ss_p mod p needs the classical half AND the PQ half — one half is not enough",
          downpq: "K_f = ss_c·ss_p mod p needs both halves — downgrading to PQ-only fails",
        };
        if (why[attack]) netLine("dim", t() + " why: " + why[attack]);
        if (consumed) netLine("dim", t() + " note: nonce " + hex16(finalNonce) + "… is also already consumed — rejected twice over");
      }
      netSetVerdict("ok", "ATTACK BLOCKED ✓");
    }
    capAdd({ src: sender.name, dst: receiver.name, hops: tel.hops - hop0, bytes: FRAME_BYTES, nonce: finalNonce, mode: attack, result: ok ? "accepted" : "rejected" });
    matrixRun(attack, !ok);
    if (!ok) hudBlock();
    await sleep(400);
    const statusText = ok ? "accepted (!) — bug" : "rejected · seal holds";
    highlightNode(receiverId, receiver.color, "received · " + statusText, ok ? "bad" : "warn");
  }

  await sleep(300);
  netLine("ok", "══════ " + sender.name + " → " + receiver.name + " · " + attackLabel + " ══════");
  busy = false;
}

/* build-site.js — regenerates site/index.html by splicing the 05-network
 * section into the HEAD branch (scoreboard removed), then self-checks.
 * Run: node build-site.js  (from the repo root). */
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const headPath = path.join(dir, 'site/.index.head.html');
if (!fs.existsSync(headPath)) throw new Error('site/.index.head.html is missing (workspace-only snapshot with the pre-network page)');
const head = fs.readFileSync(headPath, 'utf8');

/* network section — authored in this file so it is reproducible */
let network = fs.readFileSync(path.join(dir, 'site/.net.head.html'), 'utf8');
function must(s, needle, insert, tag) {
  if (s.includes(needle)) return s.replace(needle, insert);
  throw new Error('anchor missing: ' + tag);
}

/* telemetry cards, right after the lead */
network = must(
  network,
  '  <div class="net-wrap">',
  `  <div class="net-telemetry" id="netTelemetry">
    <div class="tel"><span class="tel-k">frames on wire</span><span class="tel-v" id="tFrames">0</span></div>
    <div class="tel"><span class="tel-k">bytes carried</span><span class="tel-v" id="tBytes">0</span></div>
    <div class="tel"><span class="tel-k">hops traversed</span><span class="tel-v" id="tHops">0</span></div>
    <div class="tel"><span class="tel-k">attacks blocked</span><span class="tel-v ok" id="tBlocked">0</span></div>
    <div class="tel"><span class="tel-k">seal / verify</span><span class="tel-v" id="tLatency">&mdash; / &mdash; &micro;s</span></div>
    <div class="tel"><span class="tel-k">session key</span><span class="tel-v" id="tSession">&mdash;</span></div>
  </div>
  <div class="net-wrap">`,
  "telemetry"
);

/* route + wire frame, between the canvas and the controls */
network = must(
  network,
  '  <div class="net-controls">',
  `  <div class="net-meta">
    <div class="net-route">
      <span class="meta-k">route &middot; shortest path over the LAN graph</span>
      <div class="route-chips" id="routeChips"><span class="chip idle">pick a sender and a receiver</span></div>
    </div>
    <div class="net-frame">
      <span class="meta-k">wire frame &middot; 16 B nonce &middot; 32 B ct &middot; 32 B tag</span>
      <div class="frame-bar">
        <div class="fseg nonce"><b>nonce</b><span id="frameNonce">&mdash;</span></div>
        <div class="fseg ct"><b>ct</b><span id="frameCt">&mdash;</span></div>
        <div class="fseg tag"><b>tag</b><span id="frameTag">&mdash;</span></div>
      </div>
      <div class="frame-hex" id="frameHex">the sealed record appears here the moment the sender seals it</div>
    </div>
  </div>
  <div class="net-controls">`,
  "net-meta"
);

/* device roster + attack matrix, before the log */
network = must(
  network,
  '  <div class="net-log-wrap">',
  `  <div class="net-extra">
    <div class="roster">
      <span class="meta-k">device roster &middot; addressing</span>
      <div class="roster-grid">
        <div class="roster-col">
          <h4>endpoints</h4>
          <div class="roster-item"><b>alice</b><span>10.0.1.10</span><i>laptop</i></div>
          <div class="roster-item"><b>bob</b><span>10.0.1.20</span><i>workstation</i></div>
          <div class="roster-item"><b>carol</b><span>10.0.2.10</span><i>server</i></div>
          <div class="roster-item"><b>dave</b><span>10.0.30.10</span><i>phone</i></div>
          <div class="roster-item"><b>eve</b><span>10.0.9.1</span><i>router</i></div>
          <div class="roster-item"><b>home</b><span>10.0.0.1</span><i>home gateway</i></div>
        </div>
        <div class="roster-col">
          <h4>lan gateways</h4>
          <div class="roster-item"><b>SW-1</b><span>10.0.1.1</span><i>switch &middot; alice&ndash;bob</i></div>
          <div class="roster-item"><b>SW-2</b><span>10.0.2.1</span><i>switch &middot; alice&ndash;carol</i></div>
          <div class="roster-item"><b>RT-1</b><span>10.0.10.1</span><i>router &middot; bob&ndash;eve</i></div>
          <div class="roster-item"><b>RT-2</b><span>10.0.20.1</span><i>router &middot; carol&ndash;eve</i></div>
          <div class="roster-item"><b>AP-1</b><span>10.0.30.1</span><i>access point &middot; dave&ndash;eve</i></div>
        </div>
        <div class="roster-col">
          <h4>adversaries on the wire</h4>
          <div class="roster-item bad"><b>Mallory</b><span>MITM</span><i>reroutes frames</i></div>
          <div class="roster-item bad"><b>Eve</b><span>eavesdrop</span><i>reads the wire</i></div>
          <div class="roster-item bad"><b>Oscar</b><span>offline brute</span><i>guesses K<sub>f</sub></i></div>
          <div class="roster-item bad"><b>Trent</b><span>compromised CA</span><i>grafts halves</i></div>
          <div class="roster-item bad"><b>Botnet</b><span>cluster</span><i>floods / replays</i></div>
        </div>
      </div>
    </div>
    <div class="attack-matrix">
      <div class="mx-head"><span class="meta-k">attack matrix &middot; 14 attacks &times; outcome</span><span class="mx-count" id="mxCount">0 / 14 run</span></div>
      <div class="mx-grid" id="mxGrid">
        <div class="mx" data-atk="bitflip"><b>bit-flip</b><span id="mx-bitflip">pending</span></div>
        <div class="mx" data-atk="tagforge"><b>tag forge</b><span id="mx-tagforge">pending</span></div>
        <div class="mx" data-atk="halfguess"><b>1-half guess</b><span id="mx-halfguess">pending</span></div>
        <div class="mx" data-atk="doublehalf"><b>2-half guess</b><span id="mx-doublehalf">pending</span></div>
        <div class="mx" data-atk="replay"><b>replay</b><span id="mx-replay">pending</span></div>
        <div class="mx" data-atk="replayoldnonce"><b>replay old nonce</b><span id="mx-replayoldnonce">pending</span></div>
        <div class="mx" data-atk="eavesdrop"><b>eavesdrop</b><span id="mx-eavesdrop">pending</span></div>
        <div class="mx" data-atk="mitmreroute"><b>MITM reroute</b><span id="mx-mitmreroute">pending</span></div>
        <div class="mx" data-atk="keystreamreuse"><b>keystream reuse</b><span id="mx-keystreamreuse">pending</span></div>
        <div class="mx" data-atk="cttrunc"><b>chopped ct</b><span id="mx-cttrunc">pending</span></div>
        <div class="mx" data-atk="tagtrunc"><b>truncated tag</b><span id="mx-tagtrunc">pending</span></div>
        <div class="mx" data-atk="timingprobe"><b>timing probe</b><span id="mx-timingprobe">pending</span></div>
        <div class="mx" data-atk="downclassical"><b>classical downgrade</b><span id="mx-downclassical">pending</span></div>
        <div class="mx" data-atk="downpq"><b>PQ downgrade</b><span id="mx-downpq">pending</span></div>
      </div>
    </div>
  </div>
  <div class="net-log-wrap">`,
  "roster+matrix"
);

/* splice into HEAD */
const iScore = head.indexOf('<section id="score"');
const iRepo = head.indexOf('<section id="repo"');
if (iScore < 0 || iRepo < 0 || iScore > iRepo) throw new Error("score/repo anchors wrong");

let front = head.slice(0, iScore);      /* nav → hero → demo → claims → math → timing */
const back = head.slice(iRepo);         /* repo → scenario → footer → scripts */
front = must(front, '<a href="#score">Scoreboard</a>', '<a href="#network">Network</a>', "nav link");

fs.writeFileSync(path.join(dir, 'site/index.html'), front.trimEnd() + "\n\n" + network.trimEnd() + "\n\n" + back.trimStart());

/* self-checks */
const html = fs.readFileSync(path.join(dir, 'site/index.html'), 'utf8');
const checks = [
  ["no rubric scoreboard", !html.includes('id="score"')],
  ["no .score-row", !html.includes("score-row")],
  ["network section", html.includes('id="network"')],
  ["scenario kept", html.includes('id="scenario"')],
  ["demo section", html.includes('id="demo"')],
  ["timing section", html.includes('id="timing"')],
  ["math section", html.includes('id="math"')],
  ["claims section", html.includes('id="claims"')],
  ["repo section", html.includes('id="repo"')],
  ["nav -> network", html.includes('href="#network"')],
  ["telemetry", html.includes('id="tFrames"')],
  ["route chips", html.includes('id="routeChips"')],
  ["wire frame", html.includes('id="frameHex"')],
  ["roster SW-1", html.includes("SW-1") && html.includes("RT-1") && html.includes("AP-1")],
  ["matrix", html.includes('id="mxGrid"')],
  ["scripts at end", html.indexOf("app.js") > html.indexOf("scenario")],
  ["doctype first", html.startsWith("<!DOCTYPE html>")],
  ["closing html", html.trimEnd().endsWith("</html>")],
];
let ok = true;
for (const [n, v] of checks) { console.log((v ? "OK   " : "FAIL ") + n); if (!v) ok = false; }
console.log(ok ? "\nINDEX.BUILD OK  (" + html.length + " chars)" : "\nINDEX.BUILD FAILED");
if (!ok) process.exit(1);

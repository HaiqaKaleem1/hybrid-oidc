/* build-site.js — reproduces site/index.html from two *tracked* source
 * manifests so the generation is reproducible on a clean clone:
 *
 *   site/.src.index.html   the page WITHOUT the network section (the original
 *                          rubric-scoreboard page; section is removed)
 *   site/.src.net.html     the 05-network section, ready to splice in
 *
 * Run: node build-site.js  (from the repo root).
 * The .src.* manifests are committed on *purpose* — they are the sources of
 * the generated site/index.html, not dev leftovers.
 */
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const srcPage = path.join(dir, 'site/.src.index.html');
const srcNet  = path.join(dir, 'site/.src.net.html');

for (const p of [srcPage, srcNet]) {
  if (!fs.existsSync(p)) throw new Error('missing committed source manifest: ' + p);
}

const pageHTML = fs.readFileSync(srcPage, 'utf8');
const netHTML  = fs.readFileSync(srcNet,  'utf8');

/* 1. delete the rubric scoreboard section */
const iScore = pageHTML.indexOf('<section id="score"');
const scoreEnd = iScore >= 0 ? pageHTML.indexOf('</section>', iScore) : -1;
if (iScore < 0 || scoreEnd < 0) throw new Error('scoreboard anchors not found in .src.index.html');
const page = pageHTML.slice(0, iScore) + pageHTML.slice(pageHTML.indexOf('\n', scoreEnd + 10) + 1);

/* 2. splice the network section in before the repo section */
const iRepo = page.indexOf('<section id="repo"');
if (iRepo < 0) throw new Error('repo anchor not found');
const out = page.slice(0, iRepo) + netHTML + '\n' + page.slice(iRepo);

/* 3. write + self-checks */
const htmlPath = path.join(dir, 'site/index.html');
fs.writeFileSync(htmlPath, out);
const html = out;
const checks = [
  ['no rubric scoreboard',  !html.includes('id="score"')],
  ['no .score-row',         !html.includes('score-row')],
  ['network section',       html.includes('id="network"')],
  ['no scenario section',   !html.includes('id="scenario"')],
  ['no scenario button',    !html.includes('btnRunScenario')],
  ['demo section',          html.includes('id="demo"')],
  ['timing section',        html.includes('id="timing"')],
  ['math section',          html.includes('id="math"')],
  ['claims section',        html.includes('id="claims"')],
  ['repo section',          html.includes('id="repo"')],
  ['nav -> network',        html.includes('href="#network"')],
  ['telemetry',             html.includes('id="tFrames"')],
  ['route chips',           html.includes('id="routeChips"')],
  ['wire frame',            html.includes('id="frameHex"')],
  ['roster SW-1',           html.includes('SW-1') && html.includes('RT-1') && html.includes('AP-1')],
  ['matrix',                html.includes('id="mxGrid"')],
  ['scripts at end',        html.indexOf('app.js') > html.indexOf('id="repo"')],
  ['doctype first',         html.startsWith('<!DOCTYPE html>')],
  ['closing html',          html.trimEnd().endsWith('</html>')],
];
let ok = true;
for (const [n, v] of checks) { console.log((v ? 'OK   ' : 'FAIL ') + n); if (!v) ok = false; }
console.log(ok ? 'INDEX.BUILD OK (' + html.length + ' chars)' : 'INDEX.BUILD FAILED');
if (!ok) process.exit(1);

/* build-site.js — reproduces site/index.html for the final "network" site:
 *
 *   1. starts from site/.src.index.html — the committed page with the OLD
 *      rubric scoreboard section still present
 *   2. deletes the scoreboard section (id="score")
 *   3. splices in the 05-network section from site/.src.net.html
 *   4. writes site/index.html and runs self-checks
 *
 * The manifest files live on disk (they're companion .md-style sources);
 * build-site.js is a small helper the deployment author can ignore.
 *
 * Run: node build-site.js  (from the repo root).
 */
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const srcPage = path.join(dir, 'site/.src.index.html');
const srcNet  = path.join(dir, 'site/.src.net.html');

for (const p of [srcPage, srcNet]) {
  if (!fs.existsSync(p)) throw new Error('missing source manifest: ' + path.basename(p));
}

const pageHTML = fs.readFileSync(srcPage, 'utf8');
const netHTML  = fs.readFileSync(srcNet,  'utf8');

/* 1. delete the rubric scoreboard section */
const iScore = pageHTML.indexOf('<section id="score"');
if (iScore < 0) throw new Error('scoreboard anchor not found');
const scoreEnd = pageHTML.indexOf('</section>', iScore);
if (scoreEnd < 0) throw new Error('scoreboard close not found');
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
  ['no rubric scoreboard', !html.includes('id="score"')],
  ['no .score-row', !html.includes('score-row')],
  ['network section', html.includes('id="network"')],
  ['scenario kept', html.includes('id="scenario"')],
  ['demo section', html.includes('id="demo"')],
  ['timing section', html.includes('id="timing"')],
  ['math section', html.includes('id="math"')],
  ['claims section', html.includes('id="claims"')],
  ['repo section', html.includes('id="repo"')],
  ['nav -> network', html.includes('href="#network"')],
  ['telemetry', html.includes('id="tFrames"')],
  ['route chips', html.includes('id="routeChips"')],
  ['wire frame', html.includes('id="frameHex"')],
  ['roster SW-1', html.includes('SW-1') && html.includes('RT-1') && html.includes('AP-1')],
  ['matrix', html.includes('id="mxGrid"')],
  ['scripts at end', html.indexOf('app.js') > html.indexOf('scenario')],
  ['doctype first', html.startsWith('<!DOCTYPE html>')],
  ['closing html', html.trimEnd().endsWith('</html>')],
];
let ok = true;
for (const [n, v] of checks) { console.log((v ? 'OK   ' : 'FAIL ') + n); if (!v) ok = false; }
console.log(ok ? 'INDEX.BUILD OK (' + html.length + ' chars)' : 'INDEX.BUILD FAILED');
if (!ok) process.exit(1);

# Reproducible evidence bundle

Every file in this directory is the **raw output of a real check run** against
this exact repository, not an edited paste. Regenerate any of them yourself
with the matching command — identical repo, identical engine, identical story.

| Artifact | Produced by | What it proves |
|---|---|---|
| `c-core-selftest.txt` | `cd csrc && make test` | 21 known-answer + structural checks: RFC 4231 HMAC vectors, Python-cross-checked F_p KAT, F₂ linearity, wrap/unwrap round-trip, full rejection surface |
| `timing-harness-run.txt` | `cd csrc && make timing` | measured side-channel evidence: naive comparator latencies 2→22 ns as prefix grows; `hmk_ct_memcmp` flat at 1 ns; full-unwrap medians within 0.1 % across failure cases; Welch \|t\| worst 1.82 < 4.5 → no detectable timing leak |
| `linspread-rank-check.txt` | `python3 tools/linspread_check.py` | rank(M) = 512 (invertible), full word support, ≥ 17/64 bytes changed per input-bit flip |
| `site-core-crosscheck.txt` | `node tools/check_site_core.js` | the browser site core agrees with the C core + Python references on the same vectors |

The Go claim tests (`go test -count=1 ./...`) run in CI on every push — see the
`tests` badge at the top of the main README — so the 13 claim-mapped test
results are re-verified continuously rather than frozen here.

`MANIFEST.sha256` contains the SHA-256 of each artifact; re-run
`sha256sum -c MANIFEST.sha256` after regenerating to see the bundle is
self-consistent from a clean clone.

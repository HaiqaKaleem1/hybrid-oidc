#!/usr/bin/env python3
"""gen_kat.py — emit known-answer vectors for HMK-1 from the Python reference.

The vectors are produced by reference/hmk_ref.py, never by the C core. The Go
test kat_test.go then drives the production cgo path on the same inputs and
requires byte-identical ct and tag, so a divergence between the two
implementations fails CI instead of reaching a release.

    python3 tools/gen_kat.py            # rewrite kat/hmk_vectors.json
    python3 tools/gen_kat.py --check    # fail if the checked-in file has drifted
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference"))

import hmk_ref  # noqa: E402

OUT = ROOT / "kat" / "hmk_vectors.json"


def _h(b: bytes) -> str:
    return b.hex()


CASES = [
    {
        "name": "all-zero inputs",
        "note": "degenerate: both field operands normalise to 1, so kf is a constant",
        "ss": bytes(64),
        "nonce": bytes(16),
        "mk": bytes(32),
        "aad": b"",
    },
    {
        "name": "counting bytes",
        "note": "the reference self-test vector",
        "ss": bytes(range(64)),
        "nonce": bytes(range(16)),
        "mk": bytes(range(32)),
        "aad": b"",
    },
    {
        "name": "oidc context binding",
        "note": "relying-party identity in the AAD, as the demo wraps it",
        "ss": bytes(range(64)),
        "nonce": bytes(range(16)),
        "mk": bytes(range(32)),
        "aad": b"rp=https://idp.example;sub=alice;aud=hybrid-oidc;v=1",
    },
    {
        "name": "zero left half",
        "note": "exercises nonzero normalisation of one field operand",
        "ss": bytes(32) + bytes(range(32)),
        "nonce": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "mk": bytes.fromhex("00" * 31 + "01"),
        "aad": b"ctx",
    },
    {
        "name": "high-bit limbs",
        "note": "operands above p before reduction (reduce-then-normalise path)",
        "ss": bytes.fromhex("ff" * 32) + bytes.fromhex("7f" * 32),
        "nonce": bytes.fromhex("ff" * 16),
        "mk": bytes.fromhex("ff" * 32),
        "aad": b"",
    },
    {
        "name": "empty aad with long nonce pattern",
        "note": "aad is optional; empty must not change the tag domain",
        "ss": bytes((i * 37 + 11) & 0xFF for i in range(64)),
        "nonce": bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        "mk": bytes((i * 101 + 7) & 0xFF for i in range(32)),
        "aad": b"",
    },
]


def build() -> dict:
    vectors = []
    for c in CASES:
        ct, tag = hmk_ref.wrap(c["ss"], c["nonce"], c["mk"], c["aad"])
        back = hmk_ref.unwrap(c["ss"], c["nonce"], ct, tag, c["aad"])
        assert back == c["mk"], c["name"]
        vectors.append(
            {
                "name": c["name"],
                "note": c["note"],
                "ss": _h(c["ss"]),
                "nonce": _h(c["nonce"]),
                "mk": _h(c["mk"]),
                "aad": _h(c["aad"]),
                "ct": _h(ct),
                "tag": _h(tag),
            }
        )
    return {
        "construction": "HMK-1",
        "generated_by": "reference/hmk_ref.py (independent of csrc/)",
        "field": "p = 2^256 - 2^32 + 977",
        "labels": {
            "rk": hmk_ref.LAB_RK.decode(),
            "ks": hmk_ref.LAB_KS.decode(),
            "tag": hmk_ref.LAB_TAG.decode(),
        },
        "vectors": vectors,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify, do not write")
    args = ap.parse_args()

    doc = build()
    text = json.dumps(doc, indent=2) + "\n"

    if args.check:
        if not OUT.exists():
            print(f"missing {OUT.relative_to(ROOT)}; run: python3 tools/gen_kat.py")
            return 1
        current = OUT.read_text()
        if current != text:
            print(
                f"{OUT.relative_to(ROOT)} is stale: the reference implementation and "
                "the committed vectors disagree. Regenerate with tools/gen_kat.py."
            )
            return 1
        print(f"kat: {len(doc['vectors'])} vectors match the Python reference")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(doc['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

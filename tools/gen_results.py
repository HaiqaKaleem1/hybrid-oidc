#!/usr/bin/env python3
"""Regenerate every measured number in the paper from the code that measures it.

The paper's results tables are not typed by hand. This script runs the C
harnesses and the independent checkers, parses what they report, and writes

    artifacts/results.json     machine-readable record of the run
    paper/generated/numbers.tex   LaTeX macros consumed by paper/main.tex

so that a stale figure cannot survive a rebuild: if a measurement fails or
prints something unexpected, this exits non-zero and the paper build stops.

Usage:  python3 tools/gen_results.py [--check]

    --check   only verify that the generated macros match a fresh run; do not
              rewrite any file (used by CI to catch a stale checked-in run).
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSRC = ROOT / "csrc"
OUT_JSON = ROOT / "artifacts" / "results.json"
OUT_TEX = ROOT / "paper" / "generated" / "numbers.tex"

PREFIX_KS = [0, 1, 2, 4, 8, 16, 31]


class Failure(Exception):
    pass


def run(cmd, cwd):
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=600
        )
    except FileNotFoundError:
        raise Failure(f"required executable not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise Failure(f"timed out after 600s: {' '.join(cmd)}")
    if proc.returncode != 0:
        raise Failure(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return proc.stdout


def build_harness():
    # `all` builds libhmk.a plus both binaries executed below. The `timing`
    # target would build only hmk_timing and run it, leaving hmk_selftest
    # missing on a fresh clone (which is how this failed in CI).
    run(["make", "-s", "all"], CSRC)


def parse_timing(out):
    """Parse csrc/timing_demo.c output into prefix / unwrap / t statistics."""
    prefix = {}
    unwrap = {}
    tvals = {}

    section = None
    for line in out.splitlines():
        if "tag-prefix rejection latency" in line:
            section = "prefix"
            continue
        if "full hmk_unwrap latency" in line:
            section = "unwrap"
            continue
        if "Welch t-test" in line:
            section = "t"
            continue

        if section == "prefix":
            m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", line)
            if m:
                k, naive, ct = int(m.group(1)), int(m.group(2)), int(m.group(3))
                # Map the literal k labels the paper's table uses.
                prefix[k] = {"naive_ns": naive, "ct_ns": ct}
                continue
            if prefix and line.strip() == "":
                section = None

        elif section == "unwrap":
            m = re.match(r"^\s*(correct tag|wrong tag \(byte \d+\)|wrong ss)\s+(\d+)\s*$", line)
            if m:
                unwrap[m.group(1)] = int(m.group(2))
                continue

        elif section == "t":
            m = re.match(
                r"^\s*correct vs (wrong tag \(byte \d+\)|wrong ss)\s+\|t\|\s*=\s*([\d.]+)", line
            )
            if m:
                tvals[m.group(1)] = float(m.group(2))

    missing = [k for k in PREFIX_KS if k not in prefix]
    if missing:
        raise Failure(f"timing harness did not report prefix rows for k={missing}")

    for label in ("correct tag", "wrong tag (byte 0)", "wrong tag (byte 31)", "wrong ss"):
        if label not in unwrap:
            raise Failure(f"timing harness did not report unwrap median for {label!r}")
    for label in ("wrong tag (byte 0)", "wrong tag (byte 31)", "wrong ss"):
        if label not in tvals:
            raise Failure(f"timing harness did not report a t value for {label!r}")

    medians = list(unwrap.values())
    spread_pct = (max(medians) - min(medians)) / min(medians) * 100.0

    return {
        "prefix": {str(k): v for k, v in sorted(prefix.items())},
        "unwrap_ns": unwrap,
        "t": tvals,
        "t_worst": max(tvals.values()),
        "spread_pct": round(spread_pct, 2),
    }


def parse_selftest(out):
    checks = len(re.findall(r"^ok\s+\S", out, flags=re.MULTILINE))
    if checks == 0:
        raise Failure("C self-test reported no passing checks")
    if "all checks passed" not in out:
        raise Failure("C self-test did not report success")
    return checks


def parse_linspread(out):
    rank = re.search(r"rank\(M\)\s*=\s*(\d+)\s*\(need\s*(\d+)\)", out)
    flip = re.search(r"min bytes changed per input-bit flip\s*=\s*(\d+)/(\d+)", out)
    if not rank or not flip:
        raise Failure("linspread checker did not report rank and minimum flip size")
    got, want = int(rank.group(1)), int(rank.group(2))
    if got != want:
        raise Failure(f"mixing matrix rank {got} != required {want}")
    return {
        "rank": got,
        "rank_required": want,
        "min_bytes_changed": int(flip.group(1)),
        "word_bytes": int(flip.group(2)),
    }


def collect():
    build_harness()

    timing_raw = run([str(CSRC / "hmk_timing")], ROOT)
    timing = parse_timing(timing_raw)

    selftest_raw = run([str(CSRC / "hmk_selftest")], ROOT)
    checks = parse_selftest(selftest_raw)

    linspread_raw = run([sys.executable, str(ROOT / "tools" / "linspread_check.py")], ROOT)
    linspread = parse_linspread(linspread_raw)

    return {
        "generated_by": "tools/gen_results.py",
        "machine": {
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "timing": timing,
        "selftest_checks": checks,
        "linspread": linspread,
    }


def us(ns):
    """nanoseconds -> microseconds, rounded as the paper's table shows them."""
    return f"{ns / 1000.0:.2f}"


def t2(v):
    return f"{v:.2f}"


def render_tex(res):
    t = res["timing"]
    pre = t["prefix"]
    unw = t["unwrap_ns"]
    tv = t["t"]
    lines = [
        "% Generated by tools/gen_results.py -- do not edit by hand.",
        "% Every value below was measured by the command named in the paper;",
        "% rebuilding without running the generator is a build error by design.",
        "",
        "% --- tag rejection vs. matching prefix (ns) ---",
    ]

    names = {0: "Zero", 1: "One", 2: "Two", 4: "Four", 8: "Eight", 16: "Sixteen", 31: "ThirtyOne"}
    for k in PREFIX_KS:
        lines.append(
            f"\\newcommand{{\\HmkNaiveK{names[k]}}}{{{pre[str(k)]['naive_ns']}}}"
        )
    for k in PREFIX_KS:
        lines.append(f"\\newcommand{{\\HmkCTK{names[k]}}}{{{pre[str(k)]['ct_ns']}}}")

    zero = pre["0"]["naive_ns"]
    last = pre["31"]["naive_ns"]
    ratio = last / zero if zero else 0.0

    lines += [
        "",
        "% --- full unwrap latency (microseconds) ---",
        f"\\newcommand{{\\HmkUnwrapCorrect}}{{{us(unw['correct tag'])}}}",
        f"\\newcommand{{\\HmkUnwrapBadZero}}{{{us(unw['wrong tag (byte 0)'])}}}",
        f"\\newcommand{{\\HmkUnwrapBadLast}}{{{us(unw['wrong tag (byte 31)'])}}}",
        f"\\newcommand{{\\HmkUnwrapBadSecret}}{{{us(unw['wrong ss'])}}}",
        f"\\newcommand{{\\HmkUnwrapSpreadPct}}{{{t['spread_pct']:.1f}}}",
        "",
        "% --- TVLA Welch t ---",
        f"\\newcommand{{\\HmkTBadZero}}{{{t2(tv['wrong tag (byte 0)'])}}}",
        f"\\newcommand{{\\HmkTBadLast}}{{{t2(tv['wrong tag (byte 31)'])}}}",
        f"\\newcommand{{\\HmkTBadSecret}}{{{t2(tv['wrong ss'])}}}",
        f"\\newcommand{{\\HmkTWorst}}{{{t2(t['t_worst'])}}}",
        f"\\newcommand{{\\HmkTThreshold}}{{4.5}}",
        "",
        "% --- naive-comparator growth ---",
        f"\\newcommand{{\\HmkNaiveGrowth}}{{{ratio:.1f}}}",
        "",
        "% --- structural checks ---",
        f"\\newcommand{{\\HmkSelfTestChecks}}{{{res['selftest_checks']}}}",
        f"\\newcommand{{\\HmkMatrixRank}}{{{res['linspread']['rank']}}}",
        f"\\newcommand{{\\HmkMinFlip}}{{{res['linspread']['min_bytes_changed']}/"
        f"{res['linspread']['word_bytes']}}}",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    try:
        res = collect()
    except Failure as exc:
        print(f"gen_results: FAILED\n{exc}", file=sys.stderr)
        return 1

    tex = render_tex(res)
    payload = json.dumps(res, indent=2, sort_keys=True) + "\n"

    if args.check:
        problems = []
        for path, want in ((OUT_TEX, tex), (OUT_JSON, payload)):
            if not path.exists():
                problems.append(f"{path.relative_to(ROOT)} is missing")
            elif path.read_text() != want:
                problems.append(
                    f"{path.relative_to(ROOT)} is stale (re-run tools/gen_results.py)"
                )
        if problems:
            print("gen_results --check: FAILED", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print("gen_results --check: generated numbers are up to date")
        return 0

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_TEX.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(payload)
    OUT_TEX.write_text(tex)
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_TEX.relative_to(ROOT)}")
    print(
        f"  worst |t| = {res['timing']['t_worst']:.2f}, "
        f"unwrap spread = {res['timing']['spread_pct']:.2f}%, "
        f"C self-test checks = {res['selftest_checks']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

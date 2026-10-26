#!/usr/bin/env python3
"""Exact linear-algebra verification of the linspread layer (csrc/linspread.c).

Builds the 512x512 matrix of M = T^3 over F_2 (T = I + S1*R13 + S2*R11 +
S4*R31 + S5*R47 acting on eight 64-bit words) and checks, exhaustively over
the 512 basis vectors:

  * rank(M) = 512            -> M is invertible (bijective diffusion)
  * full word support        -> every output word depends on every input word
  * minimum diffusion        -> bytes changed by one input-bit flip

Usage: python3 tools/linspread_check.py
"""
import random

MASK = (1 << 64) - 1
ROUNDS = 3
TAPS = [(1, 13), (2, 11), (4, 31), (5, 47)]


def rotl(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK if n else x


def apply_t(x):
    out = []
    for i in range(8):
        v = x[i]
        for off, r in TAPS:
            v ^= rotl(x[(i + off) % 8], r)
        out.append(v)
    return out


def linspread_bits(x):
    for _ in range(ROUNDS):
        x = apply_t(x)
    return x


def basis_image(bit):
    x = [0] * 8
    x[bit // 64] = 1 << (bit % 64)
    y = linspread_bits(x)
    v = 0
    for i, w in enumerate(y):
        v |= w << (64 * i)
    return v, y


def rank(rows):
    rows = rows[:]
    r = 0
    for col in range(511, -1, -1):
        piv = None
        for i in range(r, len(rows)):
            if (rows[i] >> col) & 1:
                piv = i
                break
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for i in range(len(rows)):
            if i != r and ((rows[i] >> col) & 1):
                rows[i] ^= rows[r]
        r += 1
    return r


def main():
    rows, support = [], [[0] * 8 for _ in range(8)]
    min_changed = 64
    base = [random.getrandbits(64) for _ in range(8)]
    base_out = linspread_bits(base)

    for bit in range(512):
        v, y = basis_image(bit)
        rows.append(v)
        for i, w in enumerate(y):
            if w:
                support[i][bit // 64] = 1

    # diffusion measured on a random base point (linearity => independent of it)
    for bit in range(512):
        x = base[:]
        x[bit // 64] ^= 1 << (bit % 64)
        y = linspread_bits(x)
        changed = sum(
            1 for i in range(8)
            for byte in range(8)
            if ((y[i] ^ base_out[i]) >> (8 * byte)) & 0xFF
        )
        min_changed = min(min_changed, changed)

    rk = rank(rows)
    full = all(all(r) for r in support)
    print(f"rank(M)          = {rk} (need 512)")
    print(f"full word support = {full}")
    print(f"min bytes changed per input-bit flip = {min_changed}/64")
    assert rk == 512, "M must be invertible"
    assert full, "every output word must depend on every input word"
    assert min_changed >= 16, "diffusion below threshold"
    print("linspread: ALL CHECKS PASSED")


if __name__ == "__main__":
    main()

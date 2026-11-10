#!/usr/bin/env python3
"""hmk_ref.py — an independent reference implementation of the HMK-1 wrap.

This file exists to make the C core checkable by something other than itself.
It is deliberately written the slow, obvious way: big integers for the field,
a byte-at-a-time linear map, and the standard library's SHA-256/HMAC. Nothing
here shares code, headers or constants with csrc/; the only thing the two
implementations have in common is the written specification in paper/.

The production path is C (csrc/hmk.c) because it has to run in constant time.
This path is Python because it has to be *obviously* correct. A divergence
between them is a bug in one of them, and `make kat` fails on it.

Construction (all lengths fixed, no length prefixes, no parsing):

    kf   = GF_combine(ss[0:32], ss[32:64])       # F_p, p = 2^256 - 2^32 + 977
    u    = LinSpread(ss)                          # F_2-linear, rank 512
    kek  = HMAC-SHA256(kf, u || "hmk/v1/rk" || 0x00)
    kmac = HMAC-SHA256(kf, u || "hmk/v1/rk" || 0x01)
    ks   = HMAC-SHA256(kek, "hmk/v1/ks" || nonce)
    ct   = mk XOR ks[0:32]
    tag  = HMAC-SHA256(kmac, "hmk/v1/tag" || nonce || ct || aad)
"""

from __future__ import annotations

import hashlib
import hmac

P = (1 << 256) - (1 << 32) + 977

LAB_RK = b"hmk/v1/rk"
LAB_KS = b"hmk/v1/ks"
LAB_TAG = b"hmk/v1/tag"

SS_LEN = 64
MK_LEN = 32
NONCE_LEN = 16
TAG_LEN = 32
CT_LEN = 32

MASK64 = (1 << 64) - 1


def nonzero_norm(x: int) -> int:
    """Reduce mod p and map 0 to 1, so every input has a multiplicative image.

    The C core applies the same normalisation (`ct_norm_nonzero`) before the
    Montgomery product, which is what makes GF_combine a bijection in each
    argument and keeps a zero half from collapsing the derived key.
    """
    r = x % P
    return 1 if r == 0 else r


def gf_combine(a: bytes, b: bytes) -> bytes:
    """K = A*B mod p, operands read little-endian, result stored little-endian."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError("gf_combine operands must be 32 bytes")
    x = nonzero_norm(int.from_bytes(a, "little"))
    y = nonzero_norm(int.from_bytes(b, "little"))
    return ((x * y) % P).to_bytes(32, "little")


def _rotl64(x: int, n: int) -> int:
    x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _round(x: list[int]) -> list[int]:
    return [
        x[i]
        ^ _rotl64(x[(i + 1) & 7], 13)
        ^ _rotl64(x[(i + 2) & 7], 11)
        ^ _rotl64(x[(i + 4) & 7], 31)
        ^ _rotl64(x[(i + 5) & 7], 47)
        for i in range(8)
    ]


def linspread(data: bytes) -> bytes:
    """Apply the F_2-linear diffusion map M = T^3 to 64 bytes."""
    if len(data) != 64:
        raise ValueError("linspread input must be 64 bytes")
    words = [int.from_bytes(data[8 * i : 8 * i + 8], "little") for i in range(8)]
    words = _round(words)
    words = _round(words)
    words = _round(words)
    return b"".join(w.to_bytes(8, "little") for w in words)


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def derive_keys(ss: bytes) -> tuple[bytes, bytes]:
    if len(ss) != SS_LEN:
        raise ValueError("ss must be 64 bytes")
    kf = gf_combine(ss[:32], ss[32:])
    u = linspread(ss)
    prefix = u + LAB_RK
    return _hmac(kf, prefix + b"\x00"), _hmac(kf, prefix + b"\x01")


def wrap(ss: bytes, nonce: bytes, mk: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    if len(ss) != SS_LEN or len(nonce) != NONCE_LEN or len(mk) != MK_LEN:
        raise ValueError("bad fixed-length input")
    kek, kmac = derive_keys(ss)
    ks = _hmac(kek, LAB_KS + nonce)
    ct = bytes(x ^ y for x, y in zip(mk, ks[:MK_LEN]))
    tag = _hmac(kmac, LAB_TAG + nonce + ct + aad)
    return ct, tag


def unwrap(ss: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Return the master key, or raise ValueError if the tag does not verify."""
    if len(ct) != CT_LEN or len(tag) != TAG_LEN:
        raise ValueError("bad fixed-length input")
    kek, kmac = derive_keys(ss)
    expected = _hmac(kmac, LAB_TAG + nonce + ct + aad)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("hmk: tag verification failed")
    ks = _hmac(kek, LAB_KS + nonce)
    return bytes(x ^ y for x, y in zip(ct, ks[:MK_LEN]))


def selftest() -> None:
    ss = bytes(range(64))
    nonce = bytes(range(16))
    mk = bytes(range(32))
    ct, tag = wrap(ss, nonce, mk)
    assert unwrap(ss, nonce, ct, tag) == mk
    for bad in (bytes(64), bytes(range(1, 65))):
        try:
            unwrap(bad, nonce, ct, tag)
        except ValueError:
            pass
        else:
            raise AssertionError("wrong secret accepted")
    print("hmk reference: self-test passed")


if __name__ == "__main__":
    selftest()

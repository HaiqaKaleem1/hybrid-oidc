#!/usr/bin/env python3
"""Independent KAT generator for the HMK-1 C core.

Recomputes the F_p product vector used in csrc/selftest.c with plain Python
arbitrary-precision arithmetic (no code shared with the C implementation) so
the Montgomery multiplication is checked against an independent reference.

Usage: python3 tools/gen_vectors.py
"""
P = 2**256 - 2**32 + 977  # NIST P-256 field prime

A = int.from_bytes(bytes([0x44] * 8 + [0x33] * 8 + [0x22] * 8 + [0x11] * 8),
                   "little")
B = 0xdeadbeefdeadbeefcafebabecafebabe0123456789abcdef0000000000000001


def le_hex(x: int) -> str:
    return x.to_bytes(32, "little").hex()


print("p          =", hex(P))
print("a          =", hex(A))
print("b          =", hex(B))
print("a*b mod p  =", hex((A * B) % P))
print("LE hex KAT =", le_hex((A * B) % P))
print()
print("Montgomery constants for csrc/gf256.c:")
print("  n0inv     = 0x%016x" % ((-pow(P % 2**64, -1, 2**64)) % 2**64))
print("  R2 limbs  =", [hex(l) for l in
                       [int.from_bytes((2**512 % P).to_bytes(32, "little")
                                       [8 * i:8 * i + 8], "little")
                        for i in range(4)]])

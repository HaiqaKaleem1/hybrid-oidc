/* gf256.h — arithmetic in the 256-bit prime field F_p,
 * p = 2^256 - 2^32 + 977 (the NIST P-256 field prime), implemented with
 * CIOS Montgomery multiplication in constant time.
 *
 * This is the number-theory component of the HMK combiner:
 *   K = (ss_c mod p) * (ss_p mod p)  mod p
 * with both inputs first mapped to F_p^* (0 -> 1, branchless).
 *
 * One-break property: for fixed nonzero a, the map b |-> a*b mod p is a
 * bijection of F_p, so if exactly one component secret is known to the
 * adversary, K is still uniform over F_p (up to O(1/p) normalization bias).
 *
 * Byte order: little-endian (byte i of the 32-byte buffer is limb byte i).
 */
#ifndef HMK_GF256_H
#define HMK_GF256_H

#include <stdint.h>

/* Product mod p of two field elements (inputs reduced branchlessly). */
void hmk_gf_mul_mod(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

/* HMK combiner: nonzero-normalized product mod p. */
void hmk_gf_combine(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

#endif

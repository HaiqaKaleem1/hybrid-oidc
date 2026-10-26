/*
 * ct.h — constant-time primitives for the HMK master-key wrap (side-channel
 * hardening layer).
 *
 * Rules enforced across the whole C core:
 *   - no secret-dependent branches            (cmov / mask arithmetic only)
 *   - no secret-dependent memory indices      (no lookup tables on secrets)
 *   - no early exit on secret comparisons     (full scan, single accumulator)
 *   - explicit zeroization of key material
 */
#ifndef HMK_CT_H
#define HMK_CT_H

#include <stddef.h>
#include <stdint.h>

/* 1 if v == 0 else 0. Branchless (setcc-friendly arithmetic). */
static inline uint8_t hmk_ct_is_zero_u8(uint8_t v)
{
    /* v | (-v) has MSB set iff v != 0 */
    unsigned int m = ((unsigned int)v | (unsigned int)(uint8_t)(0u - v)) >> 7;
    return (uint8_t)(1u ^ m);
}

/*
 * Full-scan comparison. Returns 0 iff a == b. Runs the identical number of
 * iterations and the identical instruction path for every input; a mismatch
 * at byte 0 costs exactly as much as a mismatch at byte n-1.
 */
static inline int hmk_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return (int)hmk_ct_is_zero_u8(d) ^ 1; /* 0 if equal */
}


/*
 * Conditional move: if sel == 1, dst <- src; else dst unchanged.
 * Branchless, no memory access dependent on sel.
 */
static inline void hmk_ct_cmov(uint8_t *dst, const uint8_t *src, size_t n, uint8_t sel)
{
    uint8_t m = (uint8_t)(0u - (sel & 1u));
    size_t i;
    for (i = 0; i < n; i++)
        dst[i] = (uint8_t)((dst[i] & (uint8_t)~m) | (src[i] & m));
}

/* Branchless select between two 64-bit words: sel==1 -> a, sel==0 -> b. */
static inline uint64_t hmk_ct_select_u64(uint64_t a, uint64_t b, uint64_t sel)
{
    uint64_t m = 0u - (sel & 1u);
    return (a & m) | (b & ~m);
}

/* Zeroize through a volatile pointer so the optimizer cannot elide it. */
static inline void hmk_secure_zero(void *v, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--)
        *p++ = 0;
}

#endif /* HMK_CT_H */

/* gf256.c — constant-time F_p arithmetic (CIOS Montgomery multiplication).
 *
 * Side-channel properties:
 *   - all loops are fixed-trip-count (4 limbs); no data-dependent exits
 *   - conditional reduction uses branchless mask selection (cmov pattern)
 *   - no lookup tables indexed by secret data (no log/exp tables)
 *   - comparands never touch memory out of order
 */
#include "gf256.h"

#include "ct.h"

/* p = 2^256 - 2^32 + 977, little-endian 64-bit limbs */
static const uint64_t P_LIMBS[4] = {
    0xffffffff000003d1ULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL, 0xffffffffffffffffULL
};
/* -p^{-1} mod 2^64 */
static const uint64_t N0INV = 0x895950202ddacacfULL;
/* R^2 mod p, R = 2^256 */
static const uint64_t R2_LIMBS[4] = {
    0xfffff85e000e90a1ULL, 0ULL, 0ULL, 0ULL
};

static inline uint64_t load_le64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void store_le64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void load4(uint64_t r[4], const uint8_t b[32])
{
    int i;
    for (i = 0; i < 4; i++)
        r[i] = load_le64(b + 8 * i);
}

static void store4(uint8_t b[32], const uint64_t r[4])
{
    int i;
    for (i = 0; i < 4; i++)
        store_le64(b + 8 * i, r[i]);
}

/* If t >= p (5-limb value in 0..2p), subtract p branchlessly. */
static void ct_cond_sub_p(uint64_t t[5])
{
    uint64_t d[5];
    uint64_t borrow = 0;
    int i;

    for (i = 0; i < 4; i++) {
        uint64_t bi = P_LIMBS[i];
        uint64_t x = t[i] - bi;
        uint64_t b1 = (x > t[i]) ? 1u : 0u;   /* setc — branchless */
        uint64_t y = x - borrow;
        uint64_t b2 = (y > x) ? 1u : 0u;
        d[i] = y;
        borrow = b1 | b2;
    }
    {
        uint64_t x = t[4] - borrow;
        uint64_t b4 = (x > t[4]) ? 1u : 0u;
        d[4] = x;
        /* b4 == 1  <=>  t < p  -> keep t; else take d */
        {
            uint64_t keep = 0u - b4;
            uint64_t take = ~keep;
            for (i = 0; i < 5; i++)
                t[i] = (t[i] & keep) | (d[i] & take);
        }
    }
}

/*
 * CIOS Montgomery multiplication: out = a*b*R^{-1} mod p with R = 2^256.
 * Requires a, b < p. Output reduced to < p with one conditional subtraction
 * (REDC bound gives < 2p).
 */
static void mont_mul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t u[6] = {0, 0, 0, 0, 0, 0};
    int i, j;

    for (i = 0; i < 4; i++) {
        unsigned __int128 z;
        uint64_t c;

        c = 0;
        for (j = 0; j < 4; j++) {
            z = (unsigned __int128)a[j] * b[i] + u[j] + c;
            u[j] = (uint64_t)z;
            c = (uint64_t)(z >> 64);
        }
        z = (unsigned __int128)u[4] + c;
        u[4] = (uint64_t)z;
        u[5] = (uint64_t)(z >> 64);

        /* m = u[0] * n0inv mod 2^64 */
        {
            uint64_t m = u[0] * N0INV;
            z = (unsigned __int128)m * P_LIMBS[0] + u[0];
            c = (uint64_t)(z >> 64); /* low word cancels to 0 */
            for (j = 1; j < 4; j++) {
                z = (unsigned __int128)m * P_LIMBS[j] + u[j] + c;
                u[j - 1] = (uint64_t)z;
                c = (uint64_t)(z >> 64);
            }
            z = (unsigned __int128)u[4] + c;
            u[3] = (uint64_t)z;
            c = (uint64_t)(z >> 64);
            u[4] = u[5] + c; /* final carry-out bounded to 0 by CIOS invariant */
        }
    }

    {
        uint64_t t[5] = {u[0], u[1], u[2], u[3], u[4]};
        ct_cond_sub_p(t);          /* < 2p -> < p */
        ct_cond_sub_p(t);          /* belt-and-braces; idempotent */
        out[0] = t[0]; out[1] = t[1]; out[2] = t[2]; out[3] = t[3];
        hmk_secure_zero(t, sizeof(t));
    }
    hmk_secure_zero(u, sizeof(u));
}

/* Reduce a raw 256-bit value (< 2^256) into [0, p): one conditional sub. */
static void reduce_raw(uint64_t t[4])
{
    uint64_t d[4];
    uint64_t borrow = 0;
    int i;

    for (i = 0; i < 4; i++) {
        uint64_t bi = P_LIMBS[i];
        uint64_t x = t[i] - bi;
        uint64_t b1 = (x > t[i]) ? 1u : 0u;
        uint64_t y = x - borrow;
        uint64_t b2 = (y > x) ? 1u : 0u;
        d[i] = y;
        borrow = b1 | b2;
    }
    {
        uint64_t keep = 0u - borrow;   /* borrow==1 -> t < p -> keep */
        uint64_t take = ~keep;
        for (i = 0; i < 4; i++)
            t[i] = (t[i] & keep) | (d[i] & take);
    }
}

/* t <- t + 1 if t == 0 (maps into F_p^*), branchless. */
static void ct_norm_nonzero(uint64_t t[4])
{
    uint64_t z = t[0] | t[1] | t[2] | t[3];
    uint64_t is_zero = ((z | (0u - z)) >> 63) ^ 1u;
    t[0] += is_zero; /* t == 0 exactly, so no carry can occur */
}

void hmk_gf_mul_mod(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint64_t ra[4], rb[4], ma[4], mb[4], t[4], one[4];

    load4(ra, a);
    load4(rb, b);
    reduce_raw(ra);
    reduce_raw(rb);
    one[0] = 1; one[1] = 0; one[2] = 0; one[3] = 0;

    mont_mul(ma, ra, R2_LIMBS);   /* enter Montgomery domain */
    mont_mul(mb, rb, R2_LIMBS);
    mont_mul(t, ma, mb);          /* a*b*R^{-1} */
    mont_mul(t, t, one);          /* leave Montgomery domain */

    store4(out, t);
    hmk_secure_zero(ra, sizeof(ra));
    hmk_secure_zero(rb, sizeof(rb));
    hmk_secure_zero(ma, sizeof(ma));
    hmk_secure_zero(mb, sizeof(mb));
    hmk_secure_zero(t, sizeof(t));
}

void hmk_gf_combine(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint64_t ra[4], rb[4], ma[4], mb[4], t[4], one[4];

    load4(ra, a);
    load4(rb, b);
    reduce_raw(ra);
    reduce_raw(rb);
    ct_norm_nonzero(ra);          /* F_p^*: guarantees a bijection in b */
    ct_norm_nonzero(rb);
    one[0] = 1; one[1] = 0; one[2] = 0; one[3] = 0;

    mont_mul(ma, ra, R2_LIMBS);
    mont_mul(mb, rb, R2_LIMBS);
    mont_mul(t, ma, mb);
    mont_mul(t, t, one);

    store4(out, t);
    hmk_secure_zero(ra, sizeof(ra));
    hmk_secure_zero(rb, sizeof(rb));
    hmk_secure_zero(ma, sizeof(ma));
    hmk_secure_zero(mb, sizeof(mb));
    hmk_secure_zero(t, sizeof(t));
}

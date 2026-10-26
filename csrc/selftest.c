/* selftest.c — KATs + structural checks for the HMK-1 C core.
 *
 * Vectors:
 *   - SHA-256 FIPS 180-4 examples
 *   - HMAC-SHA256 RFC 4231 cases 1-2
 *   - F_p product computed independently in Python (tools/gen_vectors.py)
 *   - wrap/unwrap roundtrip + every rejection path
 *   - linspread: F_2-linearity, full word support, diffusion threshold
 */
#include "ct.h"
#include "gf256.h"
#include "hmac_sha256.h"
#include "hmk.h"
#include "linspread.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void hexdump(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int check_hex(const char *name, const uint8_t *got, size_t n, const char *want)
{
    size_t i;
    for (i = 0; i < n; i++) {
        int hi = hexval(want[2 * i]), lo = hexval(want[2 * i + 1]);
        if (hi < 0 || lo < 0 || got[i] != (uint8_t)((hi << 4) | lo)) {
            printf("FAIL %s\n  got  ", name);
            hexdump(got, n);
            printf("\n  want %s\n", want);
            failures++;
            return 0;
        }
    }
    printf("ok   %s\n", name);
    return 1;
}

static int check(const char *name, int cond)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond)
        failures++;
    return cond;
}

/* deterministic byte source: SHA-256 over an increasing counter */
static uint64_t ctr;
static void rnd(uint8_t *out, size_t n)
{
    while (n > 0) {
        uint8_t block[32];
        uint8_t c[8];
        size_t i;
        for (i = 0; i < 8; i++)
            c[i] = (uint8_t)(ctr >> (8 * i));
        ctr++;
        hmk_sha256(c, 8, block);
        if (n < 32)
            memcpy(out, block, n);
        else
            memcpy(out, block, 32);
        out += (n < 32) ? n : 32;
        n -= (n < 32) ? n : 32;
        hmk_secure_zero(block, sizeof(block));
    }
}

static void test_sha256(void)
{
    uint8_t d[32];
    hmk_sha256("", 0, d);
    check_hex("sha256(\"\")", d, 32,
              "e3b0c44298fc1c149afbf4c8996fb924"
              "27ae41e4649b934ca495991b7852b855");
    hmk_sha256("abc", 32 - 29, d);
    check_hex("sha256(\"abc\")", d, 32,
              "ba7816bf8f01cfea414140de5dae2223"
              "b00361a396177a9cb410ff61f20015ad");
}

static void test_hmac(void)
{
    uint8_t key[20], d[32];
    memset(key, 0x0b, sizeof(key));
    hmk_hmac(key, 20, "Hi There", 8, d);
    check_hex("hmac rfc4231 tc1", d, 32,
              "b0344c61d8db38535ca8afceaf0bf12b"
              "881dc200c9833da726e9376c2e32cff7");
    hmk_hmac((const uint8_t *)"Jefe", 4,
             "what do ya want for nothing?", 28, d);
    check_hex("hmac rfc4231 tc2", d, 32,
              "5bdcc146bf60754e6a042426089575c7"
              "5a003f089d2739839dec58b964ec3843");
}

static void test_gf(void)
{
    /* a*b mod p, computed independently in Python (tools/gen_vectors.py) */
    static const uint8_t a[32] = {
        0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
        0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
        0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
    };
    static const uint8_t b[32] = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,
        0xbe,0xba,0xfe,0xca,0xbe,0xba,0xfe,0xca,
        0xef,0xbe,0xad,0xde,0xef,0xbe,0xad,0xde
    };
    uint8_t out[32];
    uint8_t z[32], one[32], zo[32];

    hmk_gf_mul_mod(out, a, b);
    check_hex("gf mul mod p (python KAT, LE bytes)", out, 32,
              "556378d057d9cfadd7368cf85987655a"
              "a17bf3a1c44b2cff7905d63eedbc887d");

    /* 0 * 5 == 0 (raw mul allows zero) */
    memset(z, 0, 32);
    memset(one, 0, 32);
    one[0] = 5;
    hmk_gf_mul_mod(zo, z, one);
    check("gf 0*x == 0", hmk_ct_memcmp(zo, z, 32) == 0);

    /* combiner: nonzero normalization — combine(0, x) behaves as combine(1, x) */
    {
        uint8_t c0[32], c1[32], x[32];
        rnd(x, 32);
        hmk_gf_combine(c0, z, x);
        memset(one, 0, 32);
        one[0] = 1;
        hmk_gf_combine(c1, one, x);
        check("gf combine normalizes 0 -> 1", hmk_ct_memcmp(c0, c1, 32) == 0);
    }
}

static void test_linspread(void)
{
    uint8_t x[64], y[64], z[64], d[64];
    int bit, i, j;
    int supp[8][8];

    /* linearity over F_2: L(x)^L(y)^L(0) == L(x^y) */
    rnd(x, 64);
    rnd(y, 64);
    memset(z, 0, 64);
    {
        uint8_t l0[64], lx[64], ly[64], lxy[64], t[64];
        hmk_linspread(l0, z);
        hmk_linspread(lx, x);
        hmk_linspread(ly, y);
        for (i = 0; i < 64; i++)
            t[i] = (uint8_t)(lx[i] ^ ly[i] ^ l0[i]);
        for (i = 0; i < 64; i++)
            d[i] = (uint8_t)(x[i] ^ y[i]);
        hmk_linspread(lxy, d);
        check("linspread is F_2-linear", hmk_ct_memcmp(t, lxy, 64) == 0);
        check("linspread(0) == 0", hmk_ct_memcmp(l0, z, 64) == 0);
    }

    /* full word support + per-flip diffusion, exhaustive over 512 basis bits */
    memset(supp, 0, sizeof(supp));
    {
        int min_changed = 64;
        uint8_t base[64], flipped[64], o1[64], o2[64];
        rnd(base, 64);
        hmk_linspread(o1, base);
        for (bit = 0; bit < 512; bit++) {
            int changed = 0;
            memcpy(flipped, base, 64);
            flipped[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            hmk_linspread(o2, flipped);
            for (i = 0; i < 64; i++)
                if (o1[i] != o2[i])
                    changed++;
            for (i = 0; i < 8; i++)
                for (j = 0; j < 8; j++)
                    for (int q = 0; q < 8; q++)
                        if (o1[8 * i + q] != o2[8 * i + q])
                            supp[i][j] = 1;
            if (changed < min_changed)
                min_changed = changed;
        }
        {
            int full = 1;
            for (i = 0; i < 8; i++)
                for (j = 0; j < 8; j++)
                    if (!supp[i][j])
                        full = 0;
            check("linspread: every output word depends on every input word", full);
        }
        check("linspread diffusion >= 16/64 bytes per input bit",
              min_changed >= 16);
        printf("       (min changed bytes: %d/64)\n", min_changed);
    }
}

static void test_hmk(void)
{
    uint8_t ss[64], nonce[16], mk[32], ct[32], tag[32], out[32];
    uint8_t zeros[32];
    const uint8_t aad[] = "rp.example.com";

    memset(zeros, 0, sizeof(zeros));
    rnd(ss, 64);
    rnd(nonce, 16);
    rnd(mk, 32);

    check("wrap ok", hmk_wrap(ss, nonce, aad, sizeof(aad) - 1, mk, ct, tag) == 0);
    check("unwrap roundtrip",
          hmk_unwrap(ss, nonce, aad, sizeof(aad) - 1, ct, tag, out) == 0 &&
          hmk_ct_memcmp(out, mk, 32) == 0);

    /* 1. tag mismatch at byte 0 */
    {
        uint8_t t2[32];
        memcpy(t2, tag, 32);
        t2[0] ^= 1;
        memset(out, 0xee, 32);
        check("reject tag[0] mismatch",
              hmk_unwrap(ss, nonce, aad, sizeof(aad) - 1, ct, t2, out) != 0 &&
              hmk_ct_memcmp(out, zeros, 32) == 0);
    }
    /* 2. tag mismatch at last byte */
    {
        uint8_t t2[32];
        memcpy(t2, tag, 32);
        t2[31] ^= 1;
        memset(out, 0xee, 32);
        check("reject tag[31] mismatch",
              hmk_unwrap(ss, nonce, aad, sizeof(aad) - 1, ct, t2, out) != 0 &&
              hmk_ct_memcmp(out, zeros, 32) == 0);
    }
    /* 3. tampered ciphertext */
    {
        uint8_t c2[32];
        memcpy(c2, ct, 32);
        c2[7] ^= 0x80;
        memset(out, 0xee, 32);
        check("reject tampered ct",
              hmk_unwrap(ss, nonce, aad, sizeof(aad) - 1, c2, tag, out) != 0 &&
              hmk_ct_memcmp(out, zeros, 32) == 0);
    }
    /* 4. wrong hybrid secret (attacker without the KEM secret) */
    {
        uint8_t ss2[64];
        rnd(ss2, 64);
        memset(out, 0xee, 32);
        check("reject wrong ss",
              hmk_unwrap(ss2, nonce, aad, sizeof(aad) - 1, ct, tag, out) != 0 &&
              hmk_ct_memcmp(out, zeros, 32) == 0);
    }
    /* 5. wrong nonce */
    {
        uint8_t n2[16];
        memcpy(n2, nonce, 16);
        n2[0] ^= 1;
        memset(out, 0xee, 32);
        check("reject wrong nonce",
              hmk_unwrap(ss, n2, aad, sizeof(aad) - 1, ct, tag, out) != 0 &&
              hmk_ct_memcmp(out, zeros, 32) == 0);
    }
    /* 6. wrong aad (channel/context binding) */
        memset(out, 0xee, 32);
    check("reject wrong aad",
          hmk_unwrap(ss, nonce, (const uint8_t *)"evil.example", 13,
                     ct, tag, out) != 0 &&
          hmk_ct_memcmp(out, zeros, 32) == 0);

    /* 7. determinism: same inputs -> same bytes (nonce reuse is visible) */
    {
        uint8_t ct2[32], tag2[32];
        hmk_wrap(ss, nonce, aad, sizeof(aad) - 1, mk, ct2, tag2);
        check("wrap is deterministic for fixed (ss, nonce, mk, aad)",
              hmk_ct_memcmp(ct, ct2, 32) == 0 &&
              hmk_ct_memcmp(tag, tag2, 32) == 0);
    }
}

int main(void)
{
    printf("HMK-1 C core self-test\n");
    printf("======================\n");
    test_sha256();
    test_hmac();
    test_gf();
    test_linspread();
    test_hmk();
    if (failures) {
        printf("\n%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}

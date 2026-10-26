/* hmk.c — HMK-1 master-key wrap/unwrap. See hmk.h for the construction. */
#include "hmk.h"

#include "ct.h"
#include "gf256.h"
#include "hmac_sha256.h"
#include "linspread.h"

#include <string.h>

static const uint8_t LAB_RK[]  = "hmk/v1/rk";
static const uint8_t LAB_KS[]  = "hmk/v1/ks";
static const uint8_t LAB_TAG[] = "hmk/v1/tag";

/* kek = HMAC(K_f, u || LAB_RK || 0x00), kmac = HMAC(K_f, u || LAB_RK || 0x01) */
static void derive_keys(const uint8_t ss[HMK_SS_LEN],
                         uint8_t kek[HMK_HMAC_LEN],
                         uint8_t kmac[HMK_HMAC_LEN])
{
    uint8_t kf[32];
    uint8_t u[64];
    uint8_t msg[64 + sizeof(LAB_RK)]; /* u || lab (2-byte counter appended) */
    hmk_hmac_ctx ctx;

    hmk_gf_combine(kf, ss, ss + 32);   /* number-theoretic combiner  */
    hmk_linspread(u, ss);              /* F_2 linear diffusion        */

    memcpy(msg, u, 64);
    memcpy(msg + 64, LAB_RK, sizeof(LAB_RK) - 1);

    /* two fixed HMAC computations, byte counter is a loop index (public) */
    {
        uint8_t ctr;
        ctr = 0x00;
        hmk_hmac_init(&ctx, kf, sizeof(kf));
        hmk_hmac_update(&ctx, msg, 64 + sizeof(LAB_RK) - 1);
        hmk_hmac_update(&ctx, &ctr, 1);
        hmk_hmac_final(&ctx, kek);

        ctr = 0x01;
        hmk_hmac_init(&ctx, kf, sizeof(kf));
        hmk_hmac_update(&ctx, msg, 64 + sizeof(LAB_RK) - 1);
        hmk_hmac_update(&ctx, &ctr, 1);
        hmk_hmac_final(&ctx, kmac);
    }

    hmk_secure_zero(kf, sizeof(kf));
    hmk_secure_zero(u, sizeof(u));
    hmk_secure_zero(msg, sizeof(msg));
    hmk_secure_zero(&ctx, sizeof(ctx));
}

int hmk_wrap(const uint8_t ss[HMK_SS_LEN],
             const uint8_t nonce[HMK_NONCE_LEN],
             const uint8_t *aad, size_t aad_len,
             const uint8_t mk[HMK_MK_LEN],
             uint8_t ct[HMK_CT_LEN],
             uint8_t tag[HMK_TAG_LEN])
{
    uint8_t kek[HMK_HMAC_LEN];
    uint8_t kmac[HMK_HMAC_LEN];
    uint8_t ks[HMK_HMAC_LEN];
    size_t i;
    hmk_hmac_ctx ctx;

    if (ct == 0 || tag == 0)
        return -1;

    derive_keys(ss, kek, kmac);

    /* keystream: KS = HMAC(kek, LAB_KS || nonce) — one fixed block */
    {
        uint8_t ksm[9 + HMK_NONCE_LEN];
        memcpy(ksm, LAB_KS, 9);
        memcpy(ksm + 9, nonce, HMK_NONCE_LEN);
        hmk_hmac(kek, HMK_HMAC_LEN, ksm, 9 + HMK_NONCE_LEN, ks);
        hmk_secure_zero(ksm, sizeof(ksm));
    }

    for (i = 0; i < HMK_MK_LEN; i++)
        ct[i] = (uint8_t)(mk[i] ^ ks[i]);

    /* tag = HMAC(kmac, LAB_TAG || nonce || ct || aad) */
    {
        uint8_t th[32 + HMK_NONCE_LEN + HMK_CT_LEN];
        size_t off = 0;
        memcpy(th + off, LAB_TAG, 9); off += 9;
        memcpy(th + off, nonce, HMK_NONCE_LEN); off += HMK_NONCE_LEN;
        memcpy(th + off, ct, HMK_CT_LEN); off += HMK_CT_LEN;
        hmk_hmac_init(&ctx, kmac, HMK_HMAC_LEN);
        hmk_hmac_update(&ctx, th, off);
        if (aad != 0 && aad_len > 0)
            hmk_hmac_update(&ctx, aad, aad_len);
        hmk_hmac_final(&ctx, tag);
        hmk_secure_zero(th, sizeof(th));
    }

    hmk_secure_zero(kek, sizeof(kek));
    hmk_secure_zero(kmac, sizeof(kmac));
    hmk_secure_zero(ks, sizeof(ks));
    hmk_secure_zero(&ctx, sizeof(ctx));
    return 0;
}

int hmk_unwrap(const uint8_t ss[HMK_SS_LEN],
               const uint8_t nonce[HMK_NONCE_LEN],
               const uint8_t *aad, size_t aad_len,
               const uint8_t ct[HMK_CT_LEN],
               const uint8_t tag[HMK_TAG_LEN],
               uint8_t mk_out[HMK_MK_LEN])
{
    uint8_t kek[HMK_HMAC_LEN];
    uint8_t kmac[HMK_HMAC_LEN];
    uint8_t ks[HMK_HMAC_LEN];
    uint8_t cand[HMK_MK_LEN];
    uint8_t calc[HMK_TAG_LEN];
    hmk_hmac_ctx ctx;
    int cmp;
    size_t i;

    /* identical work on every call — no early exits anywhere below */
    derive_keys(ss, kek, kmac);

    {
        uint8_t ksm[9 + HMK_NONCE_LEN];
        memcpy(ksm, LAB_KS, 9);
        memcpy(ksm + 9, nonce, HMK_NONCE_LEN);
        hmk_hmac(kek, HMK_HMAC_LEN, ksm, 9 + HMK_NONCE_LEN, ks);
        hmk_secure_zero(ksm, sizeof(ksm));
    }

    for (i = 0; i < HMK_MK_LEN; i++)
        cand[i] = (uint8_t)(ct[i] ^ ks[i]);

    {
        uint8_t th[32 + HMK_NONCE_LEN + HMK_CT_LEN];
        size_t off = 0;
        memcpy(th + off, LAB_TAG, 9); off += 9;
        memcpy(th + off, nonce, HMK_NONCE_LEN); off += HMK_NONCE_LEN;
        memcpy(th + off, ct, HMK_CT_LEN); off += HMK_CT_LEN;
        hmk_hmac_init(&ctx, kmac, HMK_HMAC_LEN);
        hmk_hmac_update(&ctx, th, off);
        if (aad != 0 && aad_len > 0)
            hmk_hmac_update(&ctx, aad, aad_len);
        hmk_hmac_final(&ctx, calc);
        hmk_secure_zero(th, sizeof(th));
    }

    /* full-scan compare; identical cost for every mismatch position */
    cmp = hmk_ct_memcmp(tag, calc, HMK_TAG_LEN);

    /* branchless publish: zeros unless the tag verified */
    memset(mk_out, 0, HMK_MK_LEN);
    hmk_ct_cmov(mk_out, cand, HMK_MK_LEN, (uint8_t)(cmp == 0 ? 1 : 0));

    hmk_secure_zero(kek, sizeof(kek));
    hmk_secure_zero(kmac, sizeof(kmac));
    hmk_secure_zero(ks, sizeof(ks));
    hmk_secure_zero(cand, sizeof(cand));
    hmk_secure_zero(calc, sizeof(calc));
    hmk_secure_zero(&ctx, sizeof(ctx));
    return cmp;
}

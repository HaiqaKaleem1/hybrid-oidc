/* hmac_sha256.c — HMAC-SHA256.
 *
 * Control flow depends only on key/message *lengths*, which are public and
 * fixed for every HMK invocation (keys are 32 B, messages are
 * label||fixed-fields). No secret-dependent branches or lookups.
 */
#include "hmac_sha256.h"

#include "ct.h"

#include <string.h>

void hmk_hmac_init(hmk_hmac_ctx *ctx, const uint8_t *key, size_t klen)
{
    uint8_t kpad[64];
    uint8_t khash[32];
    uint8_t ipad[64];
    const uint8_t *k = key;
    size_t i;

    if (klen > 64) {
        hmk_sha256(key, klen, khash);
        k = khash;
        klen = HMK_SHA256_LEN;
    }
    memset(kpad, 0, sizeof(kpad));
    memcpy(kpad, k, klen);
    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(kpad[i] ^ 0x36u);
        ctx->okey[i] = (uint8_t)(kpad[i] ^ 0x5cu);
    }
    hmk_sha256_init(&ctx->inner);
    hmk_sha256_update(&ctx->inner, ipad, 64);
    hmk_secure_zero(ipad, sizeof(ipad));
    hmk_secure_zero(kpad, sizeof(kpad));
    hmk_secure_zero(khash, sizeof(khash));
}

void hmk_hmac_update(hmk_hmac_ctx *ctx, const void *data, size_t len)
{
    hmk_sha256_update(&ctx->inner, data, len);
}

void hmk_hmac_final(hmk_hmac_ctx *ctx, uint8_t out[HMK_HMAC_LEN])
{
    uint8_t ihash[HMK_SHA256_LEN];
    hmk_sha256_ctx outer;

    hmk_sha256_final(&ctx->inner, ihash); /* zeroes ctx->inner */
    hmk_sha256_init(&outer);
    hmk_sha256_update(&outer, ctx->okey, 64);
    hmk_sha256_update(&outer, ihash, HMK_SHA256_LEN);
    hmk_sha256_final(&outer, out);
    hmk_secure_zero(ihash, sizeof(ihash));
    hmk_secure_zero(ctx, sizeof(*ctx));
}

void hmk_hmac(const uint8_t *key, size_t klen, const void *msg, size_t mlen,
              uint8_t out[HMK_HMAC_LEN])
{
    hmk_hmac_ctx ctx;
    hmk_hmac_init(&ctx, key, klen);
    hmk_hmac_update(&ctx, msg, mlen);
    hmk_hmac_final(&ctx, out);
}

/* hmac_sha256.h — HMAC-SHA256 (RFC 2104). */
#ifndef HMK_HMAC_SHA256_H
#define HMK_HMAC_SHA256_H

#include "sha256.h"

#include <stddef.h>
#include <stdint.h>

#define HMK_HMAC_LEN HMK_SHA256_LEN

typedef struct {
    hmk_sha256_ctx inner;
    uint8_t okey[64];
} hmk_hmac_ctx;

void hmk_hmac_init(hmk_hmac_ctx *ctx, const uint8_t *key, size_t klen);
void hmk_hmac_update(hmk_hmac_ctx *ctx, const void *data, size_t len);
void hmk_hmac_final(hmk_hmac_ctx *ctx, uint8_t out[HMK_HMAC_LEN]);
void hmk_hmac(const uint8_t *key, size_t klen, const void *msg, size_t mlen,
              uint8_t out[HMK_HMAC_LEN]);

#endif

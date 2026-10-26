/* sha256.h — FIPS 180-4 SHA-256 (public standard hash; the HMK construction
 * composes it, it is not used as a stand-alone "pre-existing cipher"). */
#ifndef HMK_SHA256_H
#define HMK_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define HMK_SHA256_LEN 32

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t buf[64];
    size_t buflen;
} hmk_sha256_ctx;

void hmk_sha256_init(hmk_sha256_ctx *ctx);
void hmk_sha256_update(hmk_sha256_ctx *ctx, const void *data, size_t len);
void hmk_sha256_final(hmk_sha256_ctx *ctx, uint8_t out[HMK_SHA256_LEN]);
void hmk_sha256(const void *data, size_t len, uint8_t out[HMK_SHA256_LEN]);

#endif

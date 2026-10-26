/* linspread.c — see linspread.h for the matrix definition.
 *
 * Verified properties (tools/linspread_check.py, mirrored by the C selftest's
 * support check):
 *   - rank 512 over F_2 (invertible linear layer)
 *   - every one of the 8 output words depends on all 8 input words
 *   - a single input-bit flip changes >= 17 of the 64 output bytes (measured
 *     minimum over the 512 basis vectors)
 */
#include "linspread.h"

#include "ct.h"

#include <string.h>

static inline uint64_t rotl64(uint64_t x, unsigned int n)
{
    return (x << n) | (x >> (64u - n));
}

static inline void round_t(uint64_t y[8], const uint64_t x[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        y[i] = x[i]
             ^ rotl64(x[(i + 1) & 7], 13)
             ^ rotl64(x[(i + 2) & 7], 11)
             ^ rotl64(x[(i + 4) & 7], 31)
             ^ rotl64(x[(i + 5) & 7], 47);
    }
}

void hmk_linspread(uint8_t out[64], const uint8_t in[64])
{
    uint64_t a[8], b[8];
    int i;

    for (i = 0; i < 8; i++) {
        a[i] = (uint64_t)in[8 * i]
             | ((uint64_t)in[8 * i + 1] << 8)
             | ((uint64_t)in[8 * i + 2] << 16)
             | ((uint64_t)in[8 * i + 3] << 24)
             | ((uint64_t)in[8 * i + 4] << 32)
             | ((uint64_t)in[8 * i + 5] << 40)
             | ((uint64_t)in[8 * i + 6] << 48)
             | ((uint64_t)in[8 * i + 7] << 56);
    }

    round_t(b, a);   /* M = T^3 */
    round_t(a, b);
    round_t(b, a);

    for (i = 0; i < 8; i++) {
        uint64_t v = b[i];
        int j;
        for (j = 0; j < 8; j++)
            out[8 * i + j] = (uint8_t)(v >> (8 * j));
    }
    hmk_secure_zero(a, sizeof(a));
    hmk_secure_zero(b, sizeof(b));
}

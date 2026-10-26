/*
 * timing_demo.c — side-channel measurement harness (the "rigorous test"
 * the Cryptographer track asks for).
 *
 * Measures, with interleaved sampling and per-sample batching:
 *
 *  1. Tag rejection latency as a function of *how many leading bytes of the
 *     presented tag match* the expected one (k = 0,1,2,4,8,16,31):
 *       - naive verifier: early-exit byte loop (classic short-circuit leak)
 *       - HMK verifier:   hmk_ct_memcmp full scan (flat by construction)
 *   A non-flat naive line is a byte-by-byte tag-recovery oracle; the HMK
 *   line must be statistically flat.
 *
 *  2. Full hmk_unwrap latency for correct vs wrong tags (mismatch at byte 0,
 *   byte 31): identical instruction path -> flat by construction.
 *
 * Reports mean ns/call per group. Exit code 0 always (a measurement tool,
 * not an assertion); the Go test in pkg/hybridoidc asserts flatness of (2).
 */
#include "ct.h"
#include "hmk.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile uint64_t sink;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Vulnerable reference: classic short-circuit comparison. */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
static int naive_verify(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/* Prevents the compiler from CSE-ing the loop-invariant compare out of the
 * measurement batch (would silently report 0 ns). */
#if defined(__GNUC__)
#define BARRIER() __asm__ __volatile__("" ::: "memory")
#else
#define BARRIER() ((void)0)
#endif

#define BATCH 512
#define SAMPLES 400

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Welch's unequal-variance t statistic over two sample arrays. */
static double welch_t(const uint64_t *a, const uint64_t *b, int n, int m)
{
    double ma = 0.0, mb = 0.0, va = 0.0, vb = 0.0;
    int i;
    for (i = 0; i < n; i++)
        ma += (double)a[i];
    ma /= n;
    for (i = 0; i < m; i++)
        mb += (double)b[i];
    mb /= m;
    for (i = 0; i < n; i++)
        va += ((double)a[i] - ma) * ((double)a[i] - ma);
    va /= (n - 1);
    for (i = 0; i < m; i++)
        vb += ((double)b[i] - mb) * ((double)b[i] - mb);
    vb /= (m - 1);
    {
        double denom = sqrt(va / n + vb / m);
        if (denom == 0.0)
            return 0.0;
        return (ma - mb) / denom;
    }
}

static uint64_t median(uint64_t *v, int n)
{
    qsort(v, (size_t)n, sizeof(uint64_t), cmp_u64);
    return v[n / 2];
}

static void seed_deterministic(uint8_t *b, size_t n, uint8_t s)
{
    size_t i;
    uint32_t x = 0x9e3779b9u ^ s;
    for (i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = (uint8_t)x;
    }
}

/* median-of-batches mean latency for naive vs ct over prefix length k */
static void measure_prefix(int k, uint64_t *naive_ns, uint64_t *ct_ns)
{
    uint8_t stored[32], presented[32];
    uint64_t naive_s[SAMPLES], ct_s[SAMPLES];
    int s, j;

    seed_deterministic(stored, 32, 1);
    memcpy(presented, stored, 32);
    presented[k] ^= 0xff; /* mismatch exactly at byte k (k<32) */

    for (s = 0; s < SAMPLES; s++) {
        uint64_t t0, acc = 0;
        /* interleave to cancel frequency drift */
        t0 = now_ns();
        for (j = 0; j < BATCH; j++) {
            BARRIER();
            sink += (uint64_t)naive_verify(presented, stored, 32);
        }
        acc = now_ns() - t0;
        naive_s[s] = acc / BATCH;

        t0 = now_ns();
        for (j = 0; j < BATCH; j++) {
            BARRIER();
            sink += (uint64_t)(hmk_ct_memcmp(presented, stored, 32) == 0);
        }
        acc = now_ns() - t0;
        ct_s[s] = acc / BATCH;
    }
    *naive_ns = median(naive_s, SAMPLES);
    *ct_ns = median(ct_s, SAMPLES);
}

static void measure_unwrap(void)
{
    static uint64_t all[4][SAMPLES];
    uint8_t ss[64], nonce[16], mk[32], ct[32], tag[32], out[32];
    const uint8_t aad[] = "rp.example.com";
    struct {
        const char *name;
        int mode; /* 0 correct, 1 mismatch@0, 2 mismatch@31, 3 wrong ss */
    } cases[4] = {
        {"correct tag      ", 0},
        {"wrong tag (byte 0)", 1},
        {"wrong tag (byte 31)", 2},
        {"wrong ss         ", 3},
    };
    int c, s, j, k;
    uint8_t wrongss[64];

    seed_deterministic(ss, 64, 2);
    seed_deterministic(nonce, 16, 3);
    seed_deterministic(mk, 32, 4);
    seed_deterministic(wrongss, 64, 9);
    hmk_wrap(ss, nonce, aad, sizeof(aad) - 1, mk, ct, tag);

    /*
     * Interleaved, rotating measurement order (standard TVLA practice):
     * every round samples all four cases, with the case order shifted by
     * the round index, so CPU frequency drift and thermal throttling hit
     * every distribution equally instead of biasing one.
     */
    printf("\nfull hmk_unwrap latency (median of %d rounds x %d calls,\n"
           "cases interleaved in rotating order to cancel temporal drift)\n",
           SAMPLES, BATCH);
    for (s = 0; s < SAMPLES; s++) {
        for (j = 0; j < 4; j++) {
            int ci = (j + s) % 4;
            uint8_t t2[32];
            const uint8_t *ssp = ss;
            uint64_t t0;
            memcpy(t2, tag, 32);
            if (cases[ci].mode == 1)
                t2[0] ^= 0xff;
            if (cases[ci].mode == 2)
                t2[31] ^= 0xff;
            if (cases[ci].mode == 3)
                ssp = wrongss;
            t0 = now_ns();
            for (k = 0; k < BATCH; k++) {
                BARRIER();
                sink += (uint64_t)(hmk_unwrap(ssp, nonce, aad, sizeof(aad) - 1,
                                              ct, t2, out) == 0);
            }
            all[ci][s] = (now_ns() - t0) / BATCH;
        }
    }
    printf("  %-22s %12s\n", "case", "ns/call");
    for (c = 0; c < 4; c++)
        printf("  %-22s %12llu\n", cases[c].name,
               (unsigned long long)median(all[c], SAMPLES));

    /* TVLA-style leakage assessment: Welch's t between the correct-tag
     * latency distribution and each failure distribution, over the
     * interleaved samples above. A leaking implementation (early exit,
     * skipped work) produces |t| far above the 4.5 threshold. */
    {
        double worst = 0.0;
        printf("\nWelch t-test, correct vs failing unwrap "
               "(constant-time passes |t| < 4.5):\n");
        for (c = 1; c < 4; c++) {
            double t = welch_t(all[0], all[c], SAMPLES, SAMPLES);
            double at = fabs(t);
            if (at > worst)
                worst = at;
            printf("  correct vs %-18s |t| = %6.3f   %s\n",
                   cases[c].name, at, at < 4.5 ? "PASS" : "FAIL");
        }
        printf("  worst |t| = %.3f -> %s\n", worst,
               worst < 4.5 ? "NO DETECTABLE TIMING LEAK" : "LEAK DETECTED");
    }
}

int main(void)
{
    static const int ks[] = {0, 1, 2, 4, 8, 16, 31};
    size_t n = sizeof(ks) / sizeof(ks[0]);
    size_t i;

    printf("HMK-1 side-channel measurement\n");
    printf("==============================\n");
    printf("tag-prefix rejection latency: presented tag matches stored tag\n");
    printf("for the first k bytes, then mismatches.\n\n");
    printf("  %4s %18s %18s\n", "k", "naive (ns)", "HMK ct (ns)");
    for (i = 0; i < n; i++) {
        uint64_t a, b;
        measure_prefix(ks[i], &a, &b);
        printf("  %4d %18llu %18llu\n", ks[i],
               (unsigned long long)a, (unsigned long long)b);
    }

    measure_unwrap();

    printf("\nsink=%llu (prevents dead-code elimination)\n",
           (unsigned long long)sink);
    return 0;
}

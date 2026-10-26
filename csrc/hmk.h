/*
 * hmk.h — HMK-1 master-key wrap: the constant-time C core of this submission
 * (Cryptographer track).
 *
 * Pipeline (all fixed-length encodings, all constant time):
 *
 *   ss = ss_c || ss_p          composite-hybrid KEM secret (Alg 3, 64 B)
 *   K_f = N(ss_c) * N(ss_p)    F_p field combiner        [number theory]
 *   u   = M * ss               invertible F_2 matrix mix  [linear algebra]
 *   RK  = HMAC-SHA256(K_f, u)  dual-input extractor -> kek || kmac
 *   KS  = HMAC(kek, lab||n)    fixed one-block keystream
 *   ct  = mk XOR KS            master-key encryption (no pre-existing cipher)
 *   tag = HMAC(kmac, lab||n||ct||aad)   encrypt-then-MAC, full-scan verify
 *
 * No pre-existing block/stream cipher (AES, ChaCha, ...) encrypts the
 * plaintext: the keystream is derived through the HMK construction itself.
 *
 * Unwrap executes the identical instruction path on every call — success,
 * failure, tag mismatch at byte 0 or byte 31 — so the only thing an
 * adversary can learn from timing is the verification outcome, which the
 * protocol already reveals.
 */
#ifndef HMK_HMK_H
#define HMK_HMK_H

#include <stddef.h>
#include <stdint.h>

#define HMK_SS_LEN    64 /* ss_c || ss_p from Alg 3 */
#define HMK_MK_LEN    32 /* master key */
#define HMK_NONCE_LEN 16 /* random per-wrap nonce */
#define HMK_TAG_LEN   32
#define HMK_CT_LEN    HMK_MK_LEN

/* Wrap master key mk under hybrid secret ss. Returns 0 on success. */
int hmk_wrap(const uint8_t ss[HMK_SS_LEN],
             const uint8_t nonce[HMK_NONCE_LEN],
             const uint8_t *aad, size_t aad_len,
             const uint8_t mk[HMK_MK_LEN],
             uint8_t ct[HMK_CT_LEN],
             uint8_t tag[HMK_TAG_LEN]);

/*
 * Unwrap. Constant time with respect to every input: runs derive/keystream/
 *tag regardless of validity, full-scan tag compare, branchless conditional
 * move of the candidate key into mk_out (zeroed unless the tag verifies).
 * Returns 0 iff the wrap authenticates.
 */
int hmk_unwrap(const uint8_t ss[HMK_SS_LEN],
               const uint8_t nonce[HMK_NONCE_LEN],
               const uint8_t *aad, size_t aad_len,
               const uint8_t ct[HMK_CT_LEN],
               const uint8_t tag[HMK_TAG_LEN],
               uint8_t mk_out[HMK_MK_LEN]);

#endif

// Package hybridoidc — cgo bindings to the constant-time C core (HMK-1).
//
// The master-key wrap/unwrap is implemented in C (csrc/) with explicit
// side-channel hardening: no secret-dependent branches, no secret-indexed
// tables, full-scan tag comparison, fixed work per call regardless of
// outcome. These wrappers validate encodings at the boundary and expose
// idiomatic Go errors; all secret handling stays in C.
package hybridoidc

/*
#cgo CFLAGS: -I${SRCDIR}/../../csrc
#include "hmk.h"
#include "gf256.h"
#include "linspread.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// HMK fixed-length encodings (mirrors csrc/hmk.h).
const (
	HMKSSLen    = int(C.HMK_SS_LEN)    // 64: ss_c || ss_p from Alg 3
	HMKMKLen    = int(C.HMK_MK_LEN)    // 32: master key
	HMKNonceLen = int(C.HMK_NONCE_LEN) // 16: random per-wrap nonce
	HMKTagLen   = int(C.HMK_TAG_LEN)   // 32
	HMKCTLen    = int(C.HMK_CT_LEN)    // 32
)

// ErrTagMismatch reports that the HMK tag did not verify (wrong secret,
// tampered ciphertext, wrong nonce, or wrong AAD context binding).
var ErrTagMismatch = errors.New("hmk: tag verification failed")

// ErrHMKLength reports a violation of a fixed-length encoding at the boundary.
var ErrHMKLength = errors.New("hmk: wrong-length input")

// WrapMasterKey encrypts and authenticates a 32-byte master key under the
// 64-byte hybrid KEM secret (Alg 3 output) using the constant-time C core.
//
// nonce must be 16 fresh random bytes per wrap (any nonce reuse under the
// same secret is a one-time-pad reuse); aad binds the wrap to a context
// string (e.g. the relying-party identity) and may be empty.
func WrapMasterKey(ss, nonce, mk, aad []byte) (ct, tag []byte, err error) {
	if len(ss) != HMKSSLen || len(nonce) != HMKNonceLen || len(mk) != HMKMKLen {
		return nil, nil, fmt.Errorf("%w: ss=%d nonce=%d mk=%d", ErrHMKLength, len(ss), len(nonce), len(mk))
	}
	ct = make([]byte, HMKCTLen)
	tag = make([]byte, HMKTagLen)
	aadp := aadOrDummy(aad)
	rc := C.hmk_wrap(
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&aadp[0])),
		C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&mk[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)
	if rc != 0 {
		return nil, nil, errors.New("hmk: wrap failed")
	}
	return ct, tag, nil
}

// UnwrapMasterKey verifies the tag in constant time and, only if it holds,
// returns the recovered master key. On any failure it returns ErrTagMismatch
// with a nil key. The C implementation performs identical work on every
// call — success or failure, mismatch at byte 0 or byte 31.
func UnwrapMasterKey(ss, nonce, ct, tag, aad []byte) ([]byte, error) {
	if len(ss) != HMKSSLen || len(nonce) != HMKNonceLen || len(ct) != HMKCTLen || len(tag) != HMKTagLen {
		return nil, fmt.Errorf("%w: ss=%d nonce=%d ct=%d tag=%d", ErrHMKLength, len(ss), len(nonce), len(ct), len(tag))
	}
	mk := make([]byte, HMKMKLen)
	aadp := aadOrDummy(aad)
	rc := C.hmk_unwrap(
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&aadp[0])),
		C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		(*C.uint8_t)(unsafe.Pointer(&mk[0])),
	)
	if rc != 0 {
		return nil, ErrTagMismatch
	}
	return mk, nil
}

// aadOrDummy returns a non-nil pointer-safe slice for empty AAD (C accepts
// NULL only together with len 0; this keeps &v[0] patterns valid).
func aadOrDummy(aad []byte) []byte {
	if len(aad) == 0 {
		return []byte{0}
	}
	return aad
}

// GFCombine exposes the F_p field combiner (K = a*b mod p, Montgomery,
// nonzero-normalized) so the demo/TUI can visualize the number-theoretic
// stage. Inputs here are already-shared demo values; never expose this on
// real secrets to an untrusted caller.
func GFCombine(a, b []byte) ([]byte, error) {
	if len(a) != 32 || len(b) != 32 {
		return nil, fmt.Errorf("%w: gf inputs must be 32 bytes", ErrHMKLength)
	}
	out := make([]byte, 32)
	C.hmk_gf_combine(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&a[0])),
		(*C.uint8_t)(unsafe.Pointer(&b[0])),
	)
	return out, nil
}

// LinSpread exposes the rank-512 F_2 linear diffusion layer (M = T^3) for
// demo/visualization output.
func LinSpread(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, fmt.Errorf("%w: linspread input must be 64 bytes", ErrHMKLength)
	}
	out := make([]byte, 64)
	C.hmk_linspread(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&in[0])),
	)
	return out, nil
}

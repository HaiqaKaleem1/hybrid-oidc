package hybridoidc

import (
	"bytes"
	"errors"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func hmkFixture(t *testing.T) (ss, nonce, mk, ct, tag []byte) {
	t.Helper()
	ss = make([]byte, HMKSSLen)
	nonce = make([]byte, HMKNonceLen)
	mk = make([]byte, HMKMKLen)
	r := rand.New(rand.NewSource(1))
	r.Read(ss)
	r.Read(nonce)
	r.Read(mk)
	var err error
	ct, tag, err = WrapMasterKey(ss, nonce, mk, []byte("rp.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	return ss, nonce, mk, ct, tag
}

// Round-trip and every rejection path of the C core through cgo.
func TestHMKWrapUnwrap(t *testing.T) {
	ss, nonce, mk, ct, tag := hmkFixture(t)
	aad := []byte("rp.example.com")

	got, err := UnwrapMasterKey(ss, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("honest unwrap failed: %v", err)
	}
	if !bytes.Equal(got, mk) {
		t.Fatal("unwrap returned wrong master key")
	}

	// each tamper surface must reject with ErrTagMismatch and no key
	tamper := []struct {
		name  string
		ss    []byte
		nonce []byte
		ct    []byte
		tag   []byte
		aad   []byte
	}{
		{"tag[0]", ss, nonce, ct, flip(tag, 0), aad},
		{"tag[31]", ss, nonce, ct, flip(tag, 31), aad},
		{"ct[7]", ss, nonce, flip(ct, 7), tag, aad},
		{"wrong ss", flip(ss, 13), nonce, ct, tag, aad},
		{"wrong nonce", ss, flip(nonce, 0), ct, tag, aad},
		{"wrong aad", ss, nonce, ct, tag, []byte("evil.example")},
	}
	for _, tc := range tamper {
		out, err := UnwrapMasterKey(tc.ss, tc.nonce, tc.ct, tc.tag, tc.aad)
		if !errors.Is(err, ErrTagMismatch) {
			t.Errorf("%s: want ErrTagMismatch, got err=%v out=%x", tc.name, err, out)
		}
		if out != nil {
			t.Errorf("%s: rejected unwrap must not return key material", tc.name)
		}
	}

	// fixed-length enforcement at the boundary
	if _, _, err := WrapMasterKey(ss[:63], nonce, mk, aad); !errors.Is(err, ErrHMKLength) {
		t.Errorf("short ss: want ErrHMKLength, got %v", err)
	}
	if _, err := UnwrapMasterKey(ss, nonce, ct, tag[:10], aad); !errors.Is(err, ErrHMKLength) {
		t.Errorf("short tag: want ErrHMKLength, got %v", err)
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 0xff
	return c
}

// End-to-end: Alg 3 hybrid KEM produces ss; HMK-1 wraps the master key;
// decapsulation on the other side unwraps it. This is the "applicable
// environment" pipeline the demo/TUI drives.
func TestHMKEndToEndWithHybridKEM(t *testing.T) {
	h := NewDefaultHybridKEM()
	pk, sk, err := h.KgenH()
	if err != nil {
		t.Fatal(err)
	}
	ss, ctKEM, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}

	mk := make([]byte, HMKMKLen)
	rand.New(rand.NewSource(2)).Read(mk)
	nonce := make([]byte, HMKNonceLen)
	rand.New(rand.NewSource(3)).Read(nonce)

	wct, wtag, err := WrapMasterKey(ss, nonce, mk, []byte("oidc:issuer"))
	if err != nil {
		t.Fatal(err)
	}

	ss2, err := h.DecH(sk, ctKEM)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapMasterKey(ss2, nonce, wct, wtag, []byte("oidc:issuer"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mk) {
		t.Fatal("end-to-end master key mismatch")
	}

	// a MITM who tampers the KEM ciphertext cannot unwrap
	tampered := append([]byte{}, ctKEM...)
	tampered[0] ^= 0x01
	if ss3, err := h.DecH(sk, tampered); err == nil {
		if _, err := UnwrapMasterKey(ss3, nonce, wct, wtag, []byte("oidc:issuer")); !errors.Is(err, ErrTagMismatch) {
			t.Fatal("tampered KEM ct must lead to rejected unwrap")
		}
	}
}

// medianDuration sorts a copy and returns the median.
func median(d []time.Duration) time.Duration {
	c := append([]time.Duration{}, d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// Side-channel regression test: hmk_unwrap must take statistically
// indistinguishable time whether verification succeeds, fails at byte 0,
// fails at byte 31, or runs under the wrong secret. A short-circuiting or
// early-return implementation would show order-of-magnitude differences
// (see csrc/timing_demo.c for the naive-vs-ct comparison harness).
//
// Tolerance is deliberately generous (2x) to stay robust on noisy shared
// runners while still catching structural leaks (~10x).
func TestHMKUnwrapConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	ss, nonce, mk, ct, tag := hmkFixture(t)
	aad := []byte("rp.example.com")
	tag0 := flip(tag, 0)
	tag31 := flip(tag, 31)
	wrongSS := flip(ss, 3)

	cases := []struct {
		name string
		ss   []byte
		tag  []byte
		ok   bool
	}{
		{"correct", ss, tag, true},
		{"mismatch@0", ss, tag0, false},
		{"mismatch@31", ss, tag31, false},
		{"wrong ss", wrongSS, tag, false},
	}
	const n = 600
	medians := make(map[string]time.Duration, len(cases))
	for _, tc := range cases {
		ds := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			out, err := UnwrapMasterKey(tc.ss, nonce, ct, tc.tag, aad)
			el := time.Since(start)
			if tc.ok != (err == nil) {
				t.Fatalf("%s: unexpected result err=%v", tc.name, err)
			}
			if tc.ok && !bytes.Equal(out, mk) {
				t.Fatalf("%s: wrong key", tc.name)
			}
			ds = append(ds, el)
		}
		medians[tc.name] = median(ds)
	}

	var lo, hi time.Duration
	for name, m := range medians {
		t.Logf("unwrap median %-12s %v", name, m)
		if lo == 0 || m < lo {
			lo = m
		}
		if m > hi {
			hi = m
		}
	}
	if lo == 0 || hi > 2*lo {
		t.Fatalf("timing leak: medians spread %v..%v exceeds 2x (short-circuit behavior?)", lo, hi)
	}
	_ = mk
}

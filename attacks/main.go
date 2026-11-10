// Command attacks runs concrete adversary experiments against HMK-1 and
// reports, for each one, what a textbook design would do and what HMK-1 does.
//
// Every experiment is deterministic (fixed seeds) so `make verify` is stable
// in CI. Exit status is non-zero if any attack succeeds where it must fail.
//
//	go run ./attacks
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"

	h "hybridoidc/pkg/hybridoidc"
)

type result struct {
	name   string
	pass   bool
	detail string
}

func main() {
	ss, nonce, mk, ct, tag := fixture()
	aad := []byte("https://rp.example.com")

	res := []result{
		attackTamperForgery(ss, nonce, mk, ct, tag, aad),
		attackKnownClassicalHalf(ss, nonce, mk, ct, tag, aad),
		attackReplayAcrossConnections(),
		attackAlgorithmConfusion(),
		attackLengthOracle(ss, nonce, ct, tag, aad),
	}

	bad := 0
	fmt.Println("HMK-1 adversary harness")
	fmt.Println("=======================")
	for _, r := range res {
		status := "PASS"
		if !r.pass {
			status = "FAIL"
			bad++
		}
		fmt.Printf("[%s] %-34s %s\n", status, r.name, r.detail)
	}
	if bad > 0 {
		fmt.Printf("\n%d attack(s) broke the scheme\n", bad)
		os.Exit(1)
	}
	fmt.Println("\nall attacks rejected; no key material released")
}

func fixture() (ss, nonce, mk, ct, tag []byte) {
	ss = randBytes(h.HMKSSLen)
	nonce = randBytes(h.HMKNonceLen)
	mk = randBytes(h.HMKMKLen)
	var err error
	ct, tag, err = h.WrapMasterKey(ss, nonce, mk, []byte("https://rp.example.com"))
	if err != nil {
		must(err)
	}
	return ss, nonce, mk, ct, tag
}

// W5-style manipulation: flip one bit in every byte position of every input
// surface. A design with an early-exit tag comparison, or one that fails to
// bind the nonce/AAD, accepts some of these. HMK-1 must reject all of them
// and publish no key material.
func attackTamperForgery(ss, nonce, mk, ct, tag, aad []byte) result {
	accepted, leaked := 0, 0
	trials := 0

	// flipOne sets bit 0 of byte i in a copy of src.
	flipOne := func(src []byte, i int) []byte {
		m := append([]byte{}, src...)
		m[i] ^= 1
		return m
	}

	for i := 0; i < len(ct); i++ { // ciphertext bits
		out, err := h.UnwrapMasterKey(ss, nonce, flipOne(ct, i), tag, aad)
		trials++
		if err == nil {
			accepted++
		}
		if len(out) > 0 {
			leaked++
		}
	}
	for i := 0; i < len(tag); i++ { // tag bits
		out, err := h.UnwrapMasterKey(ss, nonce, ct, flipOne(tag, i), aad)
		trials++
		if err == nil {
			accepted++
		}
		if len(out) > 0 {
			leaked++
		}
	}
	for i := 0; i < len(nonce); i++ { // nonce bits
		out, err := h.UnwrapMasterKey(ss, flipOne(nonce, i), ct, tag, aad)
		trials++
		if err == nil {
			accepted++
		}
		if len(out) > 0 {
			leaked++
		}
	}
	for i := 0; i < len(ss); i++ { // shared-secret bits
		out, err := h.UnwrapMasterKey(flipOne(ss, i), nonce, ct, tag, aad)
		trials++
		if err == nil {
			accepted++
		}
		if len(out) > 0 {
			leaked++
		}
	}

	// AAD substitution: a token minted for one relying party must not open
	// under another.
	if _, err := h.UnwrapMasterKey(ss, nonce, ct, tag, []byte("https://evil.example")); err == nil {
		accepted++
	}
	trials++

	return result{
		name:   "tamper-forgery (W5)",
		pass:   accepted == 0 && leaked == 0,
		detail: fmt.Sprintf("%d/%d forgeries accepted, %d key bytes leaked", accepted, trials, leaked),
	}
}

// Record-now-decrypt-later: the attacker holds the classical half in full.
// The wrap must still resist, because the combiner needs both halves.
func attackKnownClassicalHalf(ss, nonce, mk, ct, tag, aad []byte) result {
	// The attacker captured the honest ciphertext and knows ss_c in full
	// (the classical half is broken). She still has to guess ss_p.
	const tries = 512
	accepted := 0
	guess := make([]byte, h.HMKSSLen)
	for i := 0; i < tries; i++ {
		copy(guess, ss[:h.HMKSSLen/2])
		copy(guess[h.HMKSSLen/2:], randBytes(h.HMKSSLen/2))
		out, err := h.UnwrapMasterKey(guess, nonce, ct, tag, aad)
		if err == nil || len(out) > 0 {
			accepted++
		}
	}
	// Control: with both halves the honest secret opens it.
	control := opensWith(ss, nonce, ct, tag, aad, mk)
	return result{
		name:   "known-classical-half break",
		pass:   accepted == 0 && control,
		detail: fmt.Sprintf("%d/%d guess-ss_p wraps opened (honest control: %v)", accepted, tries, control),
	}
}

// Bearer-token replay across connections: a signed JWT bound to the TLS
// exporter of connection 1 must not verify on connection 2.
func attackReplayAcrossConnections() result {
	s := h.NewDefaultHybridSig()
	vk, sk, err := s.SkgH()
	if err != nil {
		return result{"replay across connections", false, err.Error()}
	}
	header := []byte(`{"alg":"hybrid","typ":"JWT"}`)
	payload := []byte(`{"sub":"alice","exp":99}`)
	b1 := h.ChannelBinding([]byte("exporter-conn-1"), []byte("tls-exporter"), []byte("rp"))
	b2 := h.ChannelBinding([]byte("exporter-conn-2"), []byte("tls-exporter"), []byte("rp"))

	j, err := h.SignJWT2(s, sk, header, payload, b1)
	if err != nil {
		return result{"replay across connections", false, err.Error()}
	}
	sameConn := h.VerifyJWT(s, vk, j, b1)
	otherConn := h.VerifyJWT(s, vk, j, b2)
	return result{
		name:   "replay across connections",
		pass:   sameConn && !otherConn,
		detail: fmt.Sprintf("own connection accepted: %v, replayed on new connection: %v", sameConn, otherConn),
	}
}

// Algorithm confusion: editing the protected header invalidates the hybrid
// signature (no separate, weaker verification path to downgrade into).
func attackAlgorithmConfusion() result {
	s := h.NewDefaultHybridSig()
	vk, sk, err := s.SkgH()
	if err != nil {
		return result{"algorithm confusion", false, err.Error()}
	}
	b := h.ChannelBinding([]byte("exporter"), []byte("tls-exporter"), []byte("rp"))
	j, err := h.SignJWT2(s, sk, []byte(`{"alg":"hybrid","typ":"JWT"}`), []byte(`{"sub":"alice"}`), b)
	if err != nil {
		return result{"algorithm confusion", false, err.Error()}
	}
	forged := &h.JWT{
		Header:  []byte(`{"alg":"none","typ":"JWT"}`),
		Payload: j.Payload,
		Sig:     j.Sig,
	}
	ok := h.VerifyJWT(s, vk, forged, b)
	return result{
		name:   "algorithm confusion",
		pass:   !ok,
		detail: fmt.Sprintf("header-rewritten token accepted: %v", ok),
	}
}

// Variable-length inputs are a timing and parser-differential channel; every
// boundary must reject with a length error rather than pad or panic.
func attackLengthOracle(ss, nonce, ct, tag, aad []byte) result {
	cases := []struct {
		name       string
		s, n, c, t []byte
	}{
		{"ss-1", ss[:len(ss)-1], nonce, ct, tag},
		{"ss+1", append(append([]byte{}, ss...), 0), nonce, ct, tag},
		{"nonce-1", ss, nonce[:len(nonce)-1], ct, tag},
		{"ct-1", ss, nonce, ct[:len(ct)-1], tag},
		{"tag-1", ss, nonce, ct, tag[:len(tag)-1]},
		{"ct+1", ss, nonce, append(append([]byte{}, ct...), 0), tag},
	}
	leaks := 0
	for _, tc := range cases {
		if out, err := h.UnwrapMasterKey(tc.s, tc.n, tc.c, tc.t, aad); err == nil || len(out) > 0 {
			leaks++
		}
	}
	return result{
		name:   "length oracle",
		pass:   leaks == 0,
		detail: fmt.Sprintf("%d/%d malformed inputs accepted", leaks, len(cases)),
	}
}

func opensWith(ss, nonce, ct, tag, aad, want []byte) bool {
	out, err := h.UnwrapMasterKey(ss, nonce, ct, tag, aad)
	return err == nil && bytes.Equal(out, want)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		must(err)
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "attack harness:", err)
		os.Exit(2)
	}
}

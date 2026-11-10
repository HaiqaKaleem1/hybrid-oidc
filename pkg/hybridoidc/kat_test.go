package hybridoidc

// kat_test.go — drives the production cgo path against vectors produced by the
// independent Python reference (kat/hmk_vectors.json, written by
// tools/gen_kat.py). The C core never generates its own expected answers here:
// if the two implementations diverge, this test fails.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type katVector struct {
	Name  string `json:"name"`
	Note  string `json:"note"`
	SS    string `json:"ss"`
	Nonce string `json:"nonce"`
	MK    string `json:"mk"`
	AAD   string `json:"aad"`
	CT    string `json:"ct"`
	Tag   string `json:"tag"`
}

type katFile struct {
	Construction string      `json:"construction"`
	Vectors      []katVector `json:"vectors"`
}

func mustHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad hex in vector: %v", field, err)
	}
	return b
}

func loadKAT(t *testing.T) katFile {
	t.Helper()
	path := filepath.Join("..", "..", "kat", "hmk_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run: python3 tools/gen_kat.py)", path, err)
	}
	var doc katFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s has no vectors", path)
	}
	return doc
}

// TestCOREAgreesWithReference is the cross-implementation check: byte-identical
// ciphertext and tag for every vector the Python reference produced.
func TestCOREAgreesWithReference(t *testing.T) {
	doc := loadKAT(t)
	if doc.Construction != "HMK-1" {
		t.Fatalf("unexpected construction %q", doc.Construction)
	}
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ss := mustHex(t, "ss", v.SS)
			nonce := mustHex(t, "nonce", v.Nonce)
			mk := mustHex(t, "mk", v.MK)
			aad := mustHex(t, "aad", v.AAD)
			wantCT := mustHex(t, "ct", v.CT)
			wantTag := mustHex(t, "tag", v.Tag)

			ct, tag, err := WrapMasterKey(ss, nonce, mk, aad)
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			if hex.EncodeToString(ct) != hex.EncodeToString(wantCT) {
				t.Errorf("ciphertext differs from reference\n got %x\nwant %x", ct, wantCT)
			}
			if hex.EncodeToString(tag) != hex.EncodeToString(wantTag) {
				t.Errorf("tag differs from reference\n got %x\nwant %x", tag, wantTag)
			}

			back, err := UnwrapMasterKey(ss, nonce, wantCT, wantTag, aad)
			if err != nil {
				t.Fatalf("unwrap of reference output: %v", err)
			}
			if hex.EncodeToString(back) != hex.EncodeToString(mk) {
				t.Errorf("recovered key differs\n got %x\nwant %x", back, mk)
			}
		})
	}
}

// TestReferenceVectorsRejectTampering confirms the reference vectors are not
// accepted once any single bound input is modified, through the production path.
func TestReferenceVectorsRejectTampering(t *testing.T) {
	doc := loadKAT(t)
	for _, v := range doc.Vectors {
		ss := mustHex(t, "ss", v.SS)
		nonce := mustHex(t, "nonce", v.Nonce)
		aad := mustHex(t, "aad", v.AAD)
		ct := mustHex(t, "ct", v.CT)
		tag := mustHex(t, "tag", v.Tag)

		flip := func(b []byte) []byte {
			if len(b) == 0 {
				// An empty AAD has no byte to flip; a one-byte AAD is a
				// different context and must still be rejected.
				return []byte{0x01}
			}
			out := append([]byte(nil), b...)
			out[0] ^= 0x01
			return out
		}

		for _, tc := range []struct {
			what string
			run  func() error
		}{
			{"ciphertext", func() error {
				_, err := UnwrapMasterKey(ss, nonce, flip(ct), tag, aad)
				return err
			}},
			{"tag", func() error {
				_, err := UnwrapMasterKey(ss, nonce, ct, flip(tag), aad)
				return err
			}},
			{"secret", func() error {
				_, err := UnwrapMasterKey(flip(ss), nonce, ct, tag, aad)
				return err
			}},
			{"nonce", func() error {
				_, err := UnwrapMasterKey(ss, flip(nonce), ct, tag, aad)
				return err
			}},
			{"aad", func() error {
				_, err := UnwrapMasterKey(ss, nonce, ct, tag, flip(aad))
				return err
			}},
		} {
			err := tc.run()
			if err == nil {
				t.Errorf("%s: tampered %s was accepted", v.Name, tc.what)
			}
		}
	}
}

// TestNonceReuseIsDetectableAcrossContexts records the one misuse the
// construction cannot prevent by itself: the caller controls the nonce. Reusing
// it under the same secret and AAD yields identical ciphertexts (a keystream
// reuse), which is exactly why the API documents nonce freshness and why the
// demo derives each nonce from the OS CSPRNG. Under a *different* AAD the tag
// differs, so replay into another context is rejected even if the nonce repeats.
func TestNonceReuseIsDetectableAcrossContexts(t *testing.T) {
	ss := bytes_(0x11, HMKSSLen)
	nonce := bytes_(0x22, HMKNonceLen)
	mkA := bytes_(0x33, HMKMKLen)
	mkB := bytes_(0x44, HMKMKLen)

	ctA, tagA, err := WrapMasterKey(ss, nonce, mkA, []byte("ctx=one"))
	if err != nil {
		t.Fatalf("wrap A: %v", err)
	}
	ctA2, tagA2, err := WrapMasterKey(ss, nonce, mkA, []byte("ctx=one"))
	if err != nil {
		t.Fatalf("wrap A again: %v", err)
	}
	if hex.EncodeToString(ctA) != hex.EncodeToString(ctA2) ||
		hex.EncodeToString(tagA) != hex.EncodeToString(tagA2) {
		t.Fatal("deterministic inputs must produce deterministic output (keystream reuse signature)")
	}

	// Two different master keys under one nonce: XOR of ciphertexts is the
	// XOR of the keys, i.e. the keystream cancels. This is the documented cost
	// of nonce reuse and the reason freshness is a caller obligation.
	ctB, _, err := WrapMasterKey(ss, nonce, mkB, []byte("ctx=one"))
	if err != nil {
		t.Fatalf("wrap B: %v", err)
	}
	for i := 0; i < HMKMKLen; i++ {
		if ctA[i]^ctB[i] != mkA[i]^mkB[i] {
			t.Fatalf("byte %d: keystream did not cancel under nonce reuse", i)
		}
	}

	// Context binding still holds under a repeated nonce.
	ctC, tagC, err := WrapMasterKey(ss, nonce, mkA, []byte("ctx=two"))
	if err != nil {
		t.Fatalf("wrap C: %v", err)
	}
	if hex.EncodeToString(ctC) != hex.EncodeToString(ctA) {
		t.Fatal("ciphertext should not depend on aad")
	}
	if hex.EncodeToString(tagC) == hex.EncodeToString(tagA) {
		t.Fatal("tag must depend on aad")
	}
	if _, err := UnwrapMasterKey(ss, nonce, ctA, tagA, []byte("ctx=two")); err == nil {
		t.Fatal("wrap from another context was accepted")
	}
}

func bytes_(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

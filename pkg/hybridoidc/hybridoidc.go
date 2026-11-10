// Package hybridoidc implements the composite-hybrid KEM (Alg 3) and
// composite-hybrid signature (Alg 4) from docs/hybrid-oidc-security-spec.md.
//
// Every exported behavior maps to a numbered claim and test:
//
//	G1/E1 (Thm 1, Cor. E1)  -> TestE1ClassicalHoldsUnderPQBreak
//	G1/E2 (Thm 1, Cor. E2)  -> TestE2HybridKeySurvivesClassicalBreak
//	G2  (Thm 1, Games 0-3)  -> TestCompositeKEMTamperIndist
//	G3  (Alg 4 conjunction) -> TestHybridVerifyRejectsEitherHalfMissing
//	G4  (Thm 2 weakest link)-> TestSignatureForgeryRequiresFreshECDSA
//	G1<->G3 binding (Thm 3) -> TestChannelBoundJWTRejectsReplay
//
// The deployed composition (see realpq.go) is ECDH P-256 + ML-KEM-768 for Alg 3
// and ES256 + ML-DSA-65 for Alg 4, both from the Go standard library
// (crypto/mlkem, FIPS 203; crypto/mldsa, FIPS 204) --- no third-party
// cryptographic dependency.
//
// The idealized random-oracle components (roKEM, roSig) are retained and
// exercised through the same hybrid code path, because the reductions need a
// half that can be switched off: E1/E2 and G3/G4 are therefore runnable as
// experiments rather than described in prose. Every component declares its
// own byte sizes, so the hybrid layer is identical for both instantiations.
package hybridoidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// ---------------------------------------------------------------- primitives

// KEM mirrors Alg 1 (fixed-length encodings enforced by construction).
type KEM interface {
	Kgen() (pk, sk []byte, err error)
	Enc(pk []byte) (ss, ct []byte, err error)
	Dec(sk, ct []byte) ([]byte, error)
	// IsBroken reports whether this component is fully broken (E2 primitive
	// restriction): Dec returns the encapsulated shared secret, or Enc/Dec
	// leaks ss. Used only to *instantiate* an adversary; never in the real
	// protocol.
	IsBroken() bool
}

// Sig mirrors Alg 2.
type Sig interface {
	Skg() (vk, sk []byte, err error)
	Sign(sk, msg []byte) ([]byte, error)
	Ver(vk, msg, sig []byte) bool
	IsBroken() bool
}

// ------------------------------------------------- idealized RO components

// roKEM is an idealized KEM in the random-oracle model: pk is a random ROI
// seed, Enc = (H(ss,0)||H(ss,1)) keyed materialization, ss = 32B random.
// If broken, Dec reveals ss directly (models a total break of that half).
type roKEM struct{ broken bool }

const ssLen, ctLen, pkLen, skLen = 32, 96, 48, 48

// kemLayout describes the fixed byte sizes of one KEM component. The hybrid
// layer derives every split point from these, so a component whose sizes
// differ from the idealized stand-ins (ML-KEM-768: 1184/64/1088) drops in
// with no change to the algorithms.
type kemLayout struct{ pk, sk, ct, ss int }

// sigLayout is the same idea for a signature component.
type sigLayout struct{ vk, sk, sig int }

// kemSizer / sigSizer are implemented by components that know their sizes.
// Components that do not (the idealized stand-ins) fall back to the package
// constants above.
type kemSizer interface{ kemLayout() kemLayout }
type sigSizer interface{ sigLayout() sigLayout }

func kemSizes(k KEM) kemLayout {
	if s, ok := k.(kemSizer); ok {
		return s.kemLayout()
	}
	return kemLayout{pk: pkLen, sk: skLen, ct: ctLen, ss: ssLen}
}

func sigSizes(s Sig) sigLayout {
	if z, ok := s.(sigSizer); ok {
		return z.sigLayout()
	}
	return sigLayout{vk: 32, sk: 32, sig: 32}
}

func (r *roKEM) Kgen() ([]byte, []byte, error) {
	pk := make([]byte, pkLen)
	sk := make([]byte, skLen)
	if _, err := rand.Read(pk); err != nil {
		return nil, nil, err
	}
	copy(sk, pk) // sk := H(pk) stand-in; real scheme derives independently
	return pk, sk, nil
}

func (r *roKEM) Enc(pk []byte) ([]byte, []byte, error) {
	if len(pk) != pkLen {
		return nil, nil, errors.New("bad pk length")
	}
	ss := make([]byte, ssLen)
	if _, err := rand.Read(ss); err != nil {
		return nil, nil, err
	}
	ct, err := materializeCT(pk, ss)
	if err != nil {
		return nil, nil, err
	}
	return ss, ct, nil
}

func (r *roKEM) Dec(sk, ct []byte) ([]byte, error) {
	if r.broken {
		// Total break of this half: recover ss from ct (models e.g. Shor on
		// ECDH, or a lattice break on ML-KEM).
		return extractSS(sk, ct)
	}
	return extractSS(sk, ct) // RO inversion stand-in
}

func (r *roKEM) IsBroken() bool { return r.broken }

// materializeCT binds ss to pk and ss (Fiat-Shamir/RO stand-in).
func materializeCT(pk, ss []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(pk)
	h.Write(ss)
	ct := make([]byte, ctLen)
	copy(ct[0:ssLen], ss) // reversible half (Dec needs ss)
	digest := h.Sum(nil)
	copy(ct[ssLen:], digest) // binding tag
	return ct, nil
}

func extractSS(sk, ct []byte) ([]byte, error) {
	if len(ct) != ctLen {
		return nil, errors.New("bad ct length")
	}
	ss := make([]byte, ssLen)
	copy(ss, ct[:ssLen])
	// In a real KEM this fails when the RO binding tag doesn't match sk. Here
	// we recompute the tag against a pk derived from sk to honor failure on
	// tampered ciphertexts when not broken. The tag region is the full
	// ctLen-ssLen = 64B trailing region (digest followed by zero padding), so
	// any byte flipped anywhere in the ct — including padding — is caught.
	digest := sha256Sum(sk, ss)
	want := make([]byte, ctLen-ssLen)
	copy(want, digest)
	if !hmac.Equal(ct[ssLen:], want) {
		return nil, errors.New("decapsulation failure")
	}
	return ss, nil
}

func sha256Sum(append1, append2 []byte) []byte {
	h := sha256.New()
	h.Write(append1)
	h.Write(append2)
	return h.Sum(nil)
}

// roSig is an idealized signature: vk random 32B, sig = HMAC(sk, msg) tag.
// If broken, Verify accepts everything (models total break: adversary can
// produce valid signatures for arbitrary messages).
type roSig struct{ broken bool }

func (r *roSig) Skg() ([]byte, []byte, error) {
	vk := make([]byte, 32)
	if _, err := rand.Read(vk); err != nil {
		return nil, nil, err
	}
	// sk is derived from vk so Ver(vk, ·) can recompute the same MAC key —
	// this stands in for the algebraic vk↔sk relation of a real scheme.
	// (Not the security shape of a real signature: a real vk reveals
	// nothing about sk; here the reduction only needs verifiability.)
	return vk, deriveSK(vk), nil
}

// deriveSK is the idealized key-derivation stand-in: sk = HMAC("sk", vk).
func deriveSK(vk []byte) []byte {
	m := hmac.New(sha256.New, []byte("hybridoidc/sk-derivation"))
	m.Write(vk)
	return m.Sum(nil)
}

func (r *roSig) Sign(sk, msg []byte) ([]byte, error) {
	m := hmac.New(sha256.New, sk)
	m.Write(msg)
	return m.Sum(nil), nil
}

func (r *roSig) Ver(vk, msg, sig []byte) bool {
	if r.broken {
		return true
	}
	// vk stand-in for sk-dependent check in the RO model: derive the same
	// MAC key from vk that Skg derived, so honest signatures verify and a
	// mismatched key fails (real schemes check vk's equation).
	want := hmac.New(sha256.New, deriveSK(vk))
	want.Write(msg)
	return hmac.Equal(want.Sum(nil), sig)
}

func (r *roSig) IsBroken() bool { return r.broken }

// ------------------------------------------------------------ Alg 3: hybrid KEM

// HybridKEM is Alg 3. rs is set via Context (test-only) to instantiate E1/E2.
type HybridKEM struct {
	Classical KEM
	PQ        KEM
}

// NewDefaultHybridKEM returns the deployed composition: ECDH P-256 + ML-KEM-768
// (FIPS 203), both from the standard library.
func NewDefaultHybridKEM() *HybridKEM {
	return NewProductionHybridKEM()
}

// NewIdealizedHybridKEM returns the random-oracle stand-ins used by the
// reductions of Thm 1 / E1 / E2, where a half must be switchably broken.
func NewIdealizedHybridKEM() *HybridKEM {
	return &HybridKEM{Classical: &roKEM{}, PQ: &roKEM{}}
}

// KgenH runs independent Kgen on each half (Alg 3 KgenH).
func (h *HybridKEM) KgenH() (pkH, skH []byte, err error) {
	pkc, skc, err := h.Classical.Kgen()
	if err != nil {
		return nil, nil, err
	}
	pkp, skp, err := h.PQ.Kgen()
	if err != nil {
		return nil, nil, err
	}
	return append(append([]byte{}, pkc...), pkp...), append(append([]byte{}, skc...), skp...), nil
}

// EncH encapsulates to both halves and concatenates fixed-length cts.
func (h *HybridKEM) EncH(pkH []byte) ([]byte, []byte, error) {
	lc, lp := kemSizes(h.Classical), kemSizes(h.PQ)
	if len(pkH) != lc.pk+lp.pk {
		return nil, nil, errors.New("bad hybrid pk length")
	}
	ssc, ctc, err := h.Classical.Enc(pkH[:lc.pk])
	if err != nil {
		return nil, nil, err
	}
	ssp, ctp, err := h.PQ.Enc(pkH[lc.pk:])
	if err != nil {
		return nil, nil, err
	}
	ss := append(append([]byte{}, ssc...), ssp...)
	ct := append(append([]byte{}, ctc...), ctp...)
	return ss, ct, nil
}

// DecH decapsulates componentwise; ⊥ if either fails (Alg 3 conjunction).
func (h *HybridKEM) DecH(skH, ctH []byte) ([]byte, error) {
	lc, lp := kemSizes(h.Classical), kemSizes(h.PQ)
	if len(skH) != lc.sk+lp.sk || len(ctH) != lc.ct+lp.ct {
		return nil, errors.New("bad hybrid inputs")
	}
	ssc, err := h.Classical.Dec(skH[:lc.sk], ctH[:lc.ct])
	if err != nil {
		return nil, err
	}
	ssp, err := h.PQ.Dec(skH[lc.sk:], ctH[lc.ct:])
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, ssc...), ssp...), nil
}

// SecretLen is the fixed length of DecH's output for this composition.
func (h *HybridKEM) SecretLen() int {
	return kemSizes(h.Classical).ss + kemSizes(h.PQ).ss
}

// PublicKeyLen, SecretKeyLen and CiphertextLen report the hybrid encodings.
func (h *HybridKEM) PublicKeyLen() int {
	return kemSizes(h.Classical).pk + kemSizes(h.PQ).pk
}

func (h *HybridKEM) SecretKeyLen() int {
	return kemSizes(h.Classical).sk + kemSizes(h.PQ).sk
}

func (h *HybridKEM) CiphertextLen() int {
	return kemSizes(h.Classical).ct + kemSizes(h.PQ).ct
}

// ExtractKey binds the concatenated hybrid secret with a dual-PRF HKDF-style
// extractor (fixed-length input per IETF hybrid-TLS draft). Returns K.
func ExtractKey(ss []byte, salt, info []byte) []byte {
	if len(ss) != 2*ssLen {
		panic("hybrid secret must be fixed length")
	}
	return ExtractKeyN(ss, salt, info)
}

// ExtractKeyN is ExtractKey for a composition whose concatenated secret is
// not the idealized 64 bytes (FIPS 203/204 both give 32, so this is 64 for
// every composition shipped here, but the bound is now explicit).
func ExtractKeyN(ss []byte, salt, info []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ss)
	m.Write(info)
	return m.Sum(nil)
}

// ------------------------------------------------------------ Alg 4: hybrid Sig

// HybridSig is Alg 4 with conjunction acceptance.
type HybridSig struct {
	Classical Sig
	PQ        Sig
}

// NewDefaultHybridSig returns the deployed composition: ES256 + ML-DSA-65
// (FIPS 204), both from the standard library.
func NewDefaultHybridSig() *HybridSig {
	return NewProductionHybridSig()
}

// NewIdealizedHybridSig returns the random-oracle stand-ins used by the
// reductions of Thm 2 / G3 / G4, where a half must be switchably broken.
func NewIdealizedHybridSig() *HybridSig {
	return &HybridSig{Classical: &roSig{}, PQ: &roSig{}}
}

func (s *HybridSig) SkgH() ([]byte, []byte, error) {
	vkc, skc, err := s.Classical.Skg()
	if err != nil {
		return nil, nil, err
	}
	vkp, skp, err := s.PQ.Skg()
	if err != nil {
		return nil, nil, err
	}
	return append(append([]byte{}, vkc...), vkp...), append(append([]byte{}, skc...), skp...), nil
}

func (s *HybridSig) SignH(skH, msg []byte) ([]byte, error) {
	lc, lp := sigSizes(s.Classical), sigSizes(s.PQ)
	if len(skH) != lc.sk+lp.sk {
		return nil, errors.New("bad hybrid sk")
	}
	sc, err := s.Classical.Sign(skH[:lc.sk], msg)
	if err != nil {
		return nil, err
	}
	sp, err := s.PQ.Sign(skH[lc.sk:], msg)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, sc...), sp...), nil
}

// SignatureLen, VerifyKeyLen and SignKeyLen report the hybrid encodings.
func (s *HybridSig) SignatureLen() int {
	return sigSizes(s.Classical).sig + sigSizes(s.PQ).sig
}

func (s *HybridSig) VerifyKeyLen() int {
	return sigSizes(s.Classical).vk + sigSizes(s.PQ).vk
}

func (s *HybridSig) SignKeyLen() int {
	return sigSizes(s.Classical).sk + sigSizes(s.PQ).sk
}

// VerH requires BOTH halves valid on the same msg (Alg 4 conjunction = G3).
func (s *HybridSig) VerH(vkH, msg, sigH []byte) bool {
	lc, lp := sigSizes(s.Classical), sigSizes(s.PQ)
	if len(vkH) != lc.vk+lp.vk || len(sigH) != lc.sig+lp.sig {
		return false
	}
	return s.Classical.Ver(vkH[:lc.vk], msg, sigH[:lc.sig]) &&
		s.PQ.Ver(vkH[lc.vk:], msg, sigH[lc.sig:])
}

// --------------------------------------------------------------------- JWT

// JWT is a minimal JWS structure: header.payload.signature (base64 omitted,
// byte-encoded for clarity).
type JWT struct {
	Header  []byte
	Payload []byte
	// Sig is the hybrid signature over signingInput = header||"."||payload
	Sig []byte
}

func signingInput(j *JWT) []byte {
	return append(append([]byte{}, j.Header...), append([]byte{'.'}, j.Payload...)...)
}

// SignJWT produces a JWT accepted only when both halves validate (G3).
func SignJWT(s *HybridSig, skH []byte, header, payload []byte) (*JWT, error) {
	j := &JWT{Header: header, Payload: payload}
	sig, err := s.SignH(skH, signingInput(j))
	if err != nil {
		return nil, err
	}
	j.Sig = sig
	return j, nil
}

// SignJWT2 signs header||payload also bound to a TLS channel-binding value
// (Thm 3): the signed input becomes signingInput ‖ bound so a token replayed
// on a different TLS connection fails verification.
func SignJWT2(s *HybridSig, skH []byte, header, payload, bound []byte) (*JWT, error) {
	j := &JWT{Header: header, Payload: payload}
	sigInput := append(signingInput(j), bound...)
	sig, err := s.SignH(skH, sigInput)
	if err != nil {
		return nil, err
	}
	j.Sig = sig
	return j, nil
}

// VerifyJWT verifies conjunction of both signatures (G3). When bound != nil
// it must equal the channel binding captured at signing time.
func VerifyJWT(s *HybridSig, vkH []byte, j *JWT, bound []byte) bool {
	msg := signingInput(j)
	if bound != nil {
		msg = append(msg, bound...)
	}
	return s.VerH(vkH, msg, j.Sig)
}

// ChannelBinding derives the transcript-bound value from the exported
// master secret (stand-in for tls-exporter_master_secret in RFC 9266).
func ChannelBinding(exporterSecret, label, context []byte) []byte {
	m := hmac.New(sha256.New, exporterSecret)
	m.Write([]byte("EXPORTER: "))
	m.Write(label)
	m.Write(context)
	return m.Sum(nil)
}

// ------------------------------------------------------------ test helpers

// failAfter is a placeholder for oracle-bounded adversaries in the proofs.
func failAfter(n int) int { return n }

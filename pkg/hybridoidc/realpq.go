// Real (FIPS-validated) components for the composite-hybrid KEM and signature.
//
// The reference components in hybridoidc.go are idealized random-oracle
// stand-ins: they exist so the reductions of Thm 1 and Thm 2 run to
// completion with an explicit "break this half" switch. They are not
// cryptography you should deploy.
//
// This file supplies the deployment components:
//
//	classical KEM   ECDH on NIST P-256          (crypto/ecdh)
//	PQ KEM          ML-KEM-768                  (crypto/mlkem,  FIPS 203)
//	classical Sig   ECDSA on NIST P-256 / ES256 (crypto/ecdsa)
//	PQ Sig          ML-DSA-65                   (crypto/mldsa,  FIPS 204)
//
// Both are pure standard library: HMK-1 still pulls in no third-party
// cryptographic code. Swapping these in changes no algorithm, no proof and no
// wire invariant — the hybrids stay "conjunction of two independent halves",
// and every secret is still 32 bytes per half so the HMK-1 wrap (which takes
// HMKSSLen = 64 bytes) is unchanged.
package hybridoidc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"math/big"
)

// ---------------------------------------------------------------- ECDH KEM

const (
	ecdhPKLen = 65 // uncompressed P-256 point
	ecdhSKLen = 32
	ecdhCTLen = 65
	ecdhSSLen = 32
)

// ecdhKEM is ECDH over P-256: Enc is an ephemeral-static Diffie-Hellman, so
// the ciphertext is the ephemeral public point and the shared secret is the
// x-coordinate (as in ECIES without the KDF, since the hybrid extractor does
// that job for the whole concatenation).
type ecdhKEM struct{}

func (ecdhKEM) kemLayout() kemLayout {
	return kemLayout{pk: ecdhPKLen, sk: ecdhSKLen, ct: ecdhCTLen, ss: ecdhSSLen}
}

func (ecdhKEM) Kgen() (pk, sk []byte, err error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

func (ecdhKEM) Enc(pk []byte) (ss, ct []byte, err error) {
	if len(pk) != ecdhPKLen {
		return nil, nil, errors.New("ecdh: bad public key length")
	}
	peer, err := ecdh.P256().NewPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := eph.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	return secret, eph.PublicKey().Bytes(), nil
}

func (ecdhKEM) Dec(sk, ct []byte) ([]byte, error) {
	if len(sk) != ecdhSKLen || len(ct) != ecdhCTLen {
		return nil, errors.New("ecdh: bad key or ciphertext length")
	}
	priv, err := ecdh.P256().NewPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(ct)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peer)
}

func (ecdhKEM) IsBroken() bool { return false }

// -------------------------------------------------------------- ML-KEM KEM

const (
	mlkemPKLen = mlkem.EncapsulationKeySize768 // 1184
	mlkemSKLen = mlkem.SeedSize                // 64-byte decapsulation key seed
	mlkemCTLen = mlkem.CiphertextSize768       // 1088
	mlkemSSLen = mlkem.SharedKeySize           // 32
)

// mlkemKEM is ML-KEM-768 exactly as specified in FIPS 203. Decapsulation has
// implicit rejection: a tampered ciphertext yields a pseudorandom secret
// rather than an error, which is why the hybrid layer, not this one, is what
// reports failure to the caller.
type mlkemKEM struct{}

func (mlkemKEM) kemLayout() kemLayout {
	return kemLayout{pk: mlkemPKLen, sk: mlkemSKLen, ct: mlkemCTLen, ss: mlkemSSLen}
}

func (mlkemKEM) Kgen() (pk, sk []byte, err error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func (mlkemKEM) Enc(pk []byte) (ss, ct []byte, err error) {
	if len(pk) != mlkemPKLen {
		return nil, nil, errors.New("mlkem: bad encapsulation key length")
	}
	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, nil, err
	}
	ss, ct = ek.Encapsulate()
	return ss, ct, nil
}

func (mlkemKEM) Dec(sk, ct []byte) ([]byte, error) {
	if len(sk) != mlkemSKLen || len(ct) != mlkemCTLen {
		return nil, errors.New("mlkem: bad key or ciphertext length")
	}
	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ct)
}

func (mlkemKEM) IsBroken() bool { return false }

// --------------------------------------------------------------- ECDSA Sig

const (
	ecdsaVKLen  = 65 // uncompressed P-256 point
	ecdsaSKLen  = 32 // scalar
	ecdsaSigLen = 64 // r ‖ s, fixed width (not ASN.1: fixed lengths everywhere)
)

// ecdsaSig is ES256. Signatures are encoded as fixed-width r‖s rather than
// DER, because a length that varies with the value is exactly the kind of
// parser side channel HMK-1 removes elsewhere.
type ecdsaSig struct{}

func (ecdsaSig) sigLayout() sigLayout {
	return sigLayout{vk: ecdsaVKLen, sk: ecdsaSKLen, sig: ecdsaSigLen}
}

func (ecdsaSig) Skg() (vk, sk []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sk = make([]byte, ecdsaSKLen)
	priv.D.FillBytes(sk)
	vk, err = priv.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return vk, sk, nil
}

func (ecdsaSig) Sign(sk, msg []byte) ([]byte, error) {
	key, err := ecdsaFromScalar(sk)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, msg)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, ecdsaSigLen)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func (ecdsaSig) Ver(vk, msg, sig []byte) bool {
	if len(vk) != ecdsaVKLen || len(sig) != ecdsaSigLen {
		return false
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), vk)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, msg, r, s)
}

func (ecdsaSig) IsBroken() bool { return false }

// ecdsaFromScalar rebuilds a P-256 private key from its 32-byte scalar.
func ecdsaFromScalar(sk []byte) (*ecdsa.PrivateKey, error) {
	if len(sk) != ecdsaSKLen {
		return nil, errors.New("ecdsa: bad private key length")
	}
	d := new(big.Int).SetBytes(sk)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("ecdsa: scalar out of range")
	}
	x, y := curve.ScalarBaseMult(sk)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

// --------------------------------------------------------------- ML-DSA Sig

const (
	mldsaVKLen  = mldsa.MLDSA65PublicKeySize  // 1952
	mldsaSKLen  = mldsa.PrivateKeySize        // 32-byte seed
	mldsaSigLen = mldsa.MLDSA65SignatureSize  // 3309
)

// mldsaSig is ML-DSA-65 (FIPS 204). The private key is stored as the 32-byte
// FIPS 204 seed and expanded on use, so a hybrid signing key stays small.
type mldsaSig struct{}

func (mldsaSig) sigLayout() sigLayout {
	return sigLayout{vk: mldsaVKLen, sk: mldsaSKLen, sig: mldsaSigLen}
}

func (mldsaSig) Skg() (vk, sk []byte, err error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

func (mldsaSig) Sign(sk, msg []byte) ([]byte, error) {
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), sk)
	if err != nil {
		return nil, err
	}
	return priv.Sign(nil, msg, (*mldsa.Options)(nil))
}

func (mldsaSig) Ver(vk, msg, sig []byte) bool {
	if len(vk) != mldsaVKLen || len(sig) != mldsaSigLen {
		return false
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), vk)
	if err != nil {
		return false
	}
	return mldsa.Verify(pub, msg, sig, nil) == nil
}

func (mldsaSig) IsBroken() bool { return false }

// ------------------------------------------------------ deployed constructors

// NewProductionHybridKEM is Alg 3 with ECDH P-256 + ML-KEM-768. Every secret
// is 32 bytes, so the concatenation is still the 64-byte HMK-1 wrap input.
func NewProductionHybridKEM() *HybridKEM {
	return &HybridKEM{Classical: ecdhKEM{}, PQ: mlkemKEM{}}
}

// NewProductionHybridSig is Alg 4 with ES256 + ML-DSA-65.
func NewProductionHybridSig() *HybridSig {
	return &HybridSig{Classical: ecdsaSig{}, PQ: mldsaSig{}}
}

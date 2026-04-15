package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// GenerateSigningKeyPair generates an ML-DSA-65 signing keypair.
// Returns the packed public key and private key bytes.
func GenerateSigningKeyPair() (publicKey []byte, privateKey []byte, err error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65 keypair: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	return pubBytes, privBytes, nil
}

// Sign signs a message using an ML-DSA-65 private key.
// Returns the signature bytes.
func Sign(message []byte, privateKey []byte) ([]byte, error) {
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	sig := make([]byte, mldsa65.SignatureSize)
	err := mldsa65.SignTo(&sk, message, nil, false, sig)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return sig, nil
}

// Verify verifies a signature against a message using an ML-DSA-65 public key.
func Verify(message []byte, signature []byte, publicKey []byte) (bool, error) {
	if len(signature) != mldsa65.SignatureSize {
		return false, errors.New("invalid signature size")
	}

	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false, fmt.Errorf("unmarshal public key: %w", err)
	}

	return mldsa65.Verify(&pk, message, nil, signature), nil
}

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/sha3"
)

// GenerateKeyPair generates an X-Wing hybrid KEM keypair (X25519 + ML-KEM-768).
// Returns the packed public key and private key bytes.
func GenerateKeyPair() (publicKey []byte, privateKey []byte, err error) {
	// Note: GenerateKeyPairPacked returns (sk, pk, err) — private key first
	sk, pk, err := xwing.GenerateKeyPairPacked(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate X-Wing keypair: %w", err)
	}
	return pk, sk, nil
}

// Encapsulate generates a shared secret and ciphertext for the given public key
// using the X-Wing hybrid KEM.
func Encapsulate(publicKey []byte) (sharedSecret [32]byte, ciphertext []byte, err error) {
	if len(publicKey) != xwing.PublicKeySize {
		return sharedSecret, nil, errors.New("invalid public key size")
	}

	ss, ct, err := xwing.Encapsulate(publicKey, nil)
	if err != nil {
		return sharedSecret, nil, fmt.Errorf("encapsulate: %w", err)
	}

	copy(sharedSecret[:], ss)
	ZeroBytes(ss)
	return sharedSecret, ct, nil
}

// Decapsulate recovers the shared secret from a ciphertext using the private key.
func Decapsulate(privateKey []byte, ciphertext []byte) (sharedSecret [32]byte, err error) {
	if len(privateKey) != xwing.PrivateKeySize {
		return sharedSecret, errors.New("invalid private key size")
	}
	if len(ciphertext) != xwing.CiphertextSize {
		return sharedSecret, errors.New("invalid ciphertext size")
	}

	ss := xwing.Decapsulate(ciphertext, privateKey)
	copy(sharedSecret[:], ss)
	ZeroBytes(ss)
	return sharedSecret, nil
}

// DeriveSessionKey derives a 256-bit session key from a shared secret and context
// string using SHAKE256 for domain separation.
func DeriveSessionKey(sharedSecret [32]byte, context string) [32]byte {
	h := sha3.NewShake256()
	h.Write(sharedSecret[:])
	h.Write([]byte(context))

	var key [32]byte
	h.Read(key[:])
	return key
}

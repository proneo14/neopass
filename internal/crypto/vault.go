package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// NonceSize is the standard GCM nonce size (12 bytes).
	NonceSize = 12
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns (ciphertext, nonce, error). The ciphertext includes the GCM auth tag.
func Encrypt(plaintext []byte, key [32]byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given nonce.
func Decrypt(ciphertext []byte, nonce []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// ZeroBytes securely zeros a byte slice.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

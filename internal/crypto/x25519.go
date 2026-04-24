package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

// X25519Encrypt performs X25519 ECDH key agreement with the recipient's public key,
// derives an AES-256-GCM key, and encrypts the plaintext.
// The recipient's public key is expected in DER SPKI format (44 bytes for X25519).
// Returns: ephemeral public key (raw 32 bytes) || nonce || ciphertext+tag
func X25519Encrypt(plaintext []byte, recipientPubKeyDER []byte) ([]byte, error) {
	// Parse recipient's X25519 public key from DER SPKI
	pubKeyAny, err := x509.ParsePKIXPublicKey(recipientPubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}

	recipientKey, ok := pubKeyAny.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not X25519/ECDH")
	}

	// Generate ephemeral X25519 keypair
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH key agreement
	sharedSecret, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// Derive encryption key from shared secret
	encKey := DeriveSessionKey([32]byte(sharedSecret), "x25519-encrypt")
	ZeroBytes(sharedSecret)

	// Encrypt with AES-256-GCM
	ct, nonce, err := Encrypt(plaintext, encKey)
	ZeroBytes(encKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Blob = ephemeral pub (32) || nonce || ciphertext
	ephPub := ephemeral.PublicKey().Bytes()
	blob := make([]byte, len(ephPub)+len(nonce)+len(ct))
	copy(blob, ephPub)
	copy(blob[len(ephPub):], nonce)
	copy(blob[len(ephPub)+len(nonce):], ct)

	return blob, nil
}

// X25519Decrypt decrypts a blob produced by X25519Encrypt.
// The private key is expected in PKCS8 DER format (as exported by Node.js).
// Blob format: ephemeral pub (32 bytes) || nonce (12 bytes) || ciphertext+tag
func X25519Decrypt(blob []byte, privateKeyDER []byte) ([]byte, error) {
	const ephPubSize = 32

	if len(blob) < ephPubSize+NonceSize+1 {
		return nil, fmt.Errorf("blob too short")
	}

	// Parse recipient's private key from PKCS8 DER
	privKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privKey, ok := privKeyAny.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not X25519/ECDH")
	}

	// Extract ephemeral public key
	ephPubBytes := blob[:ephPubSize]
	nonce := blob[ephPubSize : ephPubSize+NonceSize]
	ct := blob[ephPubSize+NonceSize:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	// ECDH key agreement
	sharedSecret, err := privKey.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// Derive same encryption key
	encKey := DeriveSessionKey([32]byte(sharedSecret), "x25519-encrypt")
	ZeroBytes(sharedSecret)

	// Decrypt
	plaintext, err := Decrypt(ct, nonce, encKey)
	ZeroBytes(encKey[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

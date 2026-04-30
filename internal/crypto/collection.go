package crypto

import (
	"crypto/rand"
	"fmt"
)

// GenerateCollectionKey generates a random 32-byte AES-256-GCM key for a collection.
func GenerateCollectionKey() ([32]byte, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate collection key: %w", err)
	}
	return key, nil
}

// EncryptCollectionKey encrypts a collection key with a user's X-Wing public key.
// Uses KEM encapsulation to derive a shared secret, then AES-GCM encrypts the collection key.
// Returns the blob: KEM ciphertext || nonce || encrypted collection key.
func EncryptCollectionKey(collectionKey [32]byte, userPublicKey []byte) ([]byte, error) {
	sharedSecret, kemCiphertext, err := Encapsulate(userPublicKey)
	if err != nil {
		return nil, fmt.Errorf("encapsulate for collection key: %w", err)
	}

	encKey := DeriveSessionKey(sharedSecret, "collection-key-encryption")
	ZeroBytes(sharedSecret[:])

	encCollKey, nonce, err := Encrypt(collectionKey[:], encKey)
	if err != nil {
		ZeroBytes(encKey[:])
		return nil, fmt.Errorf("encrypt collection key: %w", err)
	}
	ZeroBytes(encKey[:])

	// blob = KEM ciphertext || nonce || encrypted collection key
	blob := make([]byte, len(kemCiphertext)+len(nonce)+len(encCollKey))
	copy(blob, kemCiphertext)
	copy(blob[len(kemCiphertext):], nonce)
	copy(blob[len(kemCiphertext)+len(nonce):], encCollKey)

	return blob, nil
}

// DecryptCollectionKey decrypts a collection key using the user's X-Wing private key.
// Expects blob format: KEM ciphertext || nonce || encrypted collection key.
func DecryptCollectionKey(encryptedKey []byte, userPrivateKey []byte) ([32]byte, error) {
	var collectionKey [32]byte

	kemCtSize := 1120 // xwing.CiphertextSize
	if len(encryptedKey) < kemCtSize+NonceSize {
		return collectionKey, fmt.Errorf("encrypted collection key too short")
	}

	kemCiphertext := encryptedKey[:kemCtSize]
	nonce := encryptedKey[kemCtSize : kemCtSize+NonceSize]
	encCollKey := encryptedKey[kemCtSize+NonceSize:]

	sharedSecret, err := Decapsulate(userPrivateKey, kemCiphertext)
	if err != nil {
		return collectionKey, fmt.Errorf("decapsulate collection key: %w", err)
	}

	encKey := DeriveSessionKey(sharedSecret, "collection-key-encryption")
	ZeroBytes(sharedSecret[:])

	plainKey, err := Decrypt(encCollKey, nonce, encKey)
	if err != nil {
		ZeroBytes(encKey[:])
		return collectionKey, fmt.Errorf("decrypt collection key: %w", err)
	}
	ZeroBytes(encKey[:])

	if len(plainKey) != 32 {
		ZeroBytes(plainKey)
		return collectionKey, fmt.Errorf("invalid collection key size: %d", len(plainKey))
	}

	copy(collectionKey[:], plainKey)
	ZeroBytes(plainKey)
	return collectionKey, nil
}

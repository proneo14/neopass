package crypto

import (
	"fmt"
)

// GenerateOrgKeyPair generates an X-Wing keypair for an organization.
// The private key is encrypted with the admin's master key.
// Returns (orgPublicKey, encryptedOrgPrivateKey, error).
func GenerateOrgKeyPair(adminMasterKey [32]byte) (orgPublicKey []byte, encryptedOrgPrivateKey []byte, err error) {
	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate org keypair: %w", err)
	}

	encPrivKey, nonce, err := Encrypt(privKey, adminMasterKey)
	if err != nil {
		ZeroBytes(privKey)
		return nil, nil, fmt.Errorf("encrypt org private key: %w", err)
	}
	ZeroBytes(privKey)

	// Prepend nonce to encrypted private key for self-contained storage
	blob := make([]byte, len(nonce)+len(encPrivKey))
	copy(blob[:len(nonce)], nonce)
	copy(blob[len(nonce):], encPrivKey)

	return pubKey, blob, nil
}

// DecryptOrgPrivateKey decrypts the organization's private key using the admin's master key.
func DecryptOrgPrivateKey(encryptedOrgPrivateKey []byte, adminMasterKey [32]byte) ([]byte, error) {
	if len(encryptedOrgPrivateKey) < NonceSize {
		return nil, fmt.Errorf("encrypted org private key too short")
	}

	nonce := encryptedOrgPrivateKey[:NonceSize]
	ciphertext := encryptedOrgPrivateKey[NonceSize:]

	privKey, err := Decrypt(ciphertext, nonce, adminMasterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt org private key: %w", err)
	}

	return privKey, nil
}

// EncryptEscrow encrypts a user's master key with the organization's X-Wing public key.
// The escrow blob allows admins to recover the user's master key.
func EncryptEscrow(userMasterKey [32]byte, orgPublicKey []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := Encapsulate(orgPublicKey)
	if err != nil {
		return nil, fmt.Errorf("encapsulate for escrow: %w", err)
	}

	// Derive an encryption key from the KEM shared secret
	encKey := DeriveSessionKey(sharedSecret, "escrow-encryption")
	ZeroBytes(sharedSecret[:])

	// Encrypt the user's master key with the derived key
	encMasterKey, nonce, err := Encrypt(userMasterKey[:], encKey)
	if err != nil {
		ZeroBytes(encKey[:])
		return nil, fmt.Errorf("encrypt escrow: %w", err)
	}
	ZeroBytes(encKey[:])

	// Escrow blob = KEM ciphertext || nonce || encrypted master key
	blob := make([]byte, len(ciphertext)+len(nonce)+len(encMasterKey))
	copy(blob, ciphertext)
	copy(blob[len(ciphertext):], nonce)
	copy(blob[len(ciphertext)+len(nonce):], encMasterKey)

	return blob, nil
}

// DecryptEscrow recovers a user's master key from an escrow blob using the org's private key.
func DecryptEscrow(escrowBlob []byte, orgPrivateKey []byte) ([32]byte, error) {
	var userMasterKey [32]byte

	kemCtSize := 1120 // xwing.CiphertextSize
	if len(escrowBlob) < kemCtSize+NonceSize {
		return userMasterKey, fmt.Errorf("escrow blob too short")
	}

	kemCiphertext := escrowBlob[:kemCtSize]
	nonce := escrowBlob[kemCtSize : kemCtSize+NonceSize]
	encMasterKey := escrowBlob[kemCtSize+NonceSize:]

	// Recover shared secret via KEM decapsulation
	sharedSecret, err := Decapsulate(orgPrivateKey, kemCiphertext)
	if err != nil {
		return userMasterKey, fmt.Errorf("decapsulate escrow: %w", err)
	}

	// Derive the same encryption key
	encKey := DeriveSessionKey(sharedSecret, "escrow-encryption")
	ZeroBytes(sharedSecret[:])

	// Decrypt the user's master key
	plainMasterKey, err := Decrypt(encMasterKey, nonce, encKey)
	if err != nil {
		ZeroBytes(encKey[:])
		return userMasterKey, fmt.Errorf("decrypt escrow master key: %w", err)
	}
	ZeroBytes(encKey[:])

	if len(plainMasterKey) != 32 {
		ZeroBytes(plainMasterKey)
		return userMasterKey, fmt.Errorf("decrypted master key has unexpected length %d", len(plainMasterKey))
	}

	copy(userMasterKey[:], plainMasterKey)
	ZeroBytes(plainMasterKey)

	return userMasterKey, nil
}

// ReEncryptOrgPrivateKey re-encrypts the org private key with a new admin master key.
// Used when admin changes their password.
func ReEncryptOrgPrivateKey(encryptedOrgPrivateKey []byte, oldAdminMasterKey, newAdminMasterKey [32]byte) ([]byte, error) {
	// Decrypt with old key
	privKey, err := DecryptOrgPrivateKey(encryptedOrgPrivateKey, oldAdminMasterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt with old key: %w", err)
	}

	// Re-encrypt with new key
	encPrivKey, nonce, err := Encrypt(privKey, newAdminMasterKey)
	ZeroBytes(privKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt with new key: %w", err)
	}

	blob := make([]byte, len(nonce)+len(encPrivKey))
	copy(blob[:len(nonce)], nonce)
	copy(blob[len(nonce):], encPrivKey)

	return blob, nil
}

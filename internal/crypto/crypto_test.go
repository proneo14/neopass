package crypto

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// KDF Tests
// ---------------------------------------------------------------------------

func TestDeriveKeys_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef") // 16 bytes

	mk1, ah1, s1, err := DeriveKeys("testpassword", salt)
	if err != nil {
		t.Fatalf("DeriveKeys #1 failed: %v", err)
	}

	mk2, ah2, s2, err := DeriveKeys("testpassword", salt)
	if err != nil {
		t.Fatalf("DeriveKeys #2 failed: %v", err)
	}

	if mk1 != mk2 {
		t.Error("master keys differ for same password+salt")
	}
	if ah1 != ah2 {
		t.Error("auth hashes differ for same password+salt")
	}
	if !bytes.Equal(s1, s2) {
		t.Error("salts differ")
	}
}

func TestDeriveKeys_MasterKeyDiffersFromAuthHash(t *testing.T) {
	salt := []byte("0123456789abcdef")

	mk, ah, _, err := DeriveKeys("testpassword", salt)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if mk == ah {
		t.Error("master key and auth hash should be different")
	}
}

func TestDeriveKeys_DifferentPasswords(t *testing.T) {
	salt := []byte("0123456789abcdef")

	mk1, _, _, err := DeriveKeys("password1", salt)
	if err != nil {
		t.Fatalf("DeriveKeys #1 failed: %v", err)
	}

	mk2, _, _, err := DeriveKeys("password2", salt)
	if err != nil {
		t.Fatalf("DeriveKeys #2 failed: %v", err)
	}

	if mk1 == mk2 {
		t.Error("different passwords should produce different master keys")
	}
}

func TestDeriveKeys_DifferentSalts(t *testing.T) {
	mk1, _, _, err := DeriveKeys("testpassword", []byte("salt_aaaabbbbcccc"))
	if err != nil {
		t.Fatalf("DeriveKeys #1 failed: %v", err)
	}

	mk2, _, _, err := DeriveKeys("testpassword", []byte("salt_ddddeeeeffff"))
	if err != nil {
		t.Fatalf("DeriveKeys #2 failed: %v", err)
	}

	if mk1 == mk2 {
		t.Error("different salts should produce different master keys")
	}
}

func TestDeriveKeys_NilSaltGeneratesRandom(t *testing.T) {
	_, _, salt, err := DeriveKeys("testpassword", nil)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}
	if len(salt) != SaltSize {
		t.Errorf("expected salt of %d bytes, got %d", SaltSize, len(salt))
	}
}

func TestGenerateSalt(t *testing.T) {
	s1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	s2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(s1) != SaltSize || len(s2) != SaltSize {
		t.Errorf("expected %d byte salts", SaltSize)
	}
	if bytes.Equal(s1, s2) {
		t.Error("two random salts should not be equal")
	}
}

// ---------------------------------------------------------------------------
// AES-256-GCM (Vault Encryption) Tests
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	plaintext := []byte("this is a secret vault entry with sensitive data")

	ct, nonce, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != NonceSize {
		t.Errorf("expected nonce of %d bytes, got %d", NonceSize, len(nonce))
	}

	decrypted, err := Decrypt(ct, nonce, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text does not match original")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	key2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	ct, nonce, err := Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ct, nonce, key2)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	ct, nonce, err := Encrypt([]byte("secret"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with ciphertext
	ct[0] ^= 0xFF

	_, err = Decrypt(ct, nonce, key)
	if err == nil {
		t.Error("Decrypt with tampered ciphertext should fail")
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := [32]byte{1}
	plaintext := []byte("test")

	_, nonce1, _ := Encrypt(plaintext, key)
	_, nonce2, _ := Encrypt(plaintext, key)

	if bytes.Equal(nonce1, nonce2) {
		t.Error("two encryptions should produce different nonces")
	}
}

// ---------------------------------------------------------------------------
// ZeroBytes Test
// ---------------------------------------------------------------------------

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroBytes(b)

	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d not zeroed: %d", i, v)
		}
	}
}

// ---------------------------------------------------------------------------
// X-Wing Hybrid KEM Tests
// ---------------------------------------------------------------------------

func TestXWing_KeyExchange(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ss1, ct, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	ss2, err := Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("shared secrets do not match")
	}
}

func TestXWing_DifferentKeyPairs(t *testing.T) {
	pub1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair #1 failed: %v", err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair #2 failed: %v", err)
	}

	if bytes.Equal(pub1, pub2) {
		t.Error("two keypairs should have different public keys")
	}
}

func TestXWing_WrongPrivateKey(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair #1 failed: %v", err)
	}
	_, priv2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair #2 failed: %v", err)
	}

	ss1, ct, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	ss2, err := Decapsulate(priv2, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// With wrong private key, shared secrets should not match
	if ss1 == ss2 {
		t.Error("shared secrets should differ with wrong private key")
	}
}

func TestDeriveSessionKey_DomainSeparation(t *testing.T) {
	ss := [32]byte{42}

	k1 := DeriveSessionKey(ss, "context-a")
	k2 := DeriveSessionKey(ss, "context-b")

	if k1 == k2 {
		t.Error("different contexts should produce different session keys")
	}
}

// ---------------------------------------------------------------------------
// Organization Key Escrow Tests
// ---------------------------------------------------------------------------

func TestOrgKeyEscrow_RoundTrip(t *testing.T) {
	// Simulate admin creating org
	adminMasterKey := [32]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		110, 120, 130, 140, 150, 160, 170, 180, 190, 200,
		210, 220, 230, 240, 250, 1, 2, 3, 4, 5, 6, 7}

	orgPub, encOrgPriv, err := GenerateOrgKeyPair(adminMasterKey)
	if err != nil {
		t.Fatalf("GenerateOrgKeyPair failed: %v", err)
	}

	// Simulate user joining org — escrow their master key
	userMasterKey := [32]byte{99, 98, 97, 96, 95, 94, 93, 92, 91, 90,
		89, 88, 87, 86, 85, 84, 83, 82, 81, 80,
		79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68}

	escrowBlob, err := EncryptEscrow(userMasterKey, orgPub)
	if err != nil {
		t.Fatalf("EncryptEscrow failed: %v", err)
	}

	// Admin recovers user's master key via escrow
	orgPriv, err := DecryptOrgPrivateKey(encOrgPriv, adminMasterKey)
	if err != nil {
		t.Fatalf("DecryptOrgPrivateKey failed: %v", err)
	}

	recoveredKey, err := DecryptEscrow(escrowBlob, orgPriv)
	if err != nil {
		t.Fatalf("DecryptEscrow failed: %v", err)
	}
	ZeroBytes(orgPriv)

	if recoveredKey != userMasterKey {
		t.Error("recovered master key does not match original")
	}
}

func TestReEncryptOrgPrivateKey(t *testing.T) {
	oldKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	newKey := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	_, encOrgPriv, err := GenerateOrgKeyPair(oldKey)
	if err != nil {
		t.Fatalf("GenerateOrgKeyPair failed: %v", err)
	}

	// Decrypt with old key to get original private key
	origPriv, err := DecryptOrgPrivateKey(encOrgPriv, oldKey)
	if err != nil {
		t.Fatalf("DecryptOrgPrivateKey (old) failed: %v", err)
	}

	// Re-encrypt with new key
	reEncrypted, err := ReEncryptOrgPrivateKey(encOrgPriv, oldKey, newKey)
	if err != nil {
		t.Fatalf("ReEncryptOrgPrivateKey failed: %v", err)
	}

	// Decrypt with new key
	newPriv, err := DecryptOrgPrivateKey(reEncrypted, newKey)
	if err != nil {
		t.Fatalf("DecryptOrgPrivateKey (new) failed: %v", err)
	}

	if !bytes.Equal(origPriv, newPriv) {
		t.Error("re-encrypted private key doesn't match original")
	}
}

// ---------------------------------------------------------------------------
// ML-DSA-65 Signature Tests
// ---------------------------------------------------------------------------

func TestMLDSA_SignVerify(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}

	message := []byte("this is an important authentication token")

	sig, err := Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := Verify(message, sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("valid signature rejected")
	}
}

func TestMLDSA_WrongKey(t *testing.T) {
	_, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair #1 failed: %v", err)
	}
	pub2, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair #2 failed: %v", err)
	}

	message := []byte("test message")

	sig, err := Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := Verify(message, sig, pub2)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("signature verified with wrong public key — should fail")
	}
}

func TestMLDSA_TamperedMessage(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}

	sig, err := Sign([]byte("original message"), priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := Verify([]byte("tampered message"), sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("signature verified for tampered message — should fail")
	}
}

func TestMLDSA_TamperedSignature(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}

	message := []byte("test message")
	sig, err := Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Tamper with signature
	sig[0] ^= 0xFF

	valid, err := Verify(message, sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("tampered signature should not verify")
	}
}

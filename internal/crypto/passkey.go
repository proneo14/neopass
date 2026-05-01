package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// GeneratePasskeyPair generates a new passkey keypair for the given COSE algorithm.
// Returns COSE-encoded public key, raw private key bytes, and a random 32-byte credential ID.
func GeneratePasskeyPair(algorithm int) (publicKeyCBOR []byte, privateKey []byte, credentialID []byte, err error) {
	credentialID = make([]byte, 32)
	if _, err = rand.Read(credentialID); err != nil {
		return nil, nil, nil, fmt.Errorf("generate credential ID: %w", err)
	}

	switch algorithm {
	case COSEAlgES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("generate ES256 key: %w", err)
		}

		publicKeyCBOR, err = MarshalCOSEKey(COSEAlgES256, &key.PublicKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("marshal public key: %w", err)
		}

		// Encode private key as raw D value (32 bytes, zero-padded)
		d := key.D.Bytes()
		privateKey = make([]byte, 32)
		copy(privateKey[32-len(d):], d)

		return publicKeyCBOR, privateKey, credentialID, nil

	case COSEAlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("generate EdDSA key: %w", err)
		}

		publicKeyCBOR, err = MarshalCOSEKey(COSEAlgEdDSA, []byte(pub))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("marshal public key: %w", err)
		}

		// ed25519 private key is 64 bytes (seed + public)
		privateKey = make([]byte, ed25519.PrivateKeySize)
		copy(privateKey, priv)

		return publicKeyCBOR, privateKey, credentialID, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// SignAssertion signs authenticatorData || clientDataHash with the private key.
func SignAssertion(privateKeyRaw []byte, algorithm int, authData, clientDataHash []byte) ([]byte, error) {
	signedData := make([]byte, len(authData)+len(clientDataHash))
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash)

	switch algorithm {
	case COSEAlgES256:
		if len(privateKeyRaw) != 32 {
			return nil, errors.New("ES256 private key must be 32 bytes")
		}
		key := new(ecdsa.PrivateKey)
		key.Curve = elliptic.P256()
		key.D = new(big.Int).SetBytes(privateKeyRaw)
		ecdhKey, err := ecdh.P256().NewPrivateKey(privateKeyRaw)
		if err != nil {
			return nil, fmt.Errorf("ES256 derive public key: %w", err)
		}
		pubBytes := ecdhKey.PublicKey().Bytes()
		// Uncompressed point: 0x04 || X || Y, each coordinate 32 bytes
		key.X = new(big.Int).SetBytes(pubBytes[1:33])
		key.Y = new(big.Int).SetBytes(pubBytes[33:65])

		hash := sha256.Sum256(signedData)
		sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("ES256 sign: %w", err)
		}
		return sig, nil

	case COSEAlgEdDSA:
		if len(privateKeyRaw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("EdDSA private key must be %d bytes", ed25519.PrivateKeySize)
		}
		sig := ed25519.Sign(ed25519.PrivateKey(privateKeyRaw), signedData)
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// VerifyAssertion verifies a WebAuthn assertion signature.
func VerifyAssertion(publicKeyCBOR []byte, authData, clientDataHash, signature []byte) (bool, error) {
	pub, alg, err := UnmarshalCOSEKey(publicKeyCBOR)
	if err != nil {
		return false, fmt.Errorf("unmarshal public key: %w", err)
	}

	signedData := make([]byte, len(authData)+len(clientDataHash))
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash)

	switch alg {
	case COSEAlgES256:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		hash := sha256.Sum256(signedData)
		return ecdsa.VerifyASN1(ecKey, hash[:], signature), nil

	case COSEAlgEdDSA:
		edKey, ok := pub.([]byte)
		if !ok || len(edKey) != ed25519.PublicKeySize {
			return false, errors.New("expected ed25519 public key")
		}
		return ed25519.Verify(ed25519.PublicKey(edKey), signedData, signature), nil

	default:
		return false, fmt.Errorf("unsupported algorithm: %d", alg)
	}
}

// EncryptPasskeyPrivateKey encrypts a passkey private key with the user's master key.
func EncryptPasskeyPrivateKey(privateKey []byte, masterKey [32]byte) (encrypted, nonce []byte, err error) {
	return Encrypt(privateKey, masterKey)
}

// DecryptPasskeyPrivateKey decrypts a passkey private key with the user's master key.
func DecryptPasskeyPrivateKey(encrypted, nonce []byte, masterKey [32]byte) ([]byte, error) {
	return Decrypt(encrypted, nonce, masterKey)
}

package auth

import (
	"github.com/golang-jwt/jwt/v5"

	"github.com/password-manager/password-manager/internal/crypto"
)

// MLDSASigningMethod implements jwt.SigningMethod using ML-DSA-65 post-quantum signatures.
type MLDSASigningMethod struct{}

func (m *MLDSASigningMethod) Alg() string {
	return "ML-DSA-65"
}

// Verify validates a ML-DSA-65 signature on a JWT.
// The key must be a []byte containing the packed ML-DSA-65 public key.
func (m *MLDSASigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	pubKey, ok := key.([]byte)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	valid, err := crypto.Verify([]byte(signingString), sig, pubKey)
	if err != nil {
		return err
	}
	if !valid {
		return jwt.ErrSignatureInvalid
	}

	return nil
}

// Sign produces a ML-DSA-65 signature for a JWT.
// The key must be a []byte containing the packed ML-DSA-65 private key.
func (m *MLDSASigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	privKey, ok := key.([]byte)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}

	return crypto.Sign([]byte(signingString), privKey)
}

func init() {
	jwt.RegisterSigningMethod("ML-DSA-65", func() jwt.SigningMethod {
		return &MLDSASigningMethod{}
	})
}

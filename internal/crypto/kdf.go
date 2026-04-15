package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (OWASP recommended)
	argonMemory      = 64 * 1024 // 64 MB
	argonIterations  = 3
	argonParallelism = 4
	argonKeyLen      = 64 // 32 bytes master key + 32 bytes auth hash

	// SaltSize is the size of the salt in bytes.
	SaltSize = 16
)

// DeriveKeys derives a 256-bit Master Key and a 256-bit Auth Hash from the
// master password using Argon2id. The master key is used for vault encryption;
// the auth hash is sent to the server for login verification.
//
// If salt is nil, a random 16-byte salt is generated.
// Returns (masterKey, authHash, salt, error).
func DeriveKeys(masterPassword string, salt []byte) (masterKey [32]byte, authHash [32]byte, usedSalt []byte, err error) {
	if salt == nil {
		salt, err = GenerateSalt()
		if err != nil {
			return masterKey, authHash, nil, err
		}
	}

	derived := argon2.IDKey(
		[]byte(masterPassword),
		salt,
		argonIterations,
		argonMemory,
		argonParallelism,
		argonKeyLen,
	)

	copy(masterKey[:], derived[:32])
	copy(authHash[:], derived[32:64])
	ZeroBytes(derived)

	return masterKey, authHash, salt, nil
}

// GenerateSalt returns a cryptographically random 16-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

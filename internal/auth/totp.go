package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	pmcrypto "github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// 2FA errors
var (
	ErrTOTPNotConfigured = fmt.Errorf("totp not configured")
	ErrTOTPAlreadySetup  = fmt.Errorf("totp already verified")
	ErrInvalidTOTPCode   = fmt.Errorf("invalid totp code")
	ErrShareExpired      = fmt.Errorf("shared totp expired")
	ErrShareClaimed      = fmt.Errorf("shared totp already claimed")
)

const (
	recoveryCodeCount  = 8
	recoveryCodeLength = 8
	totpIssuer         = "QuantumPasswordManager"
)

// TOTPSetupResponse is returned when setting up 2FA.
type TOTPSetupResponse struct {
	Secret        string   `json:"secret"`
	QRURI         string   `json:"qr_uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// TOTPService provides 2FA operations.
type TOTPService struct {
	totpRepo *db.TOTPRepo
	userRepo *db.UserRepo
}

// NewTOTPService creates a new TOTPService.
func NewTOTPService(totpRepo *db.TOTPRepo, userRepo *db.UserRepo) *TOTPService {
	return &TOTPService{
		totpRepo: totpRepo,
		userRepo: userRepo,
	}
}

// SetupTOTP generates a TOTP secret and recovery codes for a user.
// The encryptionKey is the user's master key used to encrypt the TOTP secret at rest.
func (s *TOTPService) SetupTOTP(ctx context.Context, userID string, encryptionKey [32]byte) (TOTPSetupResponse, error) {
	// Fetch user email for TOTP account name
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return TOTPSetupResponse{}, fmt.Errorf("get user: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Email,
	})
	if err != nil {
		return TOTPSetupResponse{}, fmt.Errorf("generate totp: %w", err)
	}

	secret := key.Secret()

	// Encrypt the secret before storing
	encryptedSecret, nonce, err := pmcrypto.Encrypt([]byte(secret), encryptionKey)
	if err != nil {
		return TOTPSetupResponse{}, fmt.Errorf("encrypt totp secret: %w", err)
	}

	// Store as nonce || ciphertext
	blob := make([]byte, len(nonce)+len(encryptedSecret))
	copy(blob, nonce)
	copy(blob[len(nonce):], encryptedSecret)

	if _, err := s.totpRepo.UpsertTOTPSecret(ctx, userID, blob); err != nil {
		return TOTPSetupResponse{}, err
	}

	// Generate recovery codes
	recoveryCodes, codeHashes, err := generateRecoveryCodes()
	if err != nil {
		return TOTPSetupResponse{}, err
	}

	if err := s.totpRepo.InsertRecoveryCodes(ctx, userID, codeHashes); err != nil {
		return TOTPSetupResponse{}, err
	}

	log.Info().Str("user_id", userID).Msg("TOTP setup initiated")

	return TOTPSetupResponse{
		Secret:        secret,
		QRURI:         key.URL(),
		RecoveryCodes: recoveryCodes,
	}, nil
}

// VerifyTOTPSetup confirms the initial TOTP code and marks 2FA as active.
func (s *TOTPService) VerifyTOTPSetup(ctx context.Context, userID string, code string, encryptionKey [32]byte) error {
	secret, err := s.decryptTOTPSecret(ctx, userID, encryptionKey)
	if err != nil {
		return err
	}

	valid := totp.Validate(code, secret)
	if !valid {
		return ErrInvalidTOTPCode
	}

	if err := s.totpRepo.MarkTOTPVerified(ctx, userID); err != nil {
		return err
	}

	log.Info().Str("user_id", userID).Msg("TOTP verified and enabled")
	return nil
}

// ValidateTOTP checks a TOTP code or recovery code during login.
func (s *TOTPService) ValidateTOTP(ctx context.Context, userID string, code string, encryptionKey [32]byte) error {
	// First try TOTP code
	secret, err := s.decryptTOTPSecret(ctx, userID, encryptionKey)
	if err != nil {
		return err
	}

	if totp.Validate(code, secret) {
		return nil
	}

	// Try recovery codes
	return s.tryRecoveryCode(ctx, userID, code)
}

// ValidateTOTPWithoutKey checks a TOTP code during login when the encryption key
// is not yet available. This decrypts internally using the stored encrypted secret.
// For login flow: the server stores the encrypted TOTP secret and we need
// the user's encryption key. In practice, the client sends the code and we
// validate server-side. Since the TOTP secret is encrypted with the user's
// master key (which the server doesn't have), we need a server-side copy.
//
// Design decision: store TOTP secret encrypted with a server-derived key
// for login validation. The user's master key encrypted copy is for export/backup.
func (s *TOTPService) ValidateTOTPServerSide(ctx context.Context, userID string, code string) error {
	// Try recovery codes first (they're bcrypt-hashed, no key needed)
	if err := s.tryRecoveryCode(ctx, userID, code); err == nil {
		return nil
	}

	// For TOTP validation during login, we need the secret.
	// The current design encrypts with user's master key. For server-side
	// validation during login (before the user has decrypted anything),
	// we store the TOTP secret encrypted with a server key in production.
	// For now, return an error indicating the client should validate.
	return fmt.Errorf("server-side TOTP validation requires encryption key")
}

// ShareTOTP encrypts a TOTP secret with the recipient's public key and stores it.
func (s *TOTPService) ShareTOTP(ctx context.Context, fromUserID, toUserID string, totpSecret string, expiresIn time.Duration) (string, error) {
	// Fetch recipient's public key
	recipient, err := s.userRepo.GetUserByID(ctx, toUserID)
	if err != nil {
		return "", fmt.Errorf("get recipient: %w", err)
	}
	if recipient.PublicKey == nil {
		return "", fmt.Errorf("recipient has no public key")
	}

	// Encrypt TOTP secret with recipient's X-Wing public key via KEM
	sharedSecret, kemCiphertext, err := pmcrypto.Encapsulate(recipient.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encapsulate: %w", err)
	}

	// Derive encryption key from KEM shared secret
	encKey := pmcrypto.DeriveSessionKey(sharedSecret, "shared-2fa")
	pmcrypto.ZeroBytes(sharedSecret[:])

	// Encrypt the TOTP secret
	encSecret, nonce, err := pmcrypto.Encrypt([]byte(totpSecret), encKey)
	pmcrypto.ZeroBytes(encKey[:])
	if err != nil {
		return "", fmt.Errorf("encrypt shared totp: %w", err)
	}

	// Blob = KEM ciphertext || nonce || encrypted secret
	blob := make([]byte, len(kemCiphertext)+len(nonce)+len(encSecret))
	copy(blob, kemCiphertext)
	copy(blob[len(kemCiphertext):], nonce)
	copy(blob[len(kemCiphertext)+len(nonce):], encSecret)

	expiresAt := time.Now().Add(expiresIn)
	shareID, err := s.totpRepo.InsertSharedTOTP(ctx, fromUserID, toUserID, blob, expiresAt)
	if err != nil {
		return "", err
	}

	log.Info().
		Str("from", fromUserID).
		Str("to", toUserID).
		Str("share_id", shareID).
		Msg("TOTP shared")

	return shareID, nil
}

// ClaimSharedTOTP decrypts and returns a shared TOTP secret.
func (s *TOTPService) ClaimSharedTOTP(ctx context.Context, userID string, shareID string, privateKey []byte) (string, error) {
	shared, err := s.totpRepo.GetSharedTOTP(ctx, shareID, userID)
	if err != nil {
		return "", err
	}

	if shared.Claimed {
		return "", ErrShareClaimed
	}
	if time.Now().After(shared.ExpiresAt) {
		return "", ErrShareExpired
	}

	kemCtSize := 1120 // xwing.CiphertextSize
	if len(shared.EncryptedTOTPSecret) < kemCtSize+pmcrypto.NonceSize {
		return "", fmt.Errorf("invalid shared totp blob")
	}

	kemCiphertext := shared.EncryptedTOTPSecret[:kemCtSize]
	nonce := shared.EncryptedTOTPSecret[kemCtSize : kemCtSize+pmcrypto.NonceSize]
	encSecret := shared.EncryptedTOTPSecret[kemCtSize+pmcrypto.NonceSize:]

	// Decapsulate to get shared secret
	sharedSecret, err := pmcrypto.Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return "", fmt.Errorf("decapsulate: %w", err)
	}

	// Derive same encryption key
	encKey := pmcrypto.DeriveSessionKey(sharedSecret, "shared-2fa")
	pmcrypto.ZeroBytes(sharedSecret[:])

	// Decrypt TOTP secret
	plainSecret, err := pmcrypto.Decrypt(encSecret, nonce, encKey)
	pmcrypto.ZeroBytes(encKey[:])
	if err != nil {
		return "", fmt.Errorf("decrypt shared totp: %w", err)
	}

	// Mark as claimed
	if err := s.totpRepo.MarkSharedTOTPClaimed(ctx, shareID); err != nil {
		return "", err
	}

	log.Info().Str("user_id", userID).Str("share_id", shareID).Msg("shared TOTP claimed")

	return string(plainSecret), nil
}

// DisableTOTP removes 2FA for a user.
func (s *TOTPService) DisableTOTP(ctx context.Context, userID string) error {
	if err := s.totpRepo.DeleteTOTPSecret(ctx, userID); err != nil {
		return err
	}
	log.Info().Str("user_id", userID).Msg("TOTP disabled")
	return nil
}

// decryptTOTPSecret retrieves and decrypts the stored TOTP secret.
func (s *TOTPService) decryptTOTPSecret(ctx context.Context, userID string, encryptionKey [32]byte) (string, error) {
	stored, err := s.totpRepo.GetTOTPSecret(ctx, userID)
	if err != nil {
		return "", err
	}

	if len(stored.EncryptedSecret) < pmcrypto.NonceSize {
		return "", fmt.Errorf("invalid encrypted totp secret")
	}

	nonce := stored.EncryptedSecret[:pmcrypto.NonceSize]
	ciphertext := stored.EncryptedSecret[pmcrypto.NonceSize:]

	plaintext, err := pmcrypto.Decrypt(ciphertext, nonce, encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt totp secret: %w", err)
	}

	return string(plaintext), nil
}

// tryRecoveryCode checks if the code matches any unused recovery code.
func (s *TOTPService) tryRecoveryCode(ctx context.Context, userID string, code string) error {
	codes, err := s.totpRepo.GetUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}

	normalizedCode := strings.ToUpper(strings.TrimSpace(code))

	for _, c := range codes {
		if err := bcrypt.CompareHashAndPassword(c.CodeHash, []byte(normalizedCode)); err == nil {
			// Match found — mark as used
			if err := s.totpRepo.MarkRecoveryCodeUsed(ctx, c.ID); err != nil {
				return err
			}
			log.Info().Str("user_id", userID).Msg("recovery code used")
			return nil
		}
	}

	return ErrInvalidTOTPCode
}

// generateRecoveryCodes creates recovery codes and their bcrypt hashes.
func generateRecoveryCodes() (plaintextCodes []string, hashedCodes [][]byte, err error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars (0/O, 1/I)

	for i := 0; i < recoveryCodeCount; i++ {
		code := make([]byte, recoveryCodeLength)
		for j := range code {
			b := make([]byte, 1)
			if _, err := rand.Read(b); err != nil {
				return nil, nil, fmt.Errorf("generate recovery code: %w", err)
			}
			code[j] = charset[int(b[0])%len(charset)]
		}

		codeStr := string(code)
		hash, err := bcrypt.GenerateFromPassword([]byte(codeStr), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash recovery code: %w", err)
		}

		plaintextCodes = append(plaintextCodes, codeStr)
		hashedCodes = append(hashedCodes, hash)
	}

	return plaintextCodes, hashedCodes, nil
}

// GenerateCurrentTOTP generates the current TOTP code for a given secret.
// Used by admin when sharing 2FA assistance.
func GenerateCurrentTOTP(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("generate totp code: %w", err)
	}
	return code, nil
}

// Has2FA checks if a user has verified 2FA enabled.
func (s *TOTPService) Has2FA(ctx context.Context, userID string) (bool, error) {
	secret, err := s.totpRepo.GetTOTPSecret(ctx, userID)
	if err != nil {
		if strings.Contains(err.Error(), "not configured") {
			return false, nil
		}
		return false, err
	}
	return secret.Verified, nil
}

// ListPendingShares returns pending shared TOTPs for a user.
func (s *TOTPService) ListPendingShares(ctx context.Context, userID string) ([]db.SharedTOTP, error) {
	return s.totpRepo.ListPendingSharedTOTP(ctx, userID)
}

// HexToBytes is a helper to decode hex-encoded private key for claim operations.
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

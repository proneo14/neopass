package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// Errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrTwoFactorRequired  = errors.New("2fa required")
	ErrInvalidToken       = errors.New("invalid token")
)

// RegisterRequest contains the fields needed to register a new user.
type RegisterRequest struct {
	Email               string          `json:"email"`
	AuthHash            string          `json:"auth_hash"`    // hex-encoded
	Salt                string          `json:"salt"`         // hex-encoded
	KDFParams           json.RawMessage `json:"kdf_params"`
	PublicKey           string          `json:"public_key"`   // hex-encoded
	EncryptedPrivateKey string          `json:"encrypted_private_key"` // hex-encoded
}

// RegisterResponse is returned after successful registration.
type RegisterResponse struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LoginRequest contains the fields needed to log in.
type LoginRequest struct {
	Email    string `json:"email"`
	AuthHash string `json:"auth_hash"` // hex-encoded
}

// LoginResponse is returned after successful login.
type LoginResponse struct {
	UserID       string   `json:"user_id,omitempty"`
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Requires2FA  bool     `json:"requires_2fa,omitempty"`
	TempToken    string   `json:"temp_token,omitempty"`    // partial token for 2FA flow
	Methods      []string `json:"methods,omitempty"`       // e.g. ["totp","hardware_key"]
}

// TokenResponse is returned when refreshing tokens.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Claims are the JWT claims used for access tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
	OrgID  string `json:"org_id,omitempty"`
	Role   string `json:"role,omitempty"`
	Is2FA  bool   `json:"is_2fa,omitempty"` // true = partial token awaiting 2FA
}

// ServiceConfig holds configuration for the auth service.
type ServiceConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

// Service provides authentication operations.
type Service struct {
	userRepo    db.UserRepository
	vaultRepo   db.VaultRepository
	orgRepo     db.OrgRepository
	signingKey  []byte // ML-DSA-65 private key
	verifyKey   []byte // ML-DSA-65 public key
	config      ServiceConfig
}

// NewService creates a new auth Service.
// It generates an ML-DSA-65 keypair for JWT signing if keys are not provided.
func NewService(userRepo db.UserRepository, signingKey, verifyKey []byte, cfg ServiceConfig, optionalRepos ...interface{}) (*Service, error) {
	if signingKey == nil || verifyKey == nil {
		var err error
		verifyKey, signingKey, err = crypto.GenerateSigningKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate signing keypair: %w", err)
		}
		log.Info().Msg("generated new ML-DSA-65 signing keypair for JWT")
	}

	if cfg.AccessTokenDuration == 0 {
		cfg.AccessTokenDuration = 15 * time.Minute
	}
	if cfg.RefreshTokenDuration == 0 {
		cfg.RefreshTokenDuration = 7 * 24 * time.Hour
	}

	svc := &Service{
		userRepo:   userRepo,
		signingKey: signingKey,
		verifyKey:  verifyKey,
		config:     cfg,
	}
	for _, r := range optionalRepos {
		switch v := r.(type) {
		case db.VaultRepository:
			svc.vaultRepo = v
		case db.OrgRepository:
			svc.orgRepo = v
		}
	}
	return svc, nil
}

// Register creates a new user account.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	authHashBytes, err := hex.DecodeString(req.AuthHash)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("decode auth_hash: %w", err)
	}
	saltBytes, err := hex.DecodeString(req.Salt)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("decode salt: %w", err)
	}
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("decode public_key: %w", err)
	}
	encPrivKeyBytes, err := hex.DecodeString(req.EncryptedPrivateKey)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("decode encrypted_private_key: %w", err)
	}

	// Server-side bcrypt of the client's auth hash (double-hashing)
	bcryptHash, err := bcrypt.GenerateFromPassword(authHashBytes, bcrypt.DefaultCost)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("bcrypt auth hash: %w", err)
	}

	kdfParams := req.KDFParams
	if kdfParams == nil {
		kdfParams = json.RawMessage(`{"memory":65536,"iterations":3,"parallelism":4}`)
	}

	user, err := s.userRepo.CreateUser(ctx, req.Email, bcryptHash, saltBytes, kdfParams, pubKeyBytes, encPrivKeyBytes)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("create user: %w", err)
	}

	accessToken, err := s.generateAccessToken(user.ID, "", "")
	if err != nil {
		return RegisterResponse{}, err
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return RegisterResponse{}, err
	}

	log.Info().Str("user_id", user.ID).Str("email", req.Email).Msg("user registered")

	return RegisterResponse{
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Login authenticates a user with email and auth hash.
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Use generic error to avoid user enumeration
		log.Debug().Err(err).Str("email", req.Email).Msg("login: user lookup failed")
		return LoginResponse{}, ErrInvalidCredentials
	}

	authHashBytes, err := hex.DecodeString(req.AuthHash)
	if err != nil {
		return LoginResponse{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(user.AuthHash, authHashBytes); err != nil {
		log.Debug().Str("user_id", user.ID).Msg("login: password mismatch")
		return LoginResponse{}, ErrInvalidCredentials
	}

	// Check if 2FA is enabled
	if user.Has2FA || user.RequireHWKey {
		tempToken, err := s.generateTempToken(user.ID)
		if err != nil {
			return LoginResponse{}, err
		}

		var methods []string
		if user.Has2FA {
			methods = append(methods, "totp")
		}
		if user.RequireHWKey {
			methods = append(methods, "hardware_key")
		}

		log.Info().Str("user_id", user.ID).Strs("methods", methods).Msg("login: 2FA required")
		return LoginResponse{
			Requires2FA: true,
			TempToken:   tempToken,
			Methods:     methods,
		}, nil
	}

	accessToken, err := s.generateAccessToken(user.ID, "", "")
	if err != nil {
		return LoginResponse{}, err
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return LoginResponse{}, err
	}

	log.Info().Str("user_id", user.ID).Msg("login successful")

	return LoginResponse{
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Complete2FALogin exchanges a temp token + valid 2FA for full access tokens.
func (s *Service) Complete2FALogin(ctx context.Context, tempToken string, userID string) (LoginResponse, error) {
	// Validate the temp token
	claims, err := s.ValidateToken(tempToken)
	if err != nil {
		return LoginResponse{}, ErrInvalidToken
	}
	if !claims.Is2FA || claims.UserID != userID {
		return LoginResponse{}, ErrInvalidToken
	}

	accessToken, err := s.generateAccessToken(userID, "", "")
	if err != nil {
		return LoginResponse{}, err
	}

	refreshToken, err := s.generateRefreshToken(userID)
	if err != nil {
		return LoginResponse{}, err
	}

	return LoginResponse{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken validates a refresh token and issues new token pair.
func (s *Service) RefreshToken(ctx context.Context, refreshTokenStr string) (TokenResponse, error) {
	claims, err := s.ValidateToken(refreshTokenStr)
	if err != nil {
		return TokenResponse{}, ErrInvalidToken
	}

	// Verify it's a refresh token (longer expiry, no role)
	if claims.UserID == "" {
		return TokenResponse{}, ErrInvalidToken
	}

	// Check if the user's tokens have been revoked (e.g. after takeover)
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return TokenResponse{}, ErrInvalidToken
	}
	if user.TokensRevokedAt != nil && claims.IssuedAt != nil {
		if claims.IssuedAt.Time.Before(*user.TokensRevokedAt) {
			return TokenResponse{}, ErrInvalidToken
		}
	}

	accessToken, err := s.generateAccessToken(claims.UserID, claims.OrgID, claims.Role)
	if err != nil {
		return TokenResponse{}, err
	}

	newRefresh, err := s.generateRefreshToken(claims.UserID)
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
	}, nil
}

// ValidateToken parses and validates a JWT, returning the claims.
func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*MLDSASigningMethod); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GetVerifyKey returns the public verification key (for middleware).
func (s *Service) GetVerifyKey() []byte {
	return s.verifyKey
}

func (s *Service) generateAccessToken(userID, orgID, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "password-manager",
		},
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
	}

	token := jwt.NewWithClaims(&MLDSASigningMethod{}, claims)
	return token.SignedString(s.signingKey)
}

func (s *Service) generateRefreshToken(userID string) (string, error) {
	now := time.Now()

	// Add random jti to prevent token reuse
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "password-manager",
			ID:        hex.EncodeToString(jti),
		},
		UserID: userID,
	}

	token := jwt.NewWithClaims(&MLDSASigningMethod{}, claims)
	return token.SignedString(s.signingKey)
}

func (s *Service) generateTempToken(userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), // short-lived
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "password-manager",
		},
		UserID: userID,
		Is2FA:  true,
	}

	token := jwt.NewWithClaims(&MLDSASigningMethod{}, claims)
	return token.SignedString(s.signingKey)
}

// ChangeOwnPassword lets a user change their own master password.
// It verifies the old credentials, then re-encrypts all vault entries and keys with the new master key.
func (s *Service) ChangeOwnPassword(ctx context.Context, userID string, oldMasterKey, newMasterKey [32]byte, newAuthHash, newSalt string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	newAuthHashBytes, err := hex.DecodeString(newAuthHash)
	if err != nil {
		return fmt.Errorf("decode new auth hash: %w", err)
	}
	newSaltBytes, err := hex.DecodeString(newSalt)
	if err != nil {
		return fmt.Errorf("decode new salt: %w", err)
	}

	// Re-encrypt all vault entries
	if s.vaultRepo != nil {
		entries, err := s.vaultRepo.ListEntries(ctx, userID, db.VaultFilters{})
		if err != nil {
			return fmt.Errorf("list vault entries: %w", err)
		}

		for _, e := range entries {
			plaintext, err := crypto.Decrypt(e.EncryptedData, e.Nonce, oldMasterKey)
			if err != nil {
				// Entry is corrupted/unreadable (e.g. from a prior bad reset) — delete it
				log.Warn().Str("entry_id", e.ID).Err(err).Msg("deleting unrecoverable vault entry during password change")
				if delErr := s.vaultRepo.DeleteEntry(ctx, e.ID, userID); delErr != nil {
					log.Error().Str("entry_id", e.ID).Err(delErr).Msg("failed to delete corrupted entry")
				}
				continue
			}

			newCt, newNonce, err := crypto.Encrypt(plaintext, newMasterKey)
			crypto.ZeroBytes(plaintext)
			if err != nil {
				return fmt.Errorf("re-encrypt entry %s: %w", e.ID, err)
			}

			e.EncryptedData = newCt
			e.Nonce = newNonce
			if _, err := s.vaultRepo.UpdateEntry(ctx, e); err != nil {
				return fmt.Errorf("update entry %s: %w", e.ID, err)
			}
		}
	}

	// Bcrypt the new auth hash
	bcryptHash, err := bcrypt.GenerateFromPassword(newAuthHashBytes, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}

	// Re-encrypt user's private key with new master key
	encPrivKey := user.EncryptedPrivateKey
	if len(encPrivKey) > crypto.NonceSize {
		oldNonce := encPrivKey[:crypto.NonceSize]
		oldCt := encPrivKey[crypto.NonceSize:]
		privKeyPlain, err := crypto.Decrypt(oldCt, oldNonce, oldMasterKey)
		if err != nil {
			// Private key is corrupted — keep existing (will need re-registration to fix keys)
			log.Warn().Str("user_id", userID).Err(err).Msg("could not decrypt private key during password change, keeping existing")
		} else {
			newCt, newNonce, err := crypto.Encrypt(privKeyPlain, newMasterKey)
			crypto.ZeroBytes(privKeyPlain)
			if err != nil {
				return fmt.Errorf("re-encrypt user private key: %w", err)
			}

			encPrivKey = make([]byte, len(newNonce)+len(newCt))
			copy(encPrivKey, newNonce)
			copy(encPrivKey[len(newNonce):], newCt)
		}
	}

	if err := s.userRepo.UpdateUserKeys(ctx, userID, bcryptHash, newSaltBytes, user.PublicKey, encPrivKey); err != nil {
		return fmt.Errorf("update user keys: %w", err)
	}

	// Update escrow if user belongs to an org
	if s.orgRepo != nil {
		if _, org, err := s.orgRepo.GetUserOrg(ctx, userID); err == nil {
			newEscrow, err := crypto.EncryptEscrow(newMasterKey, org.OrgPublicKey)
			if err != nil {
				log.Error().Err(err).Str("user_id", userID).Msg("failed to encrypt escrow during password change")
			} else if err := s.orgRepo.UpdateEscrowBlob(ctx, org.ID, userID, newEscrow); err != nil {
				log.Error().Err(err).Str("user_id", userID).Msg("failed to update escrow during password change")
			}
		}
	}

	log.Info().Str("user_id", userID).Msg("user changed own password")
	return nil
}

// SetRequireHWKey enables or disables the hardware key login requirement for a user.
func (s *Service) SetRequireHWKey(ctx context.Context, userID string, require bool) error {
	return s.userRepo.SetRequireHWKey(ctx, userID, require)
}

// GetUserByID returns a user by ID (for settings retrieval).
func (s *Service) GetUserByID(ctx context.Context, userID string) (db.User, error) {
	return s.userRepo.GetUserByID(ctx, userID)
}

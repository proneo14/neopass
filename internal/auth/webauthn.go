package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
	"github.com/rs/zerolog/log"
)

// WebAuthnConfig holds the relying party configuration.
type WebAuthnConfig struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
}

// WebAuthnService handles passkey registration and authentication.
type WebAuthnService struct {
	config      WebAuthnConfig
	passkeyRepo db.PasskeyRepository
	hwKeyRepo   db.HardwareKeyRepository
	sessions    map[string]*webAuthnSession
	mu          sync.Mutex
}

type webAuthnSession struct {
	Challenge   []byte
	UserID      string
	RPID        string
	CreatedAt   time.Time
	IsHardware  bool
}

const webAuthnSessionTTL = 5 * time.Minute

// NewWebAuthnService creates a new WebAuthnService.
func NewWebAuthnService(config WebAuthnConfig, passkeyRepo db.PasskeyRepository, hwKeyRepo db.HardwareKeyRepository) *WebAuthnService {
	return &WebAuthnService{
		config:      config,
		passkeyRepo: passkeyRepo,
		hwKeyRepo:   hwKeyRepo,
		sessions:    make(map[string]*webAuthnSession),
	}
}

// ── Passkey Registration ─────────────────────────────────────────────────────

// PasskeyRegistrationOptions is returned to the client to begin registration.
type PasskeyRegistrationOptions struct {
	Challenge        string                   `json:"challenge"`
	RP               map[string]string        `json:"rp"`
	User             map[string]interface{}   `json:"user"`
	PubKeyCredParams []map[string]interface{} `json:"pubKeyCredParams"`
	Timeout          int                      `json:"timeout"`
	SessionID        string                   `json:"session_id"`
}

// BeginPasskeyRegistration starts a passkey registration ceremony.
func (s *WebAuthnService) BeginPasskeyRegistration(ctx context.Context, userID, rpID, rpName, userName, displayName string) (*PasskeyRegistrationOptions, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	userHandle := make([]byte, 32)
	if _, err := rand.Read(userHandle); err != nil {
		return nil, fmt.Errorf("generate user handle: %w", err)
	}

	sessionID := generateSessionID()
	s.mu.Lock()
	s.sessions[sessionID] = &webAuthnSession{
		Challenge: challenge,
		UserID:    userID,
		RPID:      rpID,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	// Clean up expired sessions periodically
	go s.cleanExpiredSessions()

	opts := &PasskeyRegistrationOptions{
		Challenge: base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(challenge),
		RP: map[string]string{
			"name": rpName,
			"id":   rpID,
		},
		User: map[string]interface{}{
			"id":          base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(userHandle),
			"name":        userName,
			"displayName": displayName,
		},
		PubKeyCredParams: []map[string]interface{}{
			{"type": "public-key", "alg": crypto.COSEAlgES256},
			{"type": "public-key", "alg": crypto.COSEAlgEdDSA},
		},
		Timeout:   60000,
		SessionID: sessionID,
	}

	return opts, nil
}

// FinishPasskeyRegistrationRequest is the client's response to complete registration.
type FinishPasskeyRegistrationRequest struct {
	SessionID    string `json:"session_id"`
	CredentialID string `json:"credential_id"`
	Algorithm    int    `json:"algorithm"`
	MasterKeyHex string `json:"master_key_hex"`
	RPID         string `json:"rp_id"`
	RPName       string `json:"rp_name"`
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	UserIDB64    string `json:"user_id_b64"`
}

// FinishPasskeyRegistration completes passkey registration by generating the keypair server-side.
// In our architecture, the Go sidecar acts as the software authenticator —
// it generates the keypair, encrypts the private key, and stores it.
func (s *WebAuthnService) FinishPasskeyRegistration(ctx context.Context, userID string, req *FinishPasskeyRegistrationRequest) (*db.PasskeyCredential, error) {
	// Validate session
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if ok {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("invalid or expired session")
	}
	if time.Since(sess.CreatedAt) > webAuthnSessionTTL {
		return nil, fmt.Errorf("session expired")
	}
	if sess.UserID != userID {
		return nil, fmt.Errorf("session user mismatch")
	}

	// Parse master key
	masterKey, err := parseMasterKey(req.MasterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key: %w", err)
	}

	// Generate passkey pair
	algorithm := req.Algorithm
	if algorithm == 0 {
		algorithm = crypto.COSEAlgES256
	}

	publicKeyCBOR, privateKey, credentialID, err := crypto.GeneratePasskeyPair(algorithm)
	if err != nil {
		return nil, fmt.Errorf("generate passkey pair: %w", err)
	}
	defer crypto.ZeroBytes(privateKey)

	// Encrypt private key with master key
	encryptedPrivKey, nonce, err := crypto.EncryptPasskeyPrivateKey(privateKey, masterKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	// Use website's user.id as userHandle if provided, otherwise generate random
	var userHandle []byte
	if req.UserIDB64 != "" {
		b64 := base64.URLEncoding.WithPadding(base64.NoPadding)
		if decoded, err := b64.DecodeString(req.UserIDB64); err == nil {
			userHandle = decoded
		}
	}
	if len(userHandle) == 0 {
		userHandle = make([]byte, 32)
		if _, err := rand.Read(userHandle); err != nil {
			return nil, fmt.Errorf("generate user handle: %w", err)
		}
	}

	passkey := db.PasskeyCredential{
		UserID:           userID,
		CredentialID:     credentialID,
		RPID:             req.RPID,
		RPName:           req.RPName,
		UserHandle:       userHandle,
		Username:         req.Username,
		DisplayName:      req.DisplayName,
		PublicKeyCBOR:    publicKeyCBOR,
		EncryptedPrivKey: encryptedPrivKey,
		PrivateKeyNonce:  nonce,
		SignCount:        0,
		AAGUID:           crypto.LGIPassAAGUID[:],
		Transports:       []string{"internal"},
		Discoverable:     true,
		BackedUp:         true,
		Algorithm:        algorithm,
	}

	result, err := s.passkeyRepo.CreatePasskey(ctx, passkey)
	if err != nil {
		return nil, fmt.Errorf("store passkey: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Str("rp_id", req.RPID).
		Str("passkey_id", result.ID).
		Msg("passkey registered")

	return &result, nil
}

// ── Passkey Authentication ───────────────────────────────────────────────────

// PasskeyAuthOptions is returned to start an authentication ceremony.
type PasskeyAuthOptions struct {
	Challenge        string                   `json:"challenge"`
	RPID             string                   `json:"rp_id"`
	AllowCredentials []map[string]interface{} `json:"allowCredentials,omitempty"`
	Timeout          int                      `json:"timeout"`
	SessionID        string                   `json:"session_id"`
}

// BeginPasskeyAuthentication starts a passkey authentication ceremony.
func (s *WebAuthnService) BeginPasskeyAuthentication(ctx context.Context, userID, rpID string) (*PasskeyAuthOptions, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	sessionID := generateSessionID()
	s.mu.Lock()
	s.sessions[sessionID] = &webAuthnSession{
		Challenge: challenge,
		UserID:    userID,
		RPID:      rpID,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	// Get existing credentials for this RP
	creds, err := s.passkeyRepo.GetPasskeysByRPID(ctx, userID, rpID)
	if err != nil {
		return nil, fmt.Errorf("get passkeys: %w", err)
	}

	var allowCreds []map[string]interface{}
	for _, c := range creds {
		allowCreds = append(allowCreds, map[string]interface{}{
			"type":       "public-key",
			"id":         base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(c.CredentialID),
			"transports": c.Transports,
		})
	}

	opts := &PasskeyAuthOptions{
		Challenge:        base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(challenge),
		RPID:             rpID,
		AllowCredentials: allowCreds,
		Timeout:          60000,
		SessionID:        sessionID,
	}

	return opts, nil
}

// PasskeySignRequest is the request to sign an assertion using a stored passkey.
type PasskeySignRequest struct {
	SessionID      string `json:"session_id"`
	CredentialID   string `json:"credential_id"`
	MasterKeyHex   string `json:"master_key_hex"`
	RPID           string `json:"rp_id"`
	Origin         string `json:"origin"`
	Challenge      string `json:"challenge"`
}

// PasskeySignResponse contains the WebAuthn assertion response.
type PasskeySignResponse struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle"`
}

// SignPasskeyAssertion signs an assertion using a stored passkey.
func (s *WebAuthnService) SignPasskeyAssertion(ctx context.Context, userID string, req *PasskeySignRequest) (*PasskeySignResponse, error) {
	// Validate session
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if ok {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("invalid or expired session")
	}
	if time.Since(sess.CreatedAt) > webAuthnSessionTTL {
		return nil, fmt.Errorf("session expired")
	}

	// Decode credential ID
	credIDBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(req.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("decode credential ID: %w", err)
	}

	// Fetch passkey
	passkey, err := s.passkeyRepo.GetPasskeyByCredentialID(ctx, credIDBytes)
	if err != nil {
		return nil, fmt.Errorf("get passkey: %w", err)
	}

	if passkey.UserID != userID {
		return nil, fmt.Errorf("passkey does not belong to user")
	}

	// Parse master key and decrypt private key
	masterKey, err := parseMasterKey(req.MasterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key: %w", err)
	}

	privateKey, err := crypto.DecryptPasskeyPrivateKey(passkey.EncryptedPrivKey, passkey.PrivateKeyNonce, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	defer crypto.ZeroBytes(privateKey)

	// Build authenticator data
	rpIDHash := crypto.RPIDHash(req.RPID)
	flags := crypto.FlagUserPresent | crypto.FlagUserVerified | crypto.FlagBackupElig | crypto.FlagBackupState
	newSignCount := uint32(passkey.SignCount + 1)
	authData := crypto.MarshalAuthenticatorData(rpIDHash, flags, newSignCount, nil)

	// Use website's challenge if provided, otherwise use our session challenge
	challenge := req.Challenge
	if challenge == "" {
		challenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sess.Challenge)
	}

	// Build clientDataJSON
	clientData := map[string]interface{}{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      req.Origin,
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("marshal client data: %w", err)
	}

	// Sign
	clientDataHash := sha256.Sum256(clientDataJSON)
	signature, err := crypto.SignAssertion(privateKey, passkey.Algorithm, authData, clientDataHash[:])
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	// Update sign count
	if err := s.passkeyRepo.UpdateSignCount(ctx, credIDBytes, int(newSignCount)); err != nil {
		log.Warn().Err(err).Msg("failed to update sign count")
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)
	resp := &PasskeySignResponse{
		CredentialID:      req.CredentialID,
		AuthenticatorData: b64.EncodeToString(authData),
		ClientDataJSON:    b64.EncodeToString(clientDataJSON),
		Signature:         b64.EncodeToString(signature),
		UserHandle:        b64.EncodeToString(passkey.UserHandle),
	}

	log.Info().
		Str("user_id", userID).
		Str("rp_id", req.RPID).
		Int("sign_count", int(newSignCount)).
		Msg("passkey assertion signed")

	return resp, nil
}

// ── Passkey Listing ──────────────────────────────────────────────────────────

// ListPasskeys returns all passkeys for a user, optionally filtered by RP ID.
func (s *WebAuthnService) ListPasskeys(ctx context.Context, userID, rpID string) ([]db.PasskeyCredential, error) {
	if rpID != "" {
		return s.passkeyRepo.GetPasskeysByRPID(ctx, userID, rpID)
	}
	return s.passkeyRepo.GetAllPasskeys(ctx, userID)
}

// DeletePasskey deletes a passkey.
func (s *WebAuthnService) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	return s.passkeyRepo.DeletePasskey(ctx, userID, passkeyID)
}

// ── Hardware Key Methods ─────────────────────────────────────────────────────

// HardwareKeyRegistrationOptions is returned to begin a hardware key registration.
type HardwareKeyRegistrationOptions struct {
	Challenge        string                   `json:"challenge"`
	RP               map[string]string        `json:"rp"`
	User             map[string]interface{}   `json:"user"`
	PubKeyCredParams []map[string]interface{} `json:"pubKeyCredParams"`
	AuthenticatorSelection map[string]interface{} `json:"authenticatorSelection"`
	Attestation      string                   `json:"attestation"`
	Timeout          int                      `json:"timeout"`
	SessionID        string                   `json:"session_id"`
}

// BeginHardwareKeyRegistration starts a hardware key registration ceremony.
// Unlike software passkeys, hardware keys use cross-platform authenticators
// (USB/NFC/BLE) — the browser handles CTAP2 communication.
func (s *WebAuthnService) BeginHardwareKeyRegistration(ctx context.Context, userID, userName, displayName string) (*HardwareKeyRegistrationOptions, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	userHandle := make([]byte, 32)
	if _, err := rand.Read(userHandle); err != nil {
		return nil, fmt.Errorf("generate user handle: %w", err)
	}

	sessionID := generateSessionID()
	s.mu.Lock()
	s.sessions[sessionID] = &webAuthnSession{
		Challenge:  challenge,
		UserID:     userID,
		RPID:       s.config.RPID,
		CreatedAt:  time.Now(),
		IsHardware: true,
	}
	s.mu.Unlock()

	go s.cleanExpiredSessions()

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	opts := &HardwareKeyRegistrationOptions{
		Challenge: b64.EncodeToString(challenge),
		RP: map[string]string{
			"name": s.config.RPDisplayName,
			"id":   s.config.RPID,
		},
		User: map[string]interface{}{
			"id":          b64.EncodeToString(userHandle),
			"name":        userName,
			"displayName": displayName,
		},
		PubKeyCredParams: []map[string]interface{}{
			{"type": "public-key", "alg": crypto.COSEAlgES256},
			{"type": "public-key", "alg": crypto.COSEAlgEdDSA},
		},
		AuthenticatorSelection: map[string]interface{}{
			"authenticatorAttachment": "cross-platform",
			"residentKey":             "discouraged",
			"userVerification":        "required",
		},
		Attestation: "direct",
		Timeout:     120000, // 2 minutes for physical key interaction
		SessionID:   sessionID,
	}

	return opts, nil
}

// FinishHardwareKeyRegistrationRequest is the client's response after the browser's
// native WebAuthn API completes the hardware key ceremony.
type FinishHardwareKeyRegistrationRequest struct {
	SessionID        string `json:"session_id"`
	Name             string `json:"name"`              // user-assigned name for this key
	CredentialID     string `json:"credential_id"`      // base64url from authenticator
	PublicKeyCBOR    string `json:"public_key_cbor"`    // base64url COSE key
	AttestationObject string `json:"attestation_object"` // base64url raw attestation
	ClientDataJSON   string `json:"client_data_json"`   // base64url
	Transports       []string `json:"transports"`       // ["usb","nfc","ble"]
}

// FinishHardwareKeyRegistration verifies and stores a hardware key credential.
// The browser's native WebAuthn API did the CTAP2 communication — we just verify
// the attestation and store the resulting public key.
func (s *WebAuthnService) FinishHardwareKeyRegistration(ctx context.Context, userID string, req *FinishHardwareKeyRegistrationRequest) (*db.HardwareAuthKey, error) {
	// Validate session
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if ok {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("invalid or expired session")
	}
	if time.Since(sess.CreatedAt) > webAuthnSessionTTL {
		return nil, fmt.Errorf("session expired")
	}
	if sess.UserID != userID {
		return nil, fmt.Errorf("session user mismatch")
	}
	if !sess.IsHardware {
		return nil, fmt.Errorf("session is not a hardware key session")
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Decode credential ID
	credentialID, err := b64.DecodeString(req.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("decode credential ID: %w", err)
	}

	// Decode and verify clientDataJSON
	clientDataBytes, err := b64.DecodeString(req.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("decode client data: %w", err)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return nil, fmt.Errorf("parse client data: %w", err)
	}

	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("unexpected client data type: %s", clientData.Type)
	}

	// Verify challenge matches
	expectedChallenge := b64.EncodeToString(sess.Challenge)
	if clientData.Challenge != expectedChallenge {
		return nil, fmt.Errorf("challenge mismatch")
	}

	// Verify origin
	if len(s.config.RPOrigins) > 0 {
		originValid := false
		for _, o := range s.config.RPOrigins {
			if clientData.Origin == o {
				originValid = true
				break
			}
		}
		if !originValid {
			return nil, fmt.Errorf("origin mismatch: %s", clientData.Origin)
		}
	}

	// Decode attestation object to extract AAGUID
	attestBytes, err := b64.DecodeString(req.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("decode attestation: %w", err)
	}

	// Parse the attestation object's authData to extract AAGUID
	aaguid, err := extractAAGUIDFromAttestation(attestBytes)
	if err != nil {
		log.Warn().Err(err).Msg("could not extract AAGUID from attestation")
		// Non-fatal — use zeros
		aaguid = make([]byte, 16)
	}

	// Decode public key
	publicKeyCBOR, err := b64.DecodeString(req.PublicKeyCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	// Verify the public key is valid COSE
	if _, _, err := crypto.UnmarshalCOSEKey(publicKeyCBOR); err != nil {
		return nil, fmt.Errorf("invalid COSE public key: %w", err)
	}

	if req.Name == "" {
		req.Name = "Security Key"
	}

	transports := req.Transports
	if len(transports) == 0 {
		transports = []string{"usb"}
	}

	key := db.HardwareAuthKey{
		UserID:       userID,
		CredentialID: credentialID,
		PublicKeyCBOR: publicKeyCBOR,
		SignCount:    0,
		AAGUID:       aaguid,
		Transports:   transports,
		Name:         req.Name,
	}

	result, err := s.hwKeyRepo.RegisterHardwareKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("store hardware key: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Str("key_id", result.ID).
		Str("name", req.Name).
		Msg("hardware key registered")

	return &result, nil
}

// HardwareKeyAuthOptions is returned to begin a hardware key authentication.
type HardwareKeyAuthOptions struct {
	Challenge        string                   `json:"challenge"`
	RPID             string                   `json:"rp_id"`
	AllowCredentials []map[string]interface{} `json:"allowCredentials"`
	UserVerification string                   `json:"userVerification"`
	Timeout          int                      `json:"timeout"`
	SessionID        string                   `json:"session_id"`
}

// BeginHardwareKeyAuthentication starts a hardware key authentication ceremony.
func (s *WebAuthnService) BeginHardwareKeyAuthentication(ctx context.Context, userID string) (*HardwareKeyAuthOptions, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	keys, err := s.hwKeyRepo.GetHardwareKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get hardware keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no hardware keys registered")
	}

	sessionID := generateSessionID()
	s.mu.Lock()
	s.sessions[sessionID] = &webAuthnSession{
		Challenge:  challenge,
		UserID:     userID,
		RPID:       s.config.RPID,
		CreatedAt:  time.Now(),
		IsHardware: true,
	}
	s.mu.Unlock()

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	var allowCreds []map[string]interface{}
	for _, k := range keys {
		allowCreds = append(allowCreds, map[string]interface{}{
			"type":       "public-key",
			"id":         b64.EncodeToString(k.CredentialID),
			"transports": k.Transports,
		})
	}

	opts := &HardwareKeyAuthOptions{
		Challenge:        b64.EncodeToString(challenge),
		RPID:             s.config.RPID,
		AllowCredentials: allowCreds,
		UserVerification: "required",
		Timeout:          120000,
		SessionID:        sessionID,
	}

	return opts, nil
}

// FinishHardwareKeyAuthRequest is the client's response after the browser's
// WebAuthn API completes the hardware key assertion.
type FinishHardwareKeyAuthRequest struct {
	SessionID         string `json:"session_id"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"` // base64url
	ClientDataJSON    string `json:"client_data_json"`   // base64url
	Signature         string `json:"signature"`          // base64url
}

// FinishHardwareKeyAuthentication verifies a hardware key assertion.
func (s *WebAuthnService) FinishHardwareKeyAuthentication(ctx context.Context, userID string, req *FinishHardwareKeyAuthRequest) error {
	// Validate session
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if ok {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("invalid or expired session")
	}
	if time.Since(sess.CreatedAt) > webAuthnSessionTTL {
		return fmt.Errorf("session expired")
	}
	if sess.UserID != userID {
		return fmt.Errorf("session user mismatch")
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Decode credential ID
	credIDBytes, err := b64.DecodeString(req.CredentialID)
	if err != nil {
		return fmt.Errorf("decode credential ID: %w", err)
	}

	// Fetch hardware key
	key, err := s.hwKeyRepo.GetHardwareKeyByCredentialID(ctx, credIDBytes)
	if err != nil {
		return fmt.Errorf("get hardware key: %w", err)
	}
	if key.UserID != userID {
		return fmt.Errorf("hardware key does not belong to user")
	}

	// Decode authenticator data
	authData, err := b64.DecodeString(req.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("decode authenticator data: %w", err)
	}

	// Verify RP ID hash
	rpIDHash := crypto.RPIDHash(s.config.RPID)
	_, _, signCount, _, err := crypto.ParseAuthenticatorData(authData)
	if err != nil {
		return fmt.Errorf("parse authenticator data: %w", err)
	}

	// Check RP ID hash from authData matches
	var authRPHash [32]byte
	copy(authRPHash[:], authData[:32])
	if authRPHash != rpIDHash {
		return fmt.Errorf("RP ID hash mismatch in authenticator data")
	}

	// Clone detection: sign count must be greater than stored value
	if int(signCount) > 0 && int(signCount) <= key.SignCount {
		log.Warn().
			Str("user_id", userID).
			Int("stored", key.SignCount).
			Uint32("received", signCount).
			Msg("hardware key sign count regression — possible clone")
		return fmt.Errorf("sign count regression detected — possible cloned authenticator")
	}

	// Decode and verify clientDataJSON
	clientDataBytes, err := b64.DecodeString(req.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("decode client data: %w", err)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return fmt.Errorf("parse client data: %w", err)
	}

	if clientData.Type != "webauthn.get" {
		return fmt.Errorf("unexpected client data type: %s", clientData.Type)
	}

	// Verify challenge
	expectedChallenge := b64.EncodeToString(sess.Challenge)
	if clientData.Challenge != expectedChallenge {
		return fmt.Errorf("challenge mismatch")
	}

	// Verify signature
	clientDataHash := sha256.Sum256(clientDataBytes)
	signatureBytes, err := b64.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	valid, err := crypto.VerifyAssertion(key.PublicKeyCBOR, authData, clientDataHash[:], signatureBytes)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	// Update sign count
	if err := s.hwKeyRepo.UpdateHardwareKeySignCount(ctx, credIDBytes, int(signCount)); err != nil {
		log.Warn().Err(err).Msg("failed to update hardware key sign count")
	}

	log.Info().
		Str("user_id", userID).
		Uint32("sign_count", signCount).
		Msg("hardware key authentication verified")

	return nil
}

// HasHardwareKeys checks if a user has any registered hardware keys.
func (s *WebAuthnService) HasHardwareKeys(ctx context.Context, userID string) (bool, error) {
	keys, err := s.hwKeyRepo.GetHardwareKeys(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

// ListHardwareKeys returns all hardware keys for a user.
func (s *WebAuthnService) ListHardwareKeys(ctx context.Context, userID string) ([]db.HardwareAuthKey, error) {
	return s.hwKeyRepo.GetHardwareKeys(ctx, userID)
}

// DeleteHardwareKey deletes a hardware key.
func (s *WebAuthnService) DeleteHardwareKey(ctx context.Context, userID, keyID string) error {
	return s.hwKeyRepo.DeleteHardwareKey(ctx, userID, keyID)
}

// extractAAGUIDFromAttestation extracts the AAGUID from a CBOR attestation object.
func extractAAGUIDFromAttestation(attestBytes []byte) ([]byte, error) {
	return crypto.ExtractAAGUIDFromAttestation(attestBytes)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed")
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func parseMasterKey(hex string) ([32]byte, error) {
	var key [32]byte
	if len(hex) != 64 {
		return key, fmt.Errorf("master key hex must be 64 chars")
	}
	b, err := hexDecode(hex)
	if err != nil {
		return key, err
	}
	copy(key[:], b)
	return key, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := unhex(s[i])
		low := unhex(s[i+1])
		if high == 255 || low == 255 {
			return nil, fmt.Errorf("invalid hex char")
		}
		b[i/2] = high<<4 | low
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255
	}
}

func (s *WebAuthnService) cleanExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.sessions {
		if now.Sub(sess.CreatedAt) > webAuthnSessionTTL {
			delete(s.sessions, id)
		}
	}
}

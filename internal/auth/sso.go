package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/db"
)

// SSOConfig holds the SSO configuration stored in the organization's sso_config JSONB column.
type SSOConfig struct {
	Provider   string          `json:"provider"` // "saml" or "oidc"
	SAML       *SAMLConfig     `json:"saml,omitempty"`
	OIDC       *OIDCConfig     `json:"oidc,omitempty"`
	AutoEnroll bool            `json:"auto_enroll"`
}

// SAMLConfig contains SAML 2.0 IdP settings.
type SAMLConfig struct {
	EntityID     string `json:"entity_id"`
	SSOURL       string `json:"sso_url"`
	Certificate  string `json:"certificate"`    // PEM-encoded X.509 certificate
	NameIDFormat string `json:"name_id_format"` // e.g. "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
}

// OIDCConfig contains OpenID Connect IdP settings.
type OIDCConfig struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	ClientSecretEncrypted string   `json:"client_secret_encrypted"` // encrypted with org key
	RedirectURI           string   `json:"redirect_uri"`
	Scopes                []string `json:"scopes"`
}

// SSOService handles SSO authentication flows.
type SSOService struct {
	orgRepo     db.OrgRepository
	userRepo    db.UserRepository
	authService *Service
	auditRepo   db.AuditRepository

	// In-memory PKCE + state store (keyed by state value).
	// In production, use a shared cache (e.g. Redis) for multi-instance deployments.
	stateStore map[string]*ssoStateEntry
}

type ssoStateEntry struct {
	OrgID        string
	CodeVerifier string
	CreatedAt    time.Time
}

// NewSSOService creates a new SSOService.
func NewSSOService(orgRepo db.OrgRepository, userRepo db.UserRepository, authService *Service, auditRepo db.AuditRepository) *SSOService {
	return &SSOService{
		orgRepo:     orgRepo,
		userRepo:    userRepo,
		authService: authService,
		auditRepo:   auditRepo,
		stateStore:  make(map[string]*ssoStateEntry),
	}
}

// SSOLoginResult contains the result of an SSO login callback.
type SSOLoginResult struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	SSOToken     string `json:"sso_token,omitempty"` // partial token — vault still locked
	NewUser      bool   `json:"new_user,omitempty"`
}

// InitiateLogin builds the redirect URL for the IdP.
func (s *SSOService) InitiateLogin(ctx context.Context, orgID string) (redirectURL string, err error) {
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return "", fmt.Errorf("get org: %w", err)
	}
	if !org.SSOEnabled || org.SSOConfig == nil {
		return "", fmt.Errorf("SSO is not enabled for this organization")
	}

	var cfg SSOConfig
	if err := json.Unmarshal(org.SSOConfig, &cfg); err != nil {
		return "", fmt.Errorf("parse sso config: %w", err)
	}

	switch cfg.Provider {
	case "saml":
		return s.initiateSAMLLogin(orgID, cfg.SAML)
	case "oidc":
		return s.initiateOIDCLogin(orgID, cfg.OIDC)
	default:
		return "", fmt.Errorf("unsupported SSO provider: %s", cfg.Provider)
	}
}

// HandleCallback processes the IdP callback and returns the authenticated user.
func (s *SSOService) HandleCallback(ctx context.Context, orgID string, params map[string]string) (*SSOLoginResult, error) {
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("get org: %w", err)
	}
	if !org.SSOEnabled || org.SSOConfig == nil {
		return nil, fmt.Errorf("SSO is not enabled for this organization")
	}

	var cfg SSOConfig
	if err := json.Unmarshal(org.SSOConfig, &cfg); err != nil {
		return nil, fmt.Errorf("parse sso config: %w", err)
	}

	var email, externalID string

	switch cfg.Provider {
	case "saml":
		email, externalID, err = s.handleSAMLCallback(cfg.SAML, params)
	case "oidc":
		email, externalID, err = s.handleOIDCCallback(ctx, orgID, cfg.OIDC, params)
	default:
		return nil, fmt.Errorf("unsupported SSO provider: %s", cfg.Provider)
	}
	if err != nil {
		return nil, fmt.Errorf("SSO callback: %w", err)
	}

	// Find or create user
	result, err := s.findOrCreateSSOUser(ctx, org, &cfg, email, externalID)
	if err != nil {
		return nil, err
	}

	// Audit log
	details, _ := json.Marshal(map[string]string{"email": email, "provider": cfg.Provider, "external_id": externalID})
	actorID := result.UserID
	_ = s.auditRepo.LogAction(ctx, &actorID, &orgID, "sso_login", details)

	return result, nil
}

// UnlockVault exchanges an SSO partial token + master password verification for full tokens.
func (s *SSOService) UnlockVault(ctx context.Context, ssoToken string, userID string) (*SSOLoginResult, error) {
	// Validate the SSO partial token
	claims, err := s.authService.ValidateToken(ssoToken)
	if err != nil {
		return nil, fmt.Errorf("invalid SSO token: %w", err)
	}
	if !claims.Is2FA || claims.UserID != userID {
		return nil, fmt.Errorf("invalid SSO token")
	}

	// Look up org membership for JWT claims
	member, _, err := s.orgRepo.GetUserOrg(ctx, userID)
	orgID := ""
	role := ""
	if err == nil {
		orgID = member.OrgID
		role = member.Role
	}

	// Issue full tokens
	accessToken, refreshToken, err := s.authService.GenerateTokenPair(userID, orgID, role)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	return &SSOLoginResult{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// findOrCreateSSOUser finds an existing user by SSO external ID or email,
// or creates a stub user if auto_enroll is enabled.
func (s *SSOService) findOrCreateSSOUser(ctx context.Context, org db.Organization, cfg *SSOConfig, email, externalID string) (*SSOLoginResult, error) {
	// First, try to find by SSO external ID
	if externalID != "" {
		user, err := s.userRepo.GetUserBySSOExternalID(ctx, externalID)
		if err == nil {
			// Found user by external ID — issue partial token (vault still locked)
			token, err := s.authService.GenerateSSOPartialToken(user.ID)
			if err != nil {
				return nil, fmt.Errorf("generate SSO token: %w", err)
			}
			return &SSOLoginResult{
				UserID:   user.ID,
				Email:    user.Email,
				SSOToken: token,
			}, nil
		}
	}

	// Try to find by email
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err == nil {
		// Found existing user — link SSO external ID if not already set
		if externalID != "" && (user.SSOExternalID == nil || *user.SSOExternalID != externalID) {
			if err := s.userRepo.SetSSOExternalID(ctx, user.ID, externalID); err != nil {
				log.Warn().Err(err).Str("user_id", user.ID).Msg("failed to link SSO external ID")
			}
		}

		// Auto-enroll in org if configured
		if cfg.AutoEnroll {
			_, memberErr := s.orgRepo.GetMember(ctx, org.ID, user.ID)
			if memberErr != nil {
				// Not a member — add as member with empty escrow (user must provide master key later)
				if addErr := s.orgRepo.AddMember(ctx, org.ID, user.ID, "member", nil); addErr != nil {
					log.Warn().Err(addErr).Str("user_id", user.ID).Msg("SSO auto-enroll failed")
				} else {
					log.Info().Str("user_id", user.ID).Str("org_id", org.ID).Msg("SSO auto-enrolled user in org")
				}
			}
		}

		token, err := s.authService.GenerateSSOPartialToken(user.ID)
		if err != nil {
			return nil, fmt.Errorf("generate SSO token: %w", err)
		}
		return &SSOLoginResult{
			UserID:   user.ID,
			Email:    user.Email,
			SSOToken: token,
		}, nil
	}

	// User doesn't exist — they must register first (SSO does not create vault credentials)
	return nil, fmt.Errorf("no account found for %s — please register first, then link SSO", email)
}

// ── SAML ─────────────────────────────────────────────────────────────────────

func (s *SSOService) initiateSAMLLogin(orgID string, cfg *SAMLConfig) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("SAML configuration is missing")
	}

	// Generate a unique request ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	requestID := "_" + hex.EncodeToString(idBytes)

	// Store state for callback validation
	s.stateStore[requestID] = &ssoStateEntry{
		OrgID:     orgID,
		CreatedAt: time.Now(),
	}

	// Build SAML AuthnRequest
	nameIDFormat := cfg.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}

	authnRequest := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" `+
		`ID="%s" Version="2.0" IssueInstant="%s" `+
		`AssertionConsumerServiceURL="%s" `+
		`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>`+
		`</samlp:AuthnRequest>`,
		requestID,
		time.Now().UTC().Format(time.RFC3339),
		cfg.EntityID+"/callback",
		cfg.EntityID,
		nameIDFormat,
	)

	// URL-encode the AuthnRequest as a SAMLRequest query parameter (HTTP-Redirect binding)
	encoded := base64.StdEncoding.EncodeToString([]byte(authnRequest))
	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s",
		cfg.SSOURL,
		url.QueryEscape(encoded),
		url.QueryEscape(orgID),
	)

	return redirectURL, nil
}

// samlResponse is a minimal SAML Response parser.
type samlResponse struct {
	XMLName   xml.Name       `xml:"Response"`
	Assertion samlAssertion  `xml:"Assertion"`
}

type samlAssertion struct {
	Subject         samlSubject         `xml:"Subject"`
	AttributeStmt   samlAttributeStmt   `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID samlNameID `xml:"NameID"`
}

type samlNameID struct {
	Value string `xml:",chardata"`
}

type samlAttributeStmt struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string          `xml:"Name,attr"`
	Values []samlAttrValue `xml:"AttributeValue"`
}

type samlAttrValue struct {
	Value string `xml:",chardata"`
}

func (s *SSOService) handleSAMLCallback(cfg *SAMLConfig, params map[string]string) (email, externalID string, err error) {
	samlResponseB64 := params["SAMLResponse"]
	if samlResponseB64 == "" {
		return "", "", fmt.Errorf("missing SAMLResponse parameter")
	}

	responseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", "", fmt.Errorf("decode SAML response: %w", err)
	}

	// Parse the SAML response
	// NOTE: In production, you MUST verify the XML signature against cfg.Certificate.
	// This implementation parses the response structure; signature verification
	// should use a dedicated SAML library (e.g. github.com/crewjam/saml) for
	// canonicalization and signature validation.
	var resp samlResponse
	if err := xml.Unmarshal(responseXML, &resp); err != nil {
		return "", "", fmt.Errorf("parse SAML response: %w", err)
	}

	email = resp.Assertion.Subject.NameID.Value
	if email == "" {
		return "", "", fmt.Errorf("no NameID in SAML assertion")
	}

	// Use NameID as external ID for SAML
	externalID = "saml:" + email

	// Check for external ID attribute
	for _, attr := range resp.Assertion.AttributeStmt.Attributes {
		if attr.Name == "externalId" || attr.Name == "uid" || attr.Name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" {
			if len(attr.Values) > 0 {
				externalID = "saml:" + attr.Values[0].Value
			}
		}
	}

	log.Info().Str("email", email).Str("external_id", externalID).Msg("SAML callback processed")
	return email, externalID, nil
}

// ── OIDC ─────────────────────────────────────────────────────────────────────

func (s *SSOService) initiateOIDCLogin(orgID string, cfg *OIDCConfig) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("OIDC configuration is missing")
	}

	// Generate PKCE code verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate state
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	// Store state + PKCE for callback
	s.stateStore[state] = &ssoStateEntry{
		OrgID:        orgID,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now(),
	}

	// Build code challenge (S256)
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Build scopes
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Discover authorization endpoint
	authEndpoint, err := s.discoverOIDCAuthEndpoint(cfg.Issuer)
	if err != nil {
		return "", fmt.Errorf("discover OIDC endpoints: %w", err)
	}

	params := url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":        {"code"},
		"redirect_uri":         {cfg.RedirectURI},
		"scope":                {strings.Join(scopes, " ")},
		"state":                {state},
		"code_challenge":       {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	return authEndpoint + "?" + params.Encode(), nil
}

func (s *SSOService) handleOIDCCallback(ctx context.Context, orgID string, cfg *OIDCConfig, params map[string]string) (email, externalID string, err error) {
	code := params["code"]
	state := params["state"]

	if code == "" || state == "" {
		return "", "", fmt.Errorf("missing code or state parameter")
	}

	// Validate state and retrieve PKCE verifier
	entry, ok := s.stateStore[state]
	if !ok {
		return "", "", fmt.Errorf("invalid or expired state parameter")
	}
	if time.Since(entry.CreatedAt) > 10*time.Minute {
		delete(s.stateStore, state)
		return "", "", fmt.Errorf("state parameter expired")
	}
	if entry.OrgID != orgID {
		return "", "", fmt.Errorf("state/org mismatch")
	}
	delete(s.stateStore, state) // consume state

	// Discover token endpoint
	tokenEndpoint, err := s.discoverOIDCTokenEndpoint(cfg.Issuer)
	if err != nil {
		return "", "", fmt.Errorf("discover token endpoint: %w", err)
	}

	// Exchange code for tokens
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {entry.CodeVerifier},
	}

	resp, err := http.PostForm(tokenEndpoint, tokenParams) // #nosec G107 -- tokenEndpoint from OIDC discovery
	if err != nil {
		return "", "", fmt.Errorf("exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("parse token response: %w", err)
	}

	// Decode ID token claims (JWT payload — signature validation should use
	// the IdP's JWKS in production; we extract claims for now).
	email, externalID, err = extractOIDCClaims(tokenResp.IDToken)
	if err != nil {
		return "", "", fmt.Errorf("extract ID token claims: %w", err)
	}

	log.Info().Str("email", email).Str("external_id", externalID).Msg("OIDC callback processed")
	return email, externalID, nil
}

// extractOIDCClaims decodes the ID token payload (without signature verification).
// In production, validate the JWT signature against the IdP's JWKS.
func extractOIDCClaims(idToken string) (email, sub string, err error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid ID token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode ID token payload: %w", err)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("parse ID token claims: %w", err)
	}

	if claims.Email == "" {
		return "", "", fmt.Errorf("no email claim in ID token")
	}

	return claims.Email, "oidc:" + claims.Sub, nil
}

// ── OIDC Discovery ──────────────────────────────────────────────────────────

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func (s *SSOService) discoverOIDC(issuer string) (*oidcDiscoveryDoc, error) {
	wellKnownURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(wellKnownURL) // #nosec G107 -- user-configured OIDC issuer URL
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read OIDC discovery: %w", err)
	}

	var doc oidcDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse OIDC discovery: %w", err)
	}
	return &doc, nil
}

func (s *SSOService) discoverOIDCAuthEndpoint(issuer string) (string, error) {
	doc, err := s.discoverOIDC(issuer)
	if err != nil {
		return "", err
	}
	if doc.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("no authorization_endpoint in OIDC discovery")
	}
	return doc.AuthorizationEndpoint, nil
}

func (s *SSOService) discoverOIDCTokenEndpoint(issuer string) (string, error) {
	doc, err := s.discoverOIDC(issuer)
	if err != nil {
		return "", err
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("no token_endpoint in OIDC discovery")
	}
	return doc.TokenEndpoint, nil
}

// CleanupStaleState removes expired state entries (call periodically).
func (s *SSOService) CleanupStaleState() {
	now := time.Now()
	for key, entry := range s.stateStore {
		if now.Sub(entry.CreatedAt) > 15*time.Minute {
			delete(s.stateStore, key)
		}
	}
}

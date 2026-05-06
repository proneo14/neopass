package integration_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/api"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/db"
)

// setupEmergencyAccessTest returns mock repos and two registered users (grantor and grantee).
func setupEmergencyAccessTest(t *testing.T) (
	eaRepo *MockEmergencyAccessRepo,
	userRepo *MockUserRepo,
	auditRepo *MockAuditRepo,
	grantorID string,
	granteeID string,
) {
	t.Helper()

	eaRepo = NewMockEmergencyAccessRepo()
	userRepo = NewMockUserRepo()
	auditRepo = NewMockAuditRepo()

	grantor, err := registerTestUser(userRepo, "grantor@example.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	if err != nil {
		t.Fatalf("register grantor: %v", err)
	}

	grantee, err := registerTestUser(userRepo, "grantee@example.com", hex.EncodeToString([]byte("authhashmembertestuser12")))
	if err != nil {
		t.Fatalf("register grantee: %v", err)
	}

	return eaRepo, userRepo, auditRepo, grantor.ID, grantee.ID
}

func TestEmergencyAccess_InviteAndAccept(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	// Create invitation
	ea, err := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "invited",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	if err != nil {
		t.Fatalf("CreateEmergencyAccess failed: %v", err)
	}

	if ea.ID == "" {
		t.Error("expected non-empty EA id")
	}
	if ea.Status != "invited" {
		t.Errorf("expected status=invited, got %s", ea.Status)
	}

	// Set grantee ID (simulating acceptance)
	err = eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	if err != nil {
		t.Fatalf("SetGranteeID failed: %v", err)
	}

	// Update status to accepted
	err = eaRepo.UpdateStatus(context.Background(), ea.ID, "accepted")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Verify
	updated, err := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if err != nil {
		t.Fatalf("GetEmergencyAccess failed: %v", err)
	}
	if updated.Status != "accepted" {
		t.Errorf("expected status=accepted, got %s", updated.Status)
	}
	if updated.GranteeID == nil || *updated.GranteeID != granteeID {
		t.Errorf("expected grantee_id=%s, got %v", granteeID, updated.GranteeID)
	}
}

func TestEmergencyAccess_InitiateRecovery(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	eaRepo.UpdateStatus(context.Background(), ea.ID, "accepted")

	// Initiate recovery
	err := eaRepo.InitiateRecovery(context.Background(), ea.ID)
	if err != nil {
		t.Fatalf("InitiateRecovery failed: %v", err)
	}

	updated, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if updated.Status != "recovery_initiated" {
		t.Errorf("expected status=recovery_initiated, got %s", updated.Status)
	}
	if updated.RecoveryInitiatedAt == nil {
		t.Error("expected recovery_initiated_at to be set")
	}
}

func TestEmergencyAccess_ApproveRecovery(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	eaRepo.InitiateRecovery(context.Background(), ea.ID)

	// Grantor approves
	err := eaRepo.UpdateStatus(context.Background(), ea.ID, "recovery_approved")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}

	updated, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if updated.Status != "recovery_approved" {
		t.Errorf("expected status=recovery_approved, got %s", updated.Status)
	}

	// Set encrypted key (simulating granting vault access)
	err = eaRepo.SetEncryptedKey(context.Background(), ea.ID, []byte("enckey"), []byte("nonce"))
	if err != nil {
		t.Fatalf("SetEncryptedKey failed: %v", err)
	}

	withKey, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if !bytes.Equal(withKey.EncryptedKey, []byte("enckey")) {
		t.Error("expected encrypted key to be set")
	}
}

func TestEmergencyAccess_RejectRecovery(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	eaRepo.InitiateRecovery(context.Background(), ea.ID)

	// Grantor rejects
	err := eaRepo.UpdateStatus(context.Background(), ea.ID, "accepted")
	if err != nil {
		t.Fatalf("reject (reset) failed: %v", err)
	}

	updated, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if updated.Status != "accepted" {
		t.Errorf("expected status=accepted after reject, got %s", updated.Status)
	}

	// Vault should NOT be accessible (no encrypted key set)
	if len(updated.EncryptedKey) > 0 {
		t.Error("rejected EA should not have encrypted key")
	}
}

func TestEmergencyAccess_AutoApprove(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "view",
		WaitTimeDays: 1, // 1 day wait
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	eaRepo.InitiateRecovery(context.Background(), ea.ID)

	// Simulate time passing: set recovery_initiated_at to 2 days ago
	eaRepo.mu.Lock()
	rec := eaRepo.records[ea.ID]
	past := time.Now().Add(-48 * time.Hour)
	rec.RecoveryInitiatedAt = &past
	eaRepo.records[ea.ID] = rec
	eaRepo.mu.Unlock()

	// Check auto-approve eligible
	eligible, err := eaRepo.GetAutoApproveEligible(context.Background())
	if err != nil {
		t.Fatalf("GetAutoApproveEligible failed: %v", err)
	}
	if len(eligible) != 1 {
		t.Fatalf("expected 1 eligible, got %d", len(eligible))
	}

	// Run auto-approve
	approved, err := eaRepo.AutoApproveExpired(context.Background())
	if err != nil {
		t.Fatalf("AutoApproveExpired failed: %v", err)
	}
	if approved != 1 {
		t.Errorf("expected 1 approved, got %d", approved)
	}

	updated, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if updated.Status != "recovery_approved" {
		t.Errorf("expected status=recovery_approved after auto-approve, got %s", updated.Status)
	}
}

func TestEmergencyAccess_Takeover(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "takeover",
		WaitTimeDays: 1,
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)
	eaRepo.InitiateRecovery(context.Background(), ea.ID)
	eaRepo.UpdateStatus(context.Background(), ea.ID, "recovery_approved")

	updated, _ := eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if updated.AccessType != "takeover" {
		t.Errorf("expected access_type=takeover, got %s", updated.AccessType)
	}
	if updated.Status != "recovery_approved" {
		t.Errorf("expected status=recovery_approved, got %s", updated.Status)
	}
}

func TestEmergencyAccess_Delete(t *testing.T) {
	eaRepo, _, _, grantorID, _ := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "invited",
		AccessType:   "view",
		WaitTimeDays: 3,
	})

	err := eaRepo.DeleteEmergencyAccess(context.Background(), ea.ID)
	if err != nil {
		t.Fatalf("DeleteEmergencyAccess failed: %v", err)
	}

	_, err = eaRepo.GetEmergencyAccess(context.Background(), ea.ID)
	if err == nil {
		t.Error("expected error getting deleted EA")
	}
}

func TestEmergencyAccess_ListGranted(t *testing.T) {
	eaRepo, _, _, grantorID, _ := setupEmergencyAccessTest(t)

	eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee1@example.com",
		Status:       "invited",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee2@example.com",
		Status:       "invited",
		AccessType:   "view",
		WaitTimeDays: 5,
	})

	granted, err := eaRepo.ListGrantedAccess(context.Background(), grantorID)
	if err != nil {
		t.Fatalf("ListGrantedAccess failed: %v", err)
	}
	if len(granted) != 2 {
		t.Errorf("expected 2 granted, got %d", len(granted))
	}
}

func TestEmergencyAccess_ListTrusted(t *testing.T) {
	eaRepo, _, _, grantorID, granteeID := setupEmergencyAccessTest(t)

	ea, _ := eaRepo.CreateEmergencyAccess(context.Background(), db.EmergencyAccess{
		GrantorID:    grantorID,
		GranteeEmail: "grantee@example.com",
		Status:       "accepted",
		AccessType:   "view",
		WaitTimeDays: 3,
	})
	eaRepo.SetGranteeID(context.Background(), ea.ID, granteeID)

	trusted, err := eaRepo.ListTrustedBy(context.Background(), granteeID)
	if err != nil {
		t.Fatalf("ListTrustedBy failed: %v", err)
	}
	if len(trusted) != 1 {
		t.Errorf("expected 1 trusted, got %d", len(trusted))
	}
}

// ---------------------------------------------------------------------------
// Emergency Access Handler HTTP Tests
// ---------------------------------------------------------------------------

func setupEmergencyRouter(t *testing.T) (chi.Router, string, string, string, string, *MockEmergencyAccessRepo) {
	t.Helper()

	userRepo := NewMockUserRepo()
	vaultRepo := NewMockVaultRepo()
	eaRepo := NewMockEmergencyAccessRepo()
	orgRepo := NewMockOrgRepo()
	collRepo := NewMockCollectionRepo()
	auditRepo := NewMockAuditRepo()

	authService, err := auth.NewService(userRepo, nil, nil, auth.ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}, vaultRepo)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	eaHandler := api.NewEmergencyAccessHandler(eaRepo, userRepo, vaultRepo, auditRepo, orgRepo, collRepo)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(authService, userRepo))
		r.Post("/emergency-access/invite", eaHandler.Invite)
		r.Get("/emergency-access/granted", eaHandler.ListGranted)
		r.Get("/emergency-access/trusted", eaHandler.ListTrusted)
		r.Post("/emergency-access/{id}/accept", eaHandler.Accept)
		r.Post("/emergency-access/{id}/initiate", eaHandler.Initiate)
		r.Post("/emergency-access/{id}/approve", eaHandler.Approve)
		r.Post("/emergency-access/{id}/reject", eaHandler.Reject)
		r.Delete("/emergency-access/{id}", eaHandler.Delete)
	})

	authHandler := api.NewAuthHandler(authService)
	regRouter := chi.NewRouter()
	regRouter.Post("/auth/register", authHandler.Register)

	// Register grantor
	grantorAuth := createTestAuthHash()
	regJSON, _ := json.Marshal(map[string]interface{}{
		"email":                  "grantor-h@example.com",
		"auth_hash":             grantorAuth,
		"salt":                  hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":            hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	})
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	regRouter.ServeHTTP(regW, regReq)
	var grantorResp auth.RegisterResponse
	json.NewDecoder(regW.Body).Decode(&grantorResp)

	// Register grantee
	regJSON, _ = json.Marshal(map[string]interface{}{
		"email":                  "grantee-h@example.com",
		"auth_hash":             grantorAuth,
		"salt":                  hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":            hex.EncodeToString([]byte("fake-public-key-2")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key-2")),
	})
	regReq = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	regReq.Header.Set("Content-Type", "application/json")
	regW = httptest.NewRecorder()
	regRouter.ServeHTTP(regW, regReq)
	var granteeResp auth.RegisterResponse
	json.NewDecoder(regW.Body).Decode(&granteeResp)

	return r, grantorResp.AccessToken, grantorResp.UserID, granteeResp.AccessToken, granteeResp.UserID, eaRepo
}

func TestEmergencyAccessHandler_Invite(t *testing.T) {
	router, grantorToken, _, _, _, _ := setupEmergencyRouter(t)

	body := map[string]interface{}{
		"email":          "grantee-h@example.com",
		"access_type":    "view",
		"wait_time_days": 3,
	}

	w := makeAuthRequest(router, http.MethodPost, "/emergency-access/invite", grantorToken, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("invite expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("expected id in invite response")
	}
}

func TestEmergencyAccessHandler_ListGranted(t *testing.T) {
	router, grantorToken, _, _, _, _ := setupEmergencyRouter(t)

	// Create an invite first
	makeAuthRequest(router, http.MethodPost, "/emergency-access/invite", grantorToken, map[string]interface{}{
		"email":          "grantee-h@example.com",
		"access_type":    "view",
		"wait_time_days": 3,
	})

	// List granted
	w := makeAuthRequest(router, http.MethodGet, "/emergency-access/granted", grantorToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list granted expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var granted []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&granted)
	if len(granted) != 1 {
		t.Errorf("expected 1 granted EA, got %d", len(granted))
	}
}

func TestEmergencyAccessHandler_Delete(t *testing.T) {
	router, grantorToken, _, _, _, _ := setupEmergencyRouter(t)

	// Create an invite
	w := makeAuthRequest(router, http.MethodPost, "/emergency-access/invite", grantorToken, map[string]interface{}{
		"email":          "grantee-h@example.com",
		"access_type":    "view",
		"wait_time_days": 3,
	})
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	eaID := resp["id"].(string)

	// Delete
	dw := makeAuthRequest(router, http.MethodDelete, "/emergency-access/"+eaID, grantorToken, nil)
	if dw.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d: %s", dw.Code, dw.Body.String())
	}

	// List should be empty
	lw := makeAuthRequest(router, http.MethodGet, "/emergency-access/granted", grantorToken, nil)
	var granted []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&granted)
	if len(granted) != 0 {
		t.Errorf("expected 0 granted after delete, got %d", len(granted))
	}
}

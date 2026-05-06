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
	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// setupCollectionTest creates mock repos, registers an admin user, creates an org,
// and returns everything needed for collection tests.
func setupCollectionTest(t *testing.T) (
	collectionRepo *MockCollectionRepo,
	orgRepo *MockOrgRepo,
	auditRepo *MockAuditRepo,
	adminUserID string,
	orgID string,
) {
	t.Helper()

	collectionRepo = NewMockCollectionRepo()
	orgRepo = NewMockOrgRepo()
	auditRepo = NewMockAuditRepo()

	// Create org
	org, err := orgRepo.CreateOrg(context.Background(), "Test Org", []byte("orgpubkey"), []byte("encorgprivkey"))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	// Add admin user
	adminUserID = "admin-user-1"
	if err := orgRepo.AddMember(context.Background(), org.ID, adminUserID, "admin", []byte("escrow")); err != nil {
		t.Fatalf("add admin: %v", err)
	}

	return collectionRepo, orgRepo, auditRepo, adminUserID, org.ID
}

func TestCreateCollection(t *testing.T) {
	collRepo, orgRepo, auditRepo, adminID, orgID := setupCollectionTest(t)

	key := [32]byte{1, 2, 3}
	nameEnc, nameNonce, _ := crypto.Encrypt([]byte("My Collection"), key)

	coll := db.Collection{
		OrgID:         orgID,
		NameEncrypted: nameEnc,
		NameNonce:     nameNonce,
	}

	created, err := collRepo.CreateCollection(context.Background(), coll)
	if err != nil {
		t.Fatalf("CreateCollection failed: %v", err)
	}

	if created.ID == "" {
		t.Error("expected non-empty collection ID")
	}
	if created.OrgID != orgID {
		t.Errorf("expected org_id=%s, got %s", orgID, created.OrgID)
	}

	// Add admin as manage member
	collKey := []byte("encrypted-collection-key-32bytes!")
	if err := collRepo.AddCollectionMember(context.Background(), created.ID, adminID, collKey, "manage"); err != nil {
		t.Fatalf("AddCollectionMember failed: %v", err)
	}

	// Verify in listing
	colls, err := collRepo.ListCollections(context.Background(), orgID, adminID)
	if err != nil {
		t.Fatalf("ListCollections failed: %v", err)
	}
	if len(colls) != 1 {
		t.Errorf("expected 1 collection, got %d", len(colls))
	}
	if len(colls) > 0 && colls[0].Permission != "manage" {
		t.Errorf("expected manage permission, got %s", colls[0].Permission)
	}

	_ = orgRepo
	_ = auditRepo
}

func TestAddMember(t *testing.T) {
	collRepo, _, _, adminID, orgID := setupCollectionTest(t)

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: orgID})
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, adminID, []byte("key"), "manage"); err != nil {
		t.Fatalf("AddCollectionMember (admin) failed: %v", err)
	}

	// Add a read-only member
	memberID := "member-user-1"
	err := collRepo.AddCollectionMember(context.Background(), coll.ID, memberID, []byte("memberkey"), "read")
	if err != nil {
		t.Fatalf("AddCollectionMember failed: %v", err)
	}

	members, err := collRepo.GetCollectionMembers(context.Background(), coll.ID)
	if err != nil {
		t.Fatalf("GetCollectionMembers failed: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}

	// Verify the member's key
	key, err := collRepo.GetCollectionKey(context.Background(), coll.ID, memberID)
	if err != nil {
		t.Fatalf("GetCollectionKey failed: %v", err)
	}
	if !bytes.Equal(key, []byte("memberkey")) {
		t.Error("member key mismatch")
	}
}

func TestCollectionPermission_ReadOnly(t *testing.T) {
	collRepo, _, _, adminID, orgID := setupCollectionTest(t)

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: orgID})
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, adminID, []byte("key"), "manage"); err != nil {
		t.Fatalf("AddCollectionMember (admin) failed: %v", err)
	}

	readMember := "reader-1"
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, readMember, []byte("rkey"), "read"); err != nil {
		t.Fatalf("AddCollectionMember (read) failed: %v", err)
	}

	// Verify read member cannot have write permission
	members, _ := collRepo.GetCollectionMembers(context.Background(), coll.ID)
	var readerPerm string
	for _, m := range members {
		if m.UserID == readMember {
			readerPerm = m.Permission
		}
	}
	if readerPerm != "read" {
		t.Errorf("expected read permission, got %s", readerPerm)
	}

	// Use hasPermission logic: read >= read (ok), read >= write (not ok)
	levels := map[string]int{"read": 1, "write": 2, "manage": 3}
	if levels[readerPerm] >= levels["write"] {
		t.Error("read-only member should not have write permission")
	}
}

func TestCollectionPermission_Write(t *testing.T) {
	collRepo, _, _, _, orgID := setupCollectionTest(t)

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: orgID})

	writeUser := "writer-1"
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, writeUser, []byte("wkey"), "write"); err != nil {
		t.Fatalf("AddCollectionMember (write) failed: %v", err)
	}

	// Writer can add entries
	err := collRepo.AddEntryToCollection(context.Background(), coll.ID, "entry-1", "login", []byte("encdata"), []byte("nonce"))
	if err != nil {
		t.Fatalf("AddEntryToCollection failed: %v", err)
	}

	entries, err := collRepo.GetCollectionEntries(context.Background(), coll.ID)
	if err != nil {
		t.Fatalf("GetCollectionEntries failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestCollectionPermission_Manage(t *testing.T) {
	collRepo, _, _, adminID, orgID := setupCollectionTest(t)

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: orgID})
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, adminID, []byte("key"), "manage"); err != nil {
		t.Fatalf("AddCollectionMember (admin) failed: %v", err)
	}

	// Manager can add/remove members
	newUser := "user-2"
	err := collRepo.AddCollectionMember(context.Background(), coll.ID, newUser, []byte("ukey"), "read")
	if err != nil {
		t.Fatalf("manager add member failed: %v", err)
	}

	err = collRepo.RemoveCollectionMember(context.Background(), coll.ID, newUser)
	if err != nil {
		t.Fatalf("manager remove member failed: %v", err)
	}

	members, _ := collRepo.GetCollectionMembers(context.Background(), coll.ID)
	for _, m := range members {
		if m.UserID == newUser {
			t.Error("removed member should not appear in member list")
		}
	}
}

func TestDeleteCollection(t *testing.T) {
	collRepo, _, _, adminID, orgID := setupCollectionTest(t)

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: orgID})
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, adminID, []byte("key"), "manage"); err != nil {
		t.Fatalf("AddCollectionMember failed: %v", err)
	}
	if err := collRepo.AddEntryToCollection(context.Background(), coll.ID, "entry-1", "login", []byte("data"), []byte("nonce")); err != nil {
		t.Fatalf("AddEntryToCollection failed: %v", err)
	}

	// Delete
	err := collRepo.DeleteCollection(context.Background(), coll.ID)
	if err != nil {
		t.Fatalf("DeleteCollection failed: %v", err)
	}

	// Verify cascade: members gone
	members, _ := collRepo.GetCollectionMembers(context.Background(), coll.ID)
	if len(members) != 0 {
		t.Errorf("expected 0 members after delete, got %d", len(members))
	}

	// Verify cascade: entries gone
	entries, _ := collRepo.GetCollectionEntries(context.Background(), coll.ID)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after delete, got %d", len(entries))
	}

	// Verify collection gone
	_, err = collRepo.GetCollection(context.Background(), coll.ID)
	if err == nil {
		t.Error("expected error getting deleted collection")
	}
}

// ---------------------------------------------------------------------------
// Collection Handler HTTP Tests
// ---------------------------------------------------------------------------

func setupCollectionRouter(t *testing.T) (chi.Router, string, string, *MockCollectionRepo, *MockOrgRepo) {
	t.Helper()

	userRepo := NewMockUserRepo()
	vaultRepo := NewMockVaultRepo()
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

	collHandler := api.NewCollectionHandler(collRepo, orgRepo, userRepo, auditRepo)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(authService, userRepo))
		r.Get("/collections", collHandler.ListUserCollections)
		r.Route("/collections/{id}", func(r chi.Router) {
			r.Get("/", collHandler.GetCollection)
			r.Delete("/", collHandler.DeleteCollection)
			r.Get("/members", collHandler.GetCollectionMembers)
			r.Get("/entries", collHandler.ListEntries)
		})
	})

	// Register a test user
	authHash := createTestAuthHash()
	regBody := map[string]interface{}{
		"email":                  "colluser@example.com",
		"auth_hash":             authHash,
		"salt":                  hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":            hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)

	regRouter := chi.NewRouter()
	regRouter.Post("/auth/register", api.NewAuthHandler(authService).Register)

	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	regRouter.ServeHTTP(regW, regReq)

	var regResp auth.RegisterResponse
	if err := json.NewDecoder(regW.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	return r, regResp.AccessToken, regResp.UserID, collRepo, orgRepo
}

func TestListUserCollections_Empty(t *testing.T) {
	router, token, _, _, _ := setupCollectionRouter(t)

	w := makeAuthRequest(router, http.MethodGet, "/collections", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var colls []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&colls); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(colls) != 0 {
		t.Errorf("expected 0 collections, got %d", len(colls))
	}
}

func TestListUserCollections_WithMembership(t *testing.T) {
	router, token, userID, collRepo, orgRepo := setupCollectionRouter(t)

	// Create org and collection, add user as member
	org, _ := orgRepo.CreateOrg(context.Background(), "Org", []byte("pub"), []byte("priv"))
	if err := orgRepo.AddMember(context.Background(), org.ID, userID, "admin", nil); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	coll, _ := collRepo.CreateCollection(context.Background(), db.Collection{OrgID: org.ID, NameEncrypted: []byte("name"), NameNonce: []byte("nonce")})
	if err := collRepo.AddCollectionMember(context.Background(), coll.ID, userID, []byte("enckey"), "manage"); err != nil {
		t.Fatalf("AddCollectionMember failed: %v", err)
	}

	w := makeAuthRequest(router, http.MethodGet, "/collections", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var colls []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&colls); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(colls) != 1 {
		t.Errorf("expected 1 collection, got %d", len(colls))
	}
}

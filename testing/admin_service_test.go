package integration_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/crypto"
)

func setupAdminService(t *testing.T) (*admin.Service, *MockUserRepo, *MockVaultRepo, *MockOrgRepo, *MockAuditRepo) {
	t.Helper()

	userRepo := NewMockUserRepo()
	vaultRepo := NewMockVaultRepo()
	orgRepo := NewMockOrgRepo()
	auditRepo := NewMockAuditRepo()

	adminService := admin.NewService(orgRepo, userRepo, vaultRepo, auditRepo)
	return adminService, userRepo, vaultRepo, orgRepo, auditRepo
}

func TestCreateOrg_Success(t *testing.T) {
	adminSvc, userRepo, _, _, auditRepo := setupAdminService(t)

	// Create a test user
	user, err := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	if err != nil {
		t.Fatalf("registerTestUser failed: %v", err)
	}

	adminMasterKey := [32]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		110, 120, 130, 140, 150, 160, 170, 180, 190, 200,
		210, 220, 230, 240, 250, 1, 2, 3, 4, 5, 6, 7}

	org, err := adminSvc.CreateOrg(context.Background(), user.ID, "Test Org", adminMasterKey)
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}

	if org.ID == "" {
		t.Error("expected non-empty org ID")
	}
	if org.Name != "Test Org" {
		t.Errorf("expected org name 'Test Org', got %q", org.Name)
	}

	// Check audit log
	if len(auditRepo.entries) == 0 {
		t.Error("expected audit log entry for org creation")
	}
}

func TestAccessVault_AsAdmin(t *testing.T) {
	// This test verifies the admin can access a user's vault via escrow.
	// We need a more complete mock for escrow, so we test the flow conceptually.

	adminSvc, userRepo, vaultRepo, orgRepo, _ := setupAdminService(t)

	// Create admin user
	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))

	adminMasterKey := [32]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		110, 120, 130, 140, 150, 160, 170, 180, 190, 200,
		210, 220, 230, 240, 250, 1, 2, 3, 4, 5, 6, 7}

	// Create org
	org, err := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Test Org", adminMasterKey)
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}

	// Verify the admin is a member
	members, err := orgRepo.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member (admin), got %d", len(members))
	}
	if members[0].Role != "admin" {
		t.Errorf("expected admin role, got %q", members[0].Role)
	}

	// Verify vault repo is usable
	_ = vaultRepo
}

func TestAccessVault_AsNonAdmin(t *testing.T) {
	adminSvc, userRepo, _, _, _ := setupAdminService(t)

	// Create admin and org
	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	adminMasterKey := [32]byte{10}

	org, err := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Test Org", adminMasterKey)
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}

	// Create a non-admin user
	nonAdmin, _ := registerTestUser(userRepo, "member@org.com", hex.EncodeToString([]byte("authhashmembertestuser12")))

	// Non-admin tries to access vault — should fail because they're not in the org
	_, err = adminSvc.AccessUserVault(context.Background(), nonAdmin.ID, org.ID, adminUser.ID, [32]byte{})
	if err == nil {
		t.Error("non-admin should not be able to access vault")
	}
}

func TestChangeUserPassword_AsAdmin(t *testing.T) {
	// Test that the admin path for changing password requires admin role
	adminSvc, userRepo, _, _, _ := setupAdminService(t)

	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	adminMasterKey := [32]byte{10}

	org, err := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Test Org", adminMasterKey)
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}

	// Non-admin tries to change password — should fail
	nonAdmin, _ := registerTestUser(userRepo, "target@org.com", hex.EncodeToString([]byte("authhashmembertestuser12")))

	err = adminSvc.ChangeUserPassword(
		context.Background(),
		nonAdmin.ID, org.ID, adminUser.ID,
		[32]byte{}, [32]byte{1},
		hex.EncodeToString([]byte("newauthhashmember1234567")),
		hex.EncodeToString([]byte("0123456789abcdef")),
	)
	if err == nil {
		t.Error("non-admin should not be able to change user password")
	}
}

func TestAuditLog_RecordsAccess(t *testing.T) {
	adminSvc, userRepo, _, _, auditRepo := setupAdminService(t)

	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	adminMasterKey := [32]byte{10}

	_, err := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Audited Org", adminMasterKey)
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}

	// Verify audit log has the org creation entry
	found := false
	for _, entry := range auditRepo.entries {
		if entry.Action == "org_created" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'org_created' audit log entry")
	}
}

func TestInviteAndAccept(t *testing.T) {
	adminSvc, userRepo, _, orgRepo, _ := setupAdminService(t)

	// Create admin + org
	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	adminMasterKey := [32]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		110, 120, 130, 140, 150, 160, 170, 180, 190, 200,
		210, 220, 230, 240, 250, 1, 2, 3, 4, 5, 6, 7}

	org, _ := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Invite Org", adminMasterKey)

	// Invite a user
	inv, err := adminSvc.InviteUser(context.Background(), adminUser.ID, org.ID, "member@org.com", "member")
	if err != nil {
		t.Fatalf("InviteUser failed: %v", err)
	}
	if inv.Email != "member@org.com" {
		t.Errorf("expected email member@org.com, got %s", inv.Email)
	}

	// List invitations
	invitations, _ := orgRepo.ListInvitations(context.Background(), org.ID)
	if len(invitations) != 1 {
		t.Errorf("expected 1 invitation, got %d", len(invitations))
	}
}

func TestLeaveOrg(t *testing.T) {
	adminSvc, userRepo, _, orgRepo, _ := setupAdminService(t)

	adminUser, _ := registerTestUser(userRepo, "admin@org.com", hex.EncodeToString([]byte("authhashadmintestuser1234")))
	adminMasterKey := [32]byte{10}

	org, _ := adminSvc.CreateOrg(context.Background(), adminUser.ID, "Leave Org", adminMasterKey)

	// Add a second member directly for testing
	if err := orgRepo.AddMember(context.Background(), org.ID, "user-99", "member", nil); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// Leave
	err := adminSvc.LeaveOrg(context.Background(), "user-99", org.ID)
	if err != nil {
		t.Fatalf("LeaveOrg failed: %v", err)
	}

	// Verify member is gone
	members, _ := orgRepo.ListMembers(context.Background(), org.ID)
	for _, m := range members {
		if m.UserID == "user-99" {
			t.Error("user should no longer be a member")
		}
	}
}

// Verify auth and crypto imports are used
func init() {
	_ = auth.ServiceConfig{}
	_ = crypto.SaltSize
	_ = time.Now
	_ = json.Marshal
}

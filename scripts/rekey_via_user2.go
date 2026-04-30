package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/pbkdf2"

	"github.com/password-manager/password-manager/internal/crypto"
)

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://pmuser:pmpass_dev_only@postgres:5432/password_manager?sslmode=disable"
	}
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	orgID := "e22cb781-d1b5-4a1c-9767-d0dd7ed3f8be"

	// User 2's credentials
	user2Email := "nprohnitchi@lancastergroup.ca"
	user2Password := "Poisawesome14$"
	user2ID := "abbdef68-9aef-42b2-9d7a-ac5a14f8af9c"

	// Derive user 2's master key
	salt := sha256.Sum256([]byte(user2Email))
	derived := pbkdf2.Key([]byte(user2Password), salt[:], 100000, 64, sha512.New)
	var user2MK [32]byte
	copy(user2MK[:], derived[:32])
	fmt.Printf("user2 masterKey: %s\n", hex.EncodeToString(user2MK[:]))

	// Get user 2's per-admin encrypted_org_key
	var encOrgKey []byte
	err = conn.QueryRow(ctx, "SELECT encrypted_org_key FROM org_members WHERE org_id = $1 AND user_id = $2", orgID, user2ID).Scan(&encOrgKey)
	if err != nil {
		log.Fatalf("get user2 org key: %v", err)
	}
	fmt.Printf("user2 encrypted_org_key length: %d\n", len(encOrgKey))

	// Decrypt org private key using user 2's master key
	orgPrivKey, err := crypto.DecryptOrgPrivateKey(encOrgKey, user2MK)
	if err != nil {
		log.Fatalf("decrypt org private key via user2: %v", err)
	}
	fmt.Printf("org private key length: %d\n", len(orgPrivKey))

	// Admin's new master key (Password123!)
	adminMKHex := "a495731a3412ade84537edb89e8859d2ec3cc05cbaae5c439e22ad1335cd3293"
	adminMKBytes, _ := hex.DecodeString(adminMKHex)
	var adminMK [32]byte
	copy(adminMK[:], adminMKBytes)

	// Re-encrypt org private key for admin
	encPrivKey, nonce, err := crypto.Encrypt(orgPrivKey, adminMK)
	if err != nil {
		log.Fatalf("encrypt org private key for admin: %v", err)
	}
	blob := make([]byte, len(nonce)+len(encPrivKey))
	copy(blob[:len(nonce)], nonce)
	copy(blob[len(nonce):], encPrivKey)

	// Update both the org-level key and admin's per-admin key
	_, err = conn.Exec(ctx, "UPDATE organizations SET encrypted_org_private_key = $1 WHERE id = $2", blob, orgID)
	if err != nil {
		log.Fatalf("update org: %v", err)
	}

	_, err = conn.Exec(ctx, "UPDATE org_members SET encrypted_org_key = $1 WHERE org_id = $2 AND user_id = $3",
		blob, orgID, os.Args[1])
	if err != nil {
		log.Fatalf("update admin org key: %v", err)
	}

	fmt.Println("✓ Re-keyed org private key for admin and updated org-level key")
}

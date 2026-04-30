//go:build ignore

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
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run scripts/fix_escrow.go <email> <password>")
		os.Exit(1)
	}
	email := os.Args[1]
	password := os.Args[2]

	// Derive master key the same way the Electron client does
	salt := sha256.Sum256([]byte(email))
	derived := pbkdf2.Key([]byte(password), salt[:], 100000, 64, sha512.New)
	var masterKey [32]byte
	copy(masterKey[:], derived[:32])

	fmt.Printf("email: %s\n", email)
	fmt.Printf("masterKey: %s\n", hex.EncodeToString(masterKey[:]))

	// Connect to DB
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

	// Get user ID
	var userID string
	err = conn.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err != nil {
		log.Fatalf("user not found: %v", err)
	}
	fmt.Printf("userID: %s\n", userID)

	// Get org ID and org public key
	var orgID string
	var orgPubKey []byte
	err = conn.QueryRow(ctx, `
		SELECT o.id, o.org_public_key FROM organizations o
		JOIN org_members om ON om.org_id = o.id
		WHERE om.user_id = $1
	`, userID).Scan(&orgID, &orgPubKey)
	if err != nil {
		log.Fatalf("org not found: %v", err)
	}
	fmt.Printf("orgID: %s\n", orgID)
	fmt.Printf("orgPubKey length: %d\n", len(orgPubKey))

	// Create new escrow blob
	escrowBlob, err := crypto.EncryptEscrow(masterKey, orgPubKey)
	if err != nil {
		log.Fatalf("encrypt escrow: %v", err)
	}
	fmt.Printf("new escrow blob length: %d\n", len(escrowBlob))

	// Update escrow and clear stale encrypted_org_key
	_, err = conn.Exec(ctx, `
		UPDATE org_members
		SET escrow_blob = $1, encrypted_org_key = NULL
		WHERE org_id = $2 AND user_id = $3
	`, escrowBlob, orgID, userID)
	if err != nil {
		log.Fatalf("update escrow: %v", err)
	}

	fmt.Println("✓ Updated escrow blob and cleared encrypted_org_key for", email)
}

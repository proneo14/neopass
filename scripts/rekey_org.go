//go:build ignore

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/password-manager/password-manager/internal/crypto"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: rekey_org <old_master_key_hex> <new_master_key_hex>")
		os.Exit(1)
	}
	oldMKHex := os.Args[1]
	newMKHex := os.Args[2]

	oldMKBytes, err := hex.DecodeString(oldMKHex)
	if err != nil || len(oldMKBytes) != 32 {
		log.Fatal("invalid old master key hex")
	}
	newMKBytes, err := hex.DecodeString(newMKHex)
	if err != nil || len(newMKBytes) != 32 {
		log.Fatal("invalid new master key hex")
	}

	var oldMK, newMK [32]byte
	copy(oldMK[:], oldMKBytes)
	copy(newMK[:], newMKBytes)

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

	// Get org encrypted_org_private_key
	var orgID string
	var encOrgPrivKey []byte
	err = conn.QueryRow(ctx, "SELECT id, encrypted_org_private_key FROM organizations LIMIT 1").Scan(&orgID, &encOrgPrivKey)
	if err != nil {
		log.Fatalf("get org: %v", err)
	}
	fmt.Printf("orgID: %s, encOrgPrivKey length: %d\n", orgID, len(encOrgPrivKey))

	// Decrypt with old master key
	orgPrivKey, err := crypto.DecryptOrgPrivateKey(encOrgPrivKey, oldMK)
	if err != nil {
		log.Fatalf("decrypt org private key with old master key: %v", err)
	}
	fmt.Printf("decrypted org private key length: %d\n", len(orgPrivKey))

	// Re-encrypt with new master key (same format: nonce + ciphertext)
	encPrivKey, nonce, err := crypto.Encrypt(orgPrivKey, newMK)
	if err != nil {
		log.Fatalf("re-encrypt org private key: %v", err)
	}
	newEncOrgPrivKey := make([]byte, len(nonce)+len(encPrivKey))
	copy(newEncOrgPrivKey[:len(nonce)], nonce)
	copy(newEncOrgPrivKey[len(nonce):], encPrivKey)
	fmt.Printf("new encrypted org private key length: %d\n", len(newEncOrgPrivKey))

	// Update
	_, err = conn.Exec(ctx, "UPDATE organizations SET encrypted_org_private_key = $1 WHERE id = $2", newEncOrgPrivKey, orgID)
	if err != nil {
		log.Fatalf("update org: %v", err)
	}

	fmt.Println("✓ Re-keyed org private key from old master key to new master key")
}

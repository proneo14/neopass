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
	masterKeyHex := os.Args[1] // expected: 10238d1712bca95ffda4056c7f2096155ee47a060c88d63ce02beed6f97fedc4

	masterKeyBytes, _ := hex.DecodeString(masterKeyHex)
	var masterKey [32]byte
	copy(masterKey[:], masterKeyBytes)

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

	// Get admin's encrypted_org_key
	var encOrgKey []byte
	err = conn.QueryRow(ctx, `
		SELECT om.encrypted_org_key FROM org_members om
		JOIN users u ON u.id = om.user_id
		WHERE u.email = 'admin@lgi.com'
	`).Scan(&encOrgKey)
	if err != nil {
		log.Fatalf("get encrypted_org_key: %v", err)
	}
	fmt.Printf("encrypted_org_key length: %d\n", len(encOrgKey))
	fmt.Printf("encrypted_org_key hex: %s\n", hex.EncodeToString(encOrgKey))

	// Try to decrypt org private key
	orgPrivKey, err := crypto.DecryptOrgPrivateKey(encOrgKey, masterKey)
	if err != nil {
		fmt.Printf("ERROR decrypting org key with provided master key: %v\n", err)

		// Try the org-level key as fallback
		var orgEncPrivKey []byte
		err2 := conn.QueryRow(ctx, `
			SELECT encrypted_org_private_key FROM organizations LIMIT 1
		`).Scan(&orgEncPrivKey)
		if err2 == nil {
			fmt.Printf("org-level encrypted_org_private_key length: %d\n", len(orgEncPrivKey))
			orgPrivKey2, err3 := crypto.DecryptOrgPrivateKey(orgEncPrivKey, masterKey)
			if err3 != nil {
				fmt.Printf("ERROR decrypting org-level key: %v\n", err3)
			} else {
				fmt.Printf("SUCCESS decrypting org-level key! length: %d\n", len(orgPrivKey2))
			}
		}
	} else {
		fmt.Printf("SUCCESS decrypting org key! length: %d\n", len(orgPrivKey))
	}
}

//go:build ignore

package main

import (
	"fmt"
	"github.com/password-manager/password-manager/internal/crypto"
)

func main() {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("public key size: %d\n", len(pub))
	fmt.Printf("private key size: %d\n", len(priv))
}

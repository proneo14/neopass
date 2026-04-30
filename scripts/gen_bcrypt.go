package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	authHashHex := os.Args[1]
	authHash, _ := hex.DecodeString(authHashHex)
	bcryptHash, err := bcrypt.GenerateFromPassword(authHash, bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(bcryptHash))
}

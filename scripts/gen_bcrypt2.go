//go:build ignore

package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	authHashHex := "57bf5b68bfff500374257b732660c8d56ea99e8fa4cb657fb7a2647cbed18647"
	authHash, _ := hex.DecodeString(authHashHex)
	hash, err := bcrypt.GenerateFromPassword(authHash, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
	fmt.Println(string(hash))
}

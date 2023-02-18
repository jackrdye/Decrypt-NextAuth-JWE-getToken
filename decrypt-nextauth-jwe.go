package main

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"golang.org/x/crypto/hkdf"
)

func main() {

	var err error

	rawJwe := "raw jwe text"
	nextAuthSecret := "next auth secret"
	info := "NextAuth.js Generated Encryption Key"

	// Step 1: Generate the decryption key with an hdkf lib
	hash := sha256.New
	kdf := hkdf.New(hash, []byte(nextAuthSecret), []byte(""), []byte(info))
	key := make([]byte, 32)
	_, _ = io.ReadFull(kdf, key)

	// Step 2: Decrypt with a JWE library.
	// Here we use lestrrat-go/jwx, which parses the JWE and
	// uses the JWE header info to choose the decryption algorithm.
	decrypted, err := jwe.Decrypt([]byte(rawJwe),
		jwe.WithKey(jwa.DIRECT, key))

	if err != nil {
		fmt.Printf("failed to decrypt: %s", err)
		return
	}
	fmt.Println(string(decrypted))

}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// generate random 32 bytes key
func generateRandomKey() (secret []byte) {
	n := 16
	b := make([]byte, n)
	rand.Read(b)
	secret = make([]byte, hex.EncodedLen(n))
	hex.Encode(secret, b)

	return
}
func Encrypt(pubfile string, payload []byte) ([]byte, error) {
	pubdata, err := os.ReadFile(pubfile)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	pubblock, _ := pem.Decode(pubdata)
	if pubblock == nil {
		return nil, fmt.Errorf("Nil block")
	}

	pub, err := x509.ParsePKIXPublicKey(pubblock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePKCS1PrivateKey: %w", err)
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Invalid public key")
	}

	key := generateRandomKey()
	encryptedBytes, _ := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		key,
		nil,
	)

	secret := base64.StdEncoding.EncodeToString(encryptedBytes)

	// encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	chiperText := aesgcm.Seal(nil, nonce, payload, nil)
	chiperText = append(chiperText, nonce...)
	content := base64.StdEncoding.EncodeToString([]byte(chiperText))

	fmt.Printf("SECRET: %s\n", secret)
	fmt.Printf("CONTENT: %s\n", content)

	res := Payload{
		Secret:  secret,
		Content: content,
	}
	jsres, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("Marshal: %w", err)
	}

	return jsres, nil
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func Decrypt(privfile, encsecret, enccontent string) ([]byte, error) {
	privdata, err := os.ReadFile(privfile)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	block, _ := pem.Decode(privdata)
	if block == nil {
		return nil, fmt.Errorf("Nil block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePKCS1PrivateKey: %w", err)
	}

	// DECRYPT RSA-OAEP-256 --> SECRET
	bsecret, _ := base64.StdEncoding.DecodeString(encsecret)
	secret, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		priv,
		bsecret,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("DecryptOAEP: %w", err)
	}

	fmt.Println(len(secret), "SECRET: ", string(secret))

	// PREPARE AES-GCM CIPHER
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("NewGCM: %w", err)
	}

	// DECRYPT AES-256-GCM
	decoded, _ := base64.StdEncoding.DecodeString(enccontent)
	bnonce := decoded[len(decoded)-12:] // last 12 bytes
	btext := decoded[:len(decoded)-12]  // the rest of bytes
	plaintext, err := aesgcm.Open(nil, bnonce, btext, nil)
	if err != nil {
		return nil, fmt.Errorf("Open: %w", err)
	}

	fmt.Println(len(bnonce), "NONCE BASE64:", base64.StdEncoding.EncodeToString(bnonce))
	fmt.Println(len(btext), "CIPHER BASE64:", base64.StdEncoding.EncodeToString(btext))

	return plaintext, nil
}

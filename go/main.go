package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type Payload struct {
	Secret  string `json:"secret"`
	Content string `json:"content"`
}

func main() {
	action := flag.String("action", "encrypt", "encrypt/decrypt")

	flag.Parse()

	switch *action {
	case "encrypt":
		plaintext, err := os.ReadFile("./../plaintext.json")
		if err != nil {
			fmt.Printf("ReadFile: %v", err)
			return
		}

		enc, err := Encrypt("./../test.public.txt", plaintext)
		if err != nil {
			fmt.Printf("Encrypt: %v", err)
			return
		}

		fmt.Println("\nWriting result to result.encrypt.json file...")
		if err := os.WriteFile("./../result.encrypt.json", enc, 0644); err != nil {
			fmt.Printf("WriteFile: %v", err)
			return
		}

	case "decrypt":
		benc, err := os.ReadFile("./../encrypted.json")
		if err != nil {
			fmt.Printf("ReadFile: %v", err)
			return
		}

		var enc Payload
		if err := json.Unmarshal(benc, &enc); err != nil {
			fmt.Printf("Unmarshal: %v", err)
			return
		}

		dec, err := Decrypt("./../test.private.txt", enc.Secret, enc.Content)
		if err != nil {
			fmt.Printf("Encrypt: %v", err)
			return
		}

		fmt.Println("\nWriting result to result.decrypt.json file...")
		if err := os.WriteFile("./../result.decrypt.json", dec, 0644); err != nil {
			fmt.Printf("WriteFile: %v", err)
			return
		}
	default:
		fmt.Printf("Unknown action: %s\n", *action)
		return
	}
	fmt.Println("DONE")
}

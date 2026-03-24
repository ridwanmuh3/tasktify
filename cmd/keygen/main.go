package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

func main() {
	// Generate Falcon-512 key pair (logn=9)
	skey, vkey, err := fndsa.KeyGen(9, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key pair: %v\n", err)
		os.Exit(1)
	}

	skPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "FALCON PRIVATE KEY",
		Bytes: skey,
	})

	vkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "FALCON PUBLIC KEY",
		Bytes: vkey,
	})

	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.WriteFile(outDir+"/falcon512_sk.pem", skPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write private key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outDir+"/falcon512_vk.pem", vkPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Falcon-512 key pair generated successfully")
	fmt.Printf("  Private key: %s/falcon512_sk.pem (%d bytes)\n", outDir, len(skey))
	fmt.Printf("  Public key:  %s/falcon512_vk.pem (%d bytes)\n", outDir, len(vkey))
}

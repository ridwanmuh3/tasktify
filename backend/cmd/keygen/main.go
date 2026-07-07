package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

func main() {
	outDir := "./keys"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fatal("failed to create %s: %v", outDir, err)
	}

	// Falcon-512 and Falcon-Precomputed-512 share the same FN-DSA-512 key pair.
	fnSk, fnVk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		fatal("Falcon-512 keygen failed: %v", err)
	}
	writeKeyPair(outDir, "FNDSA-512", fnVk, fnSk)

	fmt.Println("Falcon keys generated successfully in", outDir)
}

func writeKeyPair(dir, alg string, pk, sk []byte) {
	writePEM(dir+"/"+alg+"_pk.pem", alg+" PUBLIC KEY", pk, 0644)
	writePEM(dir+"/"+alg+"_sk.pem", alg+" PRIVATE KEY", sk, 0600)
}

func writePEM(path, pemType string, data []byte, mode os.FileMode) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: data})
	if err := os.WriteFile(path, pemData, mode); err != nil {
		fatal("failed to write %s: %v", path, err)
	}
	fmt.Printf("  %s (%d bytes)\n", path, len(data))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

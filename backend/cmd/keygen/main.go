package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	// FN-DSA-512 and FN-DSA-Precomputed-512 share the same FN-DSA-512 key pair.
	fnSk, fnVk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		fatal("FN-DSA-512 keygen failed: %v", err)
	}
	writeKeyPair(outDir, "FNDSA-512", fnVk, fnSk)

	// Classical baselines for the adversarial + performance comparison
	// (HS256, RS256, ES256, EdDSA) sit alongside the PQC profiles above.
	genRS256(outDir)
	genES256(outDir)
	genHS256(outDir)
	genEdDSA(outDir)

	fmt.Println("Keys generated successfully in", outDir)
}

func genRS256(outDir string) {
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal("RS256 keygen failed: %v", err)
	}
	skBytes := x509.MarshalPKCS1PrivateKey(sk)
	pkBytes, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		fatal("RS256 public key marshal failed: %v", err)
	}
	writePEM(outDir+"/RS256_sk.pem", "RSA PRIVATE KEY", skBytes, 0600)
	writePEM(outDir+"/RS256_pk.pem", "RSA PUBLIC KEY", pkBytes, 0644)
}

func genES256(outDir string) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("ES256 keygen failed: %v", err)
	}
	skBytes, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		fatal("ES256 private key marshal failed: %v", err)
	}
	pkBytes, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		fatal("ES256 public key marshal failed: %v", err)
	}
	writePEM(outDir+"/ES256_sk.pem", "EC PRIVATE KEY", skBytes, 0600)
	writePEM(outDir+"/ES256_pk.pem", "EC PUBLIC KEY", pkBytes, 0644)
}

func genHS256(outDir string) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fatal("HS256 secret generation failed: %v", err)
	}
	writePEM(outDir+"/HS256_secret.pem", "HMAC SECRET", secret, 0600)
}

func genEdDSA(outDir string) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("EdDSA keygen failed: %v", err)
	}
	skBytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		fatal("EdDSA private key marshal failed: %v", err)
	}
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		fatal("EdDSA public key marshal failed: %v", err)
	}
	writePEM(outDir+"/EdDSA_sk.pem", "PRIVATE KEY", skBytes, 0600)
	writePEM(outDir+"/EdDSA_pk.pem", "PUBLIC KEY", pkBytes, 0644)
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

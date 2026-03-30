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

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

func main() {
	outDir := "./keys"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	os.MkdirAll(outDir, 0755)

	// ── Falcon-512 (Original + Precomputed share the same key pair) ──
	fnSk, fnVk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		fatal("Falcon-512 keygen failed: %v", err)
	}
	writeKeyPair(outDir, "FNDSA-512", fnVk, fnSk)

	// ── Falcon-1024 ──
	fn1024Sk, fn1024Vk, err := fndsa.KeyGen(10, nil)
	if err != nil {
		fatal("Falcon-1024 keygen failed: %v", err)
	}
	writeKeyPair(outDir, "FNDSA-1024", fn1024Vk, fn1024Sk)

	// ── ML-DSA-44 (NIST FIPS 204) ──
	ml44pk, ml44sk, err := mldsa44.Scheme().GenerateKey()
	if err != nil {
		fatal("ML-DSA-44 keygen failed: %v", err)
	}
	ml44pkBytes, _ := ml44pk.MarshalBinary()
	ml44skBytes, _ := ml44sk.MarshalBinary()
	writePEM(outDir+"/ML-DSA-44_pk.pem", "ML-DSA-44 PUBLIC KEY", ml44pkBytes, 0644)
	writePEM(outDir+"/ML-DSA-44_sk.pem", "ML-DSA-44 PRIVATE KEY", ml44skBytes, 0600)

	// ── SLH-DSA-SHA2-128f (NIST FIPS 205) ──
	slhpk, slhsk, err := slhdsa.SHA2_128f.Scheme().GenerateKey()
	if err != nil {
		fatal("SLH-DSA-SHA2-128f keygen failed: %v", err)
	}
	slhpkBytes, _ := slhpk.MarshalBinary()
	slhskBytes, _ := slhsk.MarshalBinary()
	writePEM(outDir+"/SLH-DSA-SHA2-128f_pk.pem", "SLH-DSA-SHA2-128f PUBLIC KEY", slhpkBytes, 0644)
	writePEM(outDir+"/SLH-DSA-SHA2-128f_sk.pem", "SLH-DSA-SHA2-128f PRIVATE KEY", slhskBytes, 0600)

	// ── ES256 (ECDSA P-256) ──
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("ES256 keygen failed: %v", err)
	}
	ecSkBytes, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	ecPkBytes, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	writePEM(outDir+"/ES256_sk.pem", "EC PRIVATE KEY", ecSkBytes, 0600)
	writePEM(outDir+"/ES256_pk.pem", "EC PUBLIC KEY", ecPkBytes, 0644)

	// ── RS256 (RSA 2048) ──
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal("RS256 keygen failed: %v", err)
	}
	rsaSkBytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPkBytes, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	writePEM(outDir+"/RS256_sk.pem", "RSA PRIVATE KEY", rsaSkBytes, 0600)
	writePEM(outDir+"/RS256_pk.pem", "RSA PUBLIC KEY", rsaPkBytes, 0644)

	// ── HS256 (HMAC shared secret - 256 bits) ──
	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		fatal("HS256 keygen failed: %v", err)
	}
	writePEM(outDir+"/HS256_secret.pem", "HMAC SECRET KEY", hmacSecret, 0600)

	// ── EdDSA (Ed25519) ──
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("EdDSA keygen failed: %v", err)
	}
	edSkBytes, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	edPkBytes, _ := x509.MarshalPKIXPublicKey(edPub)
	writePEM(outDir+"/EdDSA_sk.pem", "ED25519 PRIVATE KEY", edSkBytes, 0600)
	writePEM(outDir+"/EdDSA_pk.pem", "ED25519 PUBLIC KEY", edPkBytes, 0644)

	fmt.Println("All keys generated successfully in", outDir)
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

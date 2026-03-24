package main

import (
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/pornin/go-fn-dsa/fndsa"
)

var keysDir = "./keys/"

func main() {
	mldsa44pk, mldsa44sk, _ := mldsa44.GenerateKey(rand.Reader)
	mldsa65pk, mldsa65sk, _ := mldsa65.GenerateKey(rand.Reader)
	mldsa87pk, mldsa87sk, _ := mldsa87.GenerateKey(rand.Reader)

	fndsa512_sk, fndsa512_pk, _ := fndsa.KeyGen(9, rand.Reader)
	fndsa1024_sk, fndsa1024_pk, _ := fndsa.KeyGen(10, rand.Reader)

	slhdsa_sha2_128f_Pk, slhdsa_sha2_128f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	slhdsa_sha2_128s_Pk, slhdsa_sha2_128s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	slhdsa_sha2_192f_Pk, slhdsa_sha2_192f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192f)
	slhdsa_sha2_192s_Pk, slhdsa_sha2_192s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192s)
	slhdsa_sha2_256f_Pk, slhdsa_sha2_256f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_256f)
	slhdsa_sha2_256s_Pk, slhdsa_sha2_256s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_256s)
	slhdsa_shake_128f_Pk, slhdsa_shake_128f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128f)
	slhdsa_shake_128s_Pk, slhdsa_shake_128s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128s)
	slhdsa_shake_192f_Pk, slhdsa_shake_192f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_192f)
	slhdsa_shake_192s_Pk, slhdsa_shake_192s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_192s)
	slhdsa_shake_256f_Pk, slhdsa_shake_256f_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256f)
	slhdsa_shake_256s_Pk, slhdsa_shake_256s_Sk, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256s)

	slhdsa_sha2_128f_PkBytes, _ := slhdsa_sha2_128f_Pk.MarshalBinary()
	slhdsa_sha2_128f_SkBytes, _ := slhdsa_sha2_128f_Sk.MarshalBinary()
	slhdsa_sha2_128s_PkBytes, _ := slhdsa_sha2_128s_Pk.MarshalBinary()
	slhdsa_sha2_128s_SkBytes, _ := slhdsa_sha2_128s_Sk.MarshalBinary()
	slhdsa_sha2_192f_PkBytes, _ := slhdsa_sha2_192f_Pk.MarshalBinary()
	slhdsa_sha2_192f_SkBytes, _ := slhdsa_sha2_192f_Sk.MarshalBinary()
	slhdsa_sha2_192s_PkBytes, _ := slhdsa_sha2_192s_Pk.MarshalBinary()
	slhdsa_sha2_192s_SkBytes, _ := slhdsa_sha2_192s_Sk.MarshalBinary()
	slhdsa_sha2_256f_PkBytes, _ := slhdsa_sha2_256f_Pk.MarshalBinary()
	slhdsa_sha2_256f_SkBytes, _ := slhdsa_sha2_256f_Sk.MarshalBinary()
	slhdsa_sha2_256s_PkBytes, _ := slhdsa_sha2_256s_Pk.MarshalBinary()
	slhdsa_sha2_256s_SkBytes, _ := slhdsa_sha2_256s_Sk.MarshalBinary()
	slhdsa_shake_128f_PkBytes, _ := slhdsa_shake_128f_Pk.MarshalBinary()
	slhdsa_shake_128f_SkBytes, _ := slhdsa_shake_128f_Sk.MarshalBinary()
	slhdsa_shake_128s_PkBytes, _ := slhdsa_shake_128s_Pk.MarshalBinary()
	slhdsa_shake_128s_SkBytes, _ := slhdsa_shake_128s_Sk.MarshalBinary()
	slhdsa_shake_192f_PkBytes, _ := slhdsa_shake_192f_Pk.MarshalBinary()
	slhdsa_shake_192f_SkBytes, _ := slhdsa_shake_192f_Sk.MarshalBinary()
	slhdsa_shake_192s_PkBytes, _ := slhdsa_shake_192s_Pk.MarshalBinary()
	slhdsa_shake_192s_SkBytes, _ := slhdsa_shake_192s_Sk.MarshalBinary()
	slhdsa_shake_256f_PkBytes, _ := slhdsa_shake_256f_Pk.MarshalBinary()
	slhdsa_shake_256f_SkBytes, _ := slhdsa_shake_256f_Sk.MarshalBinary()
	slhdsa_shake_256s_PkBytes, _ := slhdsa_shake_256s_Pk.MarshalBinary()
	slhdsa_shake_256s_SkBytes, _ := slhdsa_shake_256s_Sk.MarshalBinary()

	generateKeyfile("ML-DSA-44", mldsa44pk.Bytes(), mldsa44sk.Bytes())
	generateKeyfile("ML-DSA-65", mldsa65pk.Bytes(), mldsa65sk.Bytes())
	generateKeyfile("ML-DSA-87", mldsa87pk.Bytes(), mldsa87sk.Bytes())

	generateKeyfile("FNDSA-512", fndsa512_pk, fndsa512_sk)
	generateKeyfile("FNDSA-1024", fndsa1024_pk, fndsa1024_sk)

	generateKeyfile("SLH-DSA-SHA2-128f", slhdsa_sha2_128f_PkBytes, slhdsa_sha2_128f_SkBytes)
	generateKeyfile("SLH-DSA-SHA2-128s", slhdsa_sha2_128s_PkBytes, slhdsa_sha2_128s_SkBytes)
	generateKeyfile("SLH-DSA-SHA2-192f", slhdsa_sha2_192f_PkBytes, slhdsa_sha2_192f_SkBytes)
	generateKeyfile("SLH-DSA-SHA2-192s", slhdsa_sha2_192s_PkBytes, slhdsa_sha2_192s_SkBytes)
	generateKeyfile("SLH-DSA-SHA2-256f", slhdsa_sha2_256f_PkBytes, slhdsa_sha2_256f_SkBytes)
	generateKeyfile("SLH-DSA-SHA2-256s", slhdsa_sha2_256s_PkBytes, slhdsa_sha2_256s_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-128f", slhdsa_shake_128f_PkBytes, slhdsa_shake_128f_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-128s", slhdsa_shake_128s_PkBytes, slhdsa_shake_128s_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-192f", slhdsa_shake_192f_PkBytes, slhdsa_shake_192f_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-192s", slhdsa_shake_192s_PkBytes, slhdsa_shake_192s_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-256f", slhdsa_shake_256f_PkBytes, slhdsa_shake_256f_SkBytes)
	generateKeyfile("SLH-DSA-SHAKE-256s", slhdsa_shake_256s_PkBytes, slhdsa_shake_256s_SkBytes)
}

func generateKeyfile(alg string, pk, sk []byte) {
	// Write private key to file
	pkBlock := &pem.Block{
		Type:  alg + " PUBLIC KEY",
		Bytes: pk,
	}

	skBlock := &pem.Block{
		Type:  alg + " PRIVATE KEY",
		Bytes: sk,
	}

	pkPem, err := os.Create(keysDir + alg + "_pk.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer pkPem.Close()

	if err := pem.Encode(pkPem, pkBlock); err != nil {
		log.Fatal(err)
	}

	skPem, err := os.Create(keysDir + alg + "_sk.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer skPem.Close()

	if err := pem.Encode(skPem, skBlock); err != nil {
		log.Fatal(err)
	}
}

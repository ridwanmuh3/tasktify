package jwt

import (
	"encoding/pem"
	"errors"
)

var (
	ErrNotFNDSAPrivateKey = errors.New("key is not a valid FN-DSA private key")
	ErrNotFNDSAPublicKey  = errors.New("key is not a valid FN-DSA public key")
)

func ParseFNDSAPrivateKeyFromPEM(key []byte) ([]byte, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return block.Bytes, nil
}

func ParseFNDSAPublicKeyFromPEM(key []byte) ([]byte, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return block.Bytes, nil
}

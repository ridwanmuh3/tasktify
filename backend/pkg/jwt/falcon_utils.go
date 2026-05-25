package jwt

import (
	"encoding/pem"
	"errors"
)

var (
	ErrNotFalconPrivateKey = errors.New("key is not a valid Falcon private key")
	ErrNotFalconPublicKey  = errors.New("key is not a valid Falcon public key")
)

func ParseFalconPrivateKeyFromPEM(key []byte) ([]byte, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return block.Bytes, nil
}

func ParseFalconPublicKeyFromPEM(key []byte) ([]byte, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return block.Bytes, nil
}

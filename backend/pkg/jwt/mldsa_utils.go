package jwt

import (
	"encoding/pem"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var (
	ErrNotMLDSAPrivateKey = newError("key is not a valid ML-DSA private key", ErrInvalidKeyType)
	ErrNotMLDSAPublicKey  = newError("key is not a valid ML-DSA public key", ErrInvalidKeyType)
)

func ParseMLDSAPrivateKeyFromPEM(alg string, key []byte) (any, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	switch alg {
	case "ML-DSA-44":
		skSign, err := mldsa44.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPrivateKey
		}

		mldsaSk, ok := skSign.(*mldsa44.PrivateKey)
		if !ok {
			return nil, ErrNotMLDSAPrivateKey
		}

		return mldsaSk, nil
	case "ML-DSA-65":
		skSign, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPrivateKey
		}
		mldsaSk, ok := skSign.(*mldsa65.PrivateKey)
		if !ok {
			return nil, ErrNotMLDSAPrivateKey
		}
		return mldsaSk, nil
	case "ML-DSA-87":
		skSign, err := mldsa87.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPrivateKey
		}
		mldsaSk, ok := skSign.(*mldsa87.PrivateKey)
		if !ok {
			return nil, ErrNotMLDSAPrivateKey
		}
		return mldsaSk, nil
	default:
		return nil, ErrInvalidKeyType
	}
}

func ParseMLDSAPublicKeyFromPEM(alg string, key []byte) (any, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	switch alg {
	case "ML-DSA-44":
		pkSign, err := mldsa44.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPublicKey
		}

		mldsaPk, ok := pkSign.(*mldsa44.PublicKey)
		if !ok {
			return nil, ErrNotMLDSAPublicKey
		}
		return mldsaPk, nil
	case "ML-DSA-65":
		pkSign, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPublicKey
		}
		mldsaPk, ok := pkSign.(*mldsa65.PublicKey)
		if !ok {
			return nil, ErrNotMLDSAPublicKey
		}
		return mldsaPk, nil
	case "ML-DSA-87":
		pkSign, err := mldsa87.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotMLDSAPublicKey
		}
		mldsaPk, ok := pkSign.(*mldsa87.PublicKey)
		if !ok {
			return nil, ErrNotMLDSAPublicKey
		}
		return mldsaPk, nil
	default:
		return nil, ErrInvalidKeyType
	}
}

package jwt

import (
	"encoding/pem"

	"github.com/cloudflare/circl/sign/slhdsa"
)

var (
	ErrNotSLHDSAPrivateKey = newError("key is not a valid SLH-DSA private key", ErrInvalidKeyType)
	ErrNotSLHDSAPublicKey  = newError("key is not a valid SLH-DSA public key", ErrInvalidKeyType)
)

func ParseSLHDSAPrivateKeyFromPEM(alg string, key []byte) (any, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var slhdsaSk any
	switch alg {
	case "SLH-DSA-SHA2-128f":
		skSign, err := slhdsa.SHA2_128f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHA2-128s":
		skSign, err := slhdsa.SHA2_128s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHA2-192f":
		skSign, err := slhdsa.SHA2_192f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHA2-192s":
		skSign, err := slhdsa.SHA2_192s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHA2-256f":
		skSign, err := slhdsa.SHA2_256f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHA2-256s":
		skSign, err := slhdsa.SHA2_256s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-128f":
		skSign, err := slhdsa.SHAKE_128f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-128s":
		skSign, err := slhdsa.SHAKE_128s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-192f":
		skSign, err := slhdsa.SHAKE_192f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-192s":
		skSign, err := slhdsa.SHAKE_192s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-256f":
		skSign, err := slhdsa.SHAKE_256f.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	case "SLH-DSA-SHAKE-256s":
		skSign, err := slhdsa.SHAKE_256s.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPrivateKey
		}
		var ok bool
		slhdsaSk, ok = skSign.(slhdsa.PrivateKey)
		if !ok {
			return nil, ErrNotSLHDSAPrivateKey
		}
		return slhdsaSk, nil
	default:
		return nil, ErrInvalidKeyType
	}
}

func ParseSLHDSAPublicKeyFromPEM(alg string, key []byte) (any, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	var slhdsaPk any
	switch alg {
	case "SLH-DSA-SHA2-128f":
		pkSign, err := slhdsa.SHA2_128f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHA2-128s":
		pkSign, err := slhdsa.SHA2_128s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHA2-192f":
		pkSign, err := slhdsa.SHA2_192f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHA2-192s":
		pkSign, err := slhdsa.SHA2_192s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHA2-256f":
		pkSign, err := slhdsa.SHA2_256f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHA2-256s":
		pkSign, err := slhdsa.SHA2_256s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-128f":
		pkSign, err := slhdsa.SHAKE_128f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-128s":
		pkSign, err := slhdsa.SHAKE_128s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-192f":
		pkSign, err := slhdsa.SHAKE_192f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-192s":
		pkSign, err := slhdsa.SHAKE_192s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-256f":
		pkSign, err := slhdsa.SHAKE_256f.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	case "SLH-DSA-SHAKE-256s":
		pkSign, err := slhdsa.SHAKE_256s.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrNotSLHDSAPublicKey
		}
		var ok bool
		slhdsaPk, ok = pkSign.(slhdsa.PublicKey)
		if !ok {
			return nil, ErrNotSLHDSAPublicKey
		}
		return slhdsaPk, nil
	default:
		return nil, ErrInvalidKeyType
	}
}

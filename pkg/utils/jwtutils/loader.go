package jwtutils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

// LoadAlgConfig loads a single algorithm's configuration from PEM key files.
// keysDir is the directory containing key files.
// For signing (auth-service), pass signMode=true.
// For verification only (gateway), pass signMode=false.
func LoadAlgConfig(keysDir string, alg string, signMode bool) (*AlgConfig, error) {
	switch alg {
	case "Falcon-512":
		return loadFalconOriginal(keysDir, alg, signMode)
	case "Falcon-Precomputed-512":
		return loadFalconPrecomputed(keysDir, alg, signMode)
	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
		return loadMLDSA(keysDir, alg, signMode)
	case "SLH-DSA-SHA2-128f":
		return loadSLHDSA(keysDir, alg, signMode)
	case "ES256":
		return loadECDSA(keysDir, alg, signMode)
	case "RS256":
		return loadRSA(keysDir, alg, signMode)
	case "HS256":
		return loadHMAC(keysDir, alg, signMode)
	case "EdDSA":
		return loadEdDSA(keysDir, alg, signMode)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// LoadAllAlgConfigs loads configurations for all specified algorithms.
func LoadAllAlgConfigs(keysDir string, algs []string, signMode bool) (map[string]*AlgConfig, error) {
	configs := make(map[string]*AlgConfig, len(algs))
	for _, alg := range algs {
		cfg, err := LoadAlgConfig(keysDir, alg, signMode)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", alg, err)
		}
		configs[alg] = cfg
	}
	return configs, nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func loadFalconOriginal(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodFN512}

	// Public key for verification
	vkBytes, err := readFile(filepath.Join(keysDir, "FNDSA-512_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseFalconPublicKeyFromPEM(vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, "FNDSA-512_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseFalconPrivateKeyFromPEM(skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

func loadFalconPrecomputed(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}

	// Public key for verification
	vkBytes, err := readFile(filepath.Join(keysDir, "FNDSA-512_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseFalconPublicKeyFromPEM(vkBytes)
	if err != nil {
		return nil, err
	}

	cfg := &AlgConfig{Method: method, VerifyKey: vk}

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, "FNDSA-512_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseFalconPrivateKeyFromPEM(skBytes)
		if err != nil {
			return nil, err
		}
		signer, err := fndsa.NewPrecomputedSigner(sk)
		if err != nil {
			return nil, fmt.Errorf("precomputed signer: %w", err)
		}
		method.SetPrecomputedSigner(signer)
		cfg.SignKey = nil // signer embedded in method
	}
	return cfg, nil
}

func loadMLDSA(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	var method jwt.SigningMethod
	switch alg {
	case "ML-DSA-44":
		method = jwt.SigningMethodMLDSA44
	case "ML-DSA-65":
		method = jwt.SigningMethodMLDSA65
	case "ML-DSA-87":
		method = jwt.SigningMethodMLDSA87
	}

	cfg := &AlgConfig{Method: method}

	// Public key
	vkBytes, err := readFile(filepath.Join(keysDir, alg+"_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseMLDSAPublicKeyFromPEM(alg, vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, alg+"_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseMLDSAPrivateKeyFromPEM(alg, skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

func loadSLHDSA(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodSLHDSA_SHA2_128f}

	vkBytes, err := readFile(filepath.Join(keysDir, alg+"_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseSLHDSAPublicKeyFromPEM(alg, vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, alg+"_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseSLHDSAPrivateKeyFromPEM(alg, skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

func loadECDSA(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodES256}

	vkBytes, err := readFile(filepath.Join(keysDir, "ES256_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseECPublicKeyFromPEM(vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, "ES256_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseECPrivateKeyFromPEM(skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

func loadRSA(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodRS256}

	vkBytes, err := readFile(filepath.Join(keysDir, "RS256_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseRSAPublicKeyFromPEM(vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, "RS256_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseRSAPrivateKeyFromPEM(skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

func loadHMAC(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodHS256}

	// HMAC uses symmetric key (same for sign and verify)
	secretBytes, err := readFile(filepath.Join(keysDir, "HS256_secret.pem"))
	if err != nil {
		return nil, err
	}
	secret, err := jwt.ParseFalconPrivateKeyFromPEM(secretBytes) // reuse PEM decoder for raw bytes
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = secret

	if signMode {
		cfg.SignKey = secret
	}
	return cfg, nil
}

func loadEdDSA(keysDir, alg string, signMode bool) (*AlgConfig, error) {
	cfg := &AlgConfig{Method: jwt.SigningMethodEdDSA}

	vkBytes, err := readFile(filepath.Join(keysDir, "EdDSA_pk.pem"))
	if err != nil {
		return nil, err
	}
	vk, err := jwt.ParseEdPublicKeyFromPEM(vkBytes)
	if err != nil {
		return nil, err
	}
	cfg.VerifyKey = vk

	if signMode {
		skBytes, err := readFile(filepath.Join(keysDir, "EdDSA_sk.pem"))
		if err != nil {
			return nil, err
		}
		sk, err := jwt.ParseEdPrivateKeyFromPEM(skBytes)
		if err != nil {
			return nil, err
		}
		cfg.SignKey = sk
	}
	return cfg, nil
}

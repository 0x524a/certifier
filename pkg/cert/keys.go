package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// GeneratePrivateKey generates a private key based on the specified key type
func GeneratePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyTypeEd25519:
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, err
	default:
		// Default to RSA 2048
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}

// GetPublicKey extracts the public key from a private key
func GetPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return key.Public(), nil
	case *ecdsa.PrivateKey:
		return key.Public(), nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// GetKeySize returns the size in bits of a private key
func GetKeySize(privateKey crypto.PrivateKey) int {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return key.N.BitLen()
	case *ecdsa.PrivateKey:
		return key.D.BitLen()
	case ed25519.PrivateKey:
		return 256 // Ed25519 is always 256 bits
	default:
		return 0
	}
}

// GetSignatureAlgorithmForKey returns the appropriate signature algorithm for a key
func GetSignatureAlgorithmForKey(privateKey crypto.PrivateKey) (x509.SignatureAlgorithm, error) {
	return GetSignatureAlgorithmForKeyWithPSS(privateKey, false)
}

// GetSignatureAlgorithmForKeyWithPSS determines the appropriate signature algorithm with PSS option
func GetSignatureAlgorithmForKeyWithPSS(privateKey crypto.PrivateKey, usePSS bool) (x509.SignatureAlgorithm, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if usePSS {
			return x509.SHA256WithRSAPSS, nil
		}
		return x509.SHA256WithRSA, nil
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSAWithSHA384, nil
		case elliptic.P521():
			return x509.ECDSAWithSHA512, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported curve: %v", key.Curve)
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

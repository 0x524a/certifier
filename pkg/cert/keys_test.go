package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestGeneratePrivateKeyErrorHandling(t *testing.T) {
	// Test that invalid key type defaults to RSA 2048
	key, err := GeneratePrivateKey("invalid-type")
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed for invalid type: %v", err)
	}

	// Verify it's an RSA key
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("Expected RSA key for invalid key type, got %T", key)
		return
	}

	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected RSA 2048, got %d bits", rsaKey.N.BitLen())
	}
}

func TestGetPublicKeyExtractRSA(t *testing.T) {
	key, err := GeneratePrivateKey(KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey, err := GetPublicKey(key)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	// Verify it's an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Expected RSA public key, got %T", pubKey)
		return
	}

	if rsaPubKey.E == 0 {
		t.Errorf("Expected valid RSA public key with E set")
	}
}

func TestGetPublicKeyExtractECDSA(t *testing.T) {
	key, err := GeneratePrivateKey(KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey, err := GetPublicKey(key)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	// Verify it's an ECDSA public key
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("Expected ECDSA public key, got %T", pubKey)
		return
	}

	if ecdsaPubKey.Curve == nil {
		t.Errorf("Expected valid ECDSA public key with Curve set")
	}
}

func TestGetPublicKeyExtractEd25519(t *testing.T) {
	key, err := GeneratePrivateKey(KeyTypeEd25519)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey, err := GetPublicKey(key)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	// Verify it's an Ed25519 public key
	ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Errorf("Expected Ed25519 public key, got %T", pubKey)
		return
	}

	if len(ed25519PubKey) != ed25519.PublicKeySize {
		t.Errorf("Expected Ed25519 public key of size %d, got %d", ed25519.PublicKeySize, len(ed25519PubKey))
	}
}

func TestGetKeySizeWithUnsupportedKeyType(t *testing.T) {
	// Test with unsupported key type
	type unsupportedKey struct {
		data string
	}

	unsupported := unsupportedKey{data: "not a valid key"}
	size := GetKeySize(unsupported)

	if size != 0 {
		t.Errorf("Expected 0 for unsupported key type, got %d", size)
	}
}

func TestGetSignatureAlgorithmForKeyWithUnsupportedKeyType(t *testing.T) {
	// Test with unsupported key type
	type unsupportedKey struct {
		data string
	}

	unsupported := unsupportedKey{data: "not a valid key"}
	algo, err := GetSignatureAlgorithmForKey(unsupported)

	if err == nil {
		t.Errorf("Expected error for unsupported key type")
	}

	if algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("Expected UnknownSignatureAlgorithm, got %v", algo)
	}
}

func TestGetSignatureAlgorithmForKeyWithPSSUnsupportedKeyType(t *testing.T) {
	// Test with unsupported key type
	type unsupportedKey struct {
		data string
	}

	unsupported := unsupportedKey{data: "not a valid key"}
	algo, err := GetSignatureAlgorithmForKeyWithPSS(unsupported, true)

	if err == nil {
		t.Errorf("Expected error for unsupported key type")
	}

	if algo != x509.UnknownSignatureAlgorithm {
		t.Errorf("Expected UnknownSignatureAlgorithm, got %v", algo)
	}
}

func TestGetSignatureAlgorithmForKeyWithPSSRSA(t *testing.T) {
	// Test PSS variant for RSA keys
	key, err := GeneratePrivateKey(KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Without PSS
	algo1, err := GetSignatureAlgorithmForKeyWithPSS(key, false)
	if err != nil {
		t.Fatalf("GetSignatureAlgorithmForKeyWithPSS failed: %v", err)
	}

	if algo1 != x509.SHA256WithRSA {
		t.Errorf("Expected SHA256WithRSA, got %v", algo1)
	}

	// With PSS
	algo2, err := GetSignatureAlgorithmForKeyWithPSS(key, true)
	if err != nil {
		t.Fatalf("GetSignatureAlgorithmForKeyWithPSS failed: %v", err)
	}

	if algo2 != x509.SHA256WithRSAPSS {
		t.Errorf("Expected SHA256WithRSAPSS, got %v", algo2)
	}
}

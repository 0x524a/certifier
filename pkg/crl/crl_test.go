package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/0x524a/certifier/pkg/cert"
)

func TestGenerateCRL(t *testing.T) {
	// Generate CA for CRL signing
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tests := []struct {
		name    string
		config  *CRLConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing CA certificate",
			config: &CRLConfig{
				CAKeyPair: &keyPair{PrivateKey: caKey},
			},
			wantErr: true,
		},
		{
			name: "missing CA private key",
			config: &CRLConfig{
				CACertificate: caCert,
				CAKeyPair:     nil,
			},
			wantErr: true,
		},
		{
			name: "valid empty CRL",
			config: &CRLConfig{
				CACertificate: caCert,
				CAKeyPair:     &keyPair{PrivateKey: caKey},
				ValidityDays:  30,
				Number:        1,
			},
			wantErr: false,
		},
		{
			name: "valid CRL with revoked certificates",
			config: &CRLConfig{
				CACertificate: caCert,
				CAKeyPair:     &keyPair{PrivateKey: caKey},
				RevokedCerts: []*RevokedCertificate{
					{
						SerialNumber:     big.NewInt(123),
						RevocationTime:   time.Now(),
						RevocationReason: ReasonKeyCompromise,
					},
					{
						SerialNumber:     big.NewInt(456),
						RevocationTime:   time.Now(),
						RevocationReason: ReasonSuperseded,
					},
				},
				ValidityDays: 30,
				Number:       1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crlBytes, err := GenerateCRL(tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCRL error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(crlBytes) == 0 {
				t.Errorf("Expected non-empty CRL bytes")
			}
		})
	}
}

func TestParseCRL(t *testing.T) {
	// Generate CA and CRL
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	crlConfig := &CRLConfig{
		CACertificate: caCert,
		CAKeyPair:     &keyPair{PrivateKey: caKey},
		RevokedCerts: []*RevokedCertificate{
			{
				SerialNumber:   big.NewInt(100),
				RevocationTime: time.Now(),
			},
		},
		ValidityDays: 30,
		Number:       1,
	}

	crlBytes, err := GenerateCRL(crlConfig)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	// Test parsing
	tests := []struct {
		name    string
		crlData []byte
		wantErr bool
	}{
		{
			name:    "valid CRL",
			crlData: crlBytes,
			wantErr: false,
		},
		{
			name:    "empty CRL data",
			crlData: []byte{},
			wantErr: true,
		},
		{
			name:    "invalid CRL data",
			crlData: []byte("not a valid CRL"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedCRL, err := ParseCRL(tt.crlData)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCRL error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && parsedCRL == nil {
				t.Errorf("Expected non-nil parsed CRL")
			}
		})
	}
}

func TestCheckRevocation(t *testing.T) {
	// Generate CA and two certificates
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate two leaf certificates
	leafCfg1 := &cert.CertificateConfig{
		CommonName:   "cert1.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	cert1, _, err := cert.GenerateCASignedCertificate(leafCfg1, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate cert1: %v", err)
	}

	leafCfg2 := &cert.CertificateConfig{
		CommonName:   "cert2.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	cert2, _, err := cert.GenerateCASignedCertificate(leafCfg2, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate cert2: %v", err)
	}

	// Create CRL with cert1 revoked
	crlConfig := &CRLConfig{
		CACertificate: caCert,
		CAKeyPair:     &keyPair{PrivateKey: caKey},
		RevokedCerts: []*RevokedCertificate{
			{
				SerialNumber:   cert1.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
		ValidityDays: 30,
		Number:       1,
	}

	crlBytes, err := GenerateCRL(crlConfig)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crl, err := ParseCRL(crlBytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		crl     *x509.RevocationList
		revoked bool
	}{
		{
			name:    "revoked certificate",
			cert:    cert1,
			crl:     crl,
			revoked: true,
		},
		{
			name:    "non-revoked certificate",
			cert:    cert2,
			crl:     crl,
			revoked: false,
		},
		{
			name:    "nil certificate",
			cert:    nil,
			crl:     crl,
			revoked: false,
		},
		{
			name:    "nil CRL",
			cert:    cert1,
			crl:     nil,
			revoked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revoked := CheckRevocation(tt.cert, tt.crl)
			if revoked != tt.revoked {
				t.Errorf("CheckRevocation returned %v, expected %v", revoked, tt.revoked)
			}
		})
	}
}

func TestRevocationReasonConstants(t *testing.T) {
	// Verify all revocation reason constants are defined
	reasons := []int{
		ReasonUnspecified,
		ReasonKeyCompromise,
		ReasonCACompromise,
		ReasonAffiliationChanged,
		ReasonSuperseded,
		ReasonCessationOfOperation,
		ReasonCertificateHold,
		ReasonRemoveFromCRL,
		ReasonPrivilegeWithdrawn,
		ReasonAACompromise,
	}

	expectedValues := []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 10}

	for i, reason := range reasons {
		if reason != expectedValues[i] {
			t.Errorf("Reason %d expected value %d, got %d", i, expectedValues[i], reason)
		}
	}
}

func TestSimpleSignerPublic(t *testing.T) {
	// Test with RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signer := &simpleSigner{pk: privateKey}
	pubKey := signer.Public()

	if pubKey == nil {
		t.Errorf("Expected non-nil public key")
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Expected RSA public key")
	}

	if !rsaPubKey.Equal(&privateKey.PublicKey) {
		t.Errorf("Public key mismatch")
	}
}

func TestSimpleSignerSign(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signer := &simpleSigner{pk: privateKey}

	// Test signing with hashed data
	data := []byte("test data")
	hash := crypto.SHA256
	hashFunc := hash.HashFunc()
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, digest, hash)

	if err != nil {
		t.Errorf("Sign returned error: %v", err)
	}

	if len(signature) == 0 {
		t.Errorf("Expected non-empty signature")
	}
}

func TestCRLValidity(t *testing.T) {
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tests := []struct {
		name         string
		validityDays int
	}{
		{name: "default validity (30 days)", validityDays: 0},
		{name: "7 days", validityDays: 7},
		{name: "60 days", validityDays: 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crlConfig := &CRLConfig{
				CACertificate: caCert,
				CAKeyPair:     &keyPair{PrivateKey: caKey},
				ValidityDays:  tt.validityDays,
				Number:        1,
			}

			crlBytes, err := GenerateCRL(crlConfig)
			if err != nil {
				t.Fatalf("Failed to generate CRL: %v", err)
			}

			crl, err := ParseCRL(crlBytes)
			if err != nil {
				t.Fatalf("Failed to parse CRL: %v", err)
			}

			if crl.ThisUpdate.IsZero() {
				t.Errorf("Expected non-zero ThisUpdate")
			}

			if crl.NextUpdate.IsZero() {
				t.Errorf("Expected non-zero NextUpdate")
			}

			if !crl.NextUpdate.After(crl.ThisUpdate) {
				t.Errorf("NextUpdate should be after ThisUpdate")
			}
		})
	}
}

func TestCRLWithMultipleRevocations(t *testing.T) {
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Create CRL with multiple revoked certs
	revokedCerts := make([]*RevokedCertificate, 10)
	for i := 0; i < 10; i++ {
		revokedCerts[i] = &RevokedCertificate{
			SerialNumber:   big.NewInt(int64(i + 1)),
			RevocationTime: time.Now(),
		}
	}

	crlConfig := &CRLConfig{
		CACertificate: caCert,
		CAKeyPair:     &keyPair{PrivateKey: caKey},
		RevokedCerts:  revokedCerts,
		ValidityDays:  30,
		Number:        1,
	}

	crlBytes, err := GenerateCRL(crlConfig)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crl, err := ParseCRL(crlBytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 10 {
		t.Errorf("Expected 10 revoked certificates, got %d", len(crl.RevokedCertificateEntries))
	}
}

func TestSimpleSignerSignWithPSS(t *testing.T) {
	// Test signing with RSA-PSS options
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signer := &simpleSigner{pk: privateKey}

	// Test signing with PSS options
	data := []byte("test data for PSS")
	hash := crypto.SHA256
	hashFunc := hash.HashFunc()
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}

	signature, err := signer.Sign(rand.Reader, digest, pssOpts)

	if err != nil {
		t.Errorf("Sign with PSS returned error: %v", err)
	}

	if len(signature) == 0 {
		t.Errorf("Expected non-empty signature with PSS")
	}
}

func TestSimpleSignerSignUnsupportedKeyType(t *testing.T) {
	// Test with an unsupported key type (not RSA)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a mock unsupported key type
	type unsupportedKey struct {
		key *rsa.PrivateKey
	}

	signer := &simpleSigner{pk: unsupportedKey{key: privateKey}}

	// Test signing with unsupported key
	data := []byte("test data")
	hash := crypto.SHA256
	hashFunc := hash.HashFunc()
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	_, err = signer.Sign(rand.Reader, digest, hash)

	if err == nil {
		t.Errorf("Expected error for unsupported key type")
	}
}

func TestSimpleSignerPublicWithPublicKeyMethod(t *testing.T) {
	// Test Public() method with a key that has Public() method
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a signer with RSA key that has Public() method
	signer := &simpleSigner{pk: privateKey}
	pubKey := signer.Public()

	if pubKey == nil {
		t.Errorf("Expected non-nil public key from RSA key")
	}
}

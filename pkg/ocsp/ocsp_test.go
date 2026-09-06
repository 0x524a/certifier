package ocsp

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x524a/certifier/pkg/cert"
	xocsp "golang.org/x/crypto/ocsp"
)

// testFixtures generates a self-signed CA and a leaf certificate signed by it,
// returning the CA cert/key and the leaf cert/key for use across OCSP tests.
func testFixtures(t *testing.T) (caCert *x509.Certificate, caKey interface{}, leafCert *x509.Certificate, leafKey interface{}) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, leafKey, err = cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	return caCert, caKey, leafCert, leafKey
}

func TestGenerateOCSPResponse(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	tests := []struct {
		name    string
		config  *OCSPConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing certificate",
			config: &OCSPConfig{
				Status: 0,
			},
			wantErr: true,
		},
		{
			name: "missing CA certificate",
			config: &OCSPConfig{
				Certificate: leafCert,
			},
			wantErr: true,
		},
		{
			name: "missing responder private key",
			config: &OCSPConfig{
				Certificate:   leafCert,
				CACertificate: caCert,
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			config: &OCSPConfig{
				Certificate:         leafCert,
				CACertificate:       caCert,
				ResponderPrivateKey: caKey,
				Status:              99,
			},
			wantErr: true,
		},
		{
			name: "valid good response, CA as responder",
			config: &OCSPConfig{
				Certificate:         leafCert,
				CACertificate:       caCert,
				ResponderPrivateKey: caKey,
				Status:              0,
				ThisUpdate:          time.Now(),
				NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			respBytes, err := GenerateOCSPResponse(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateOCSPResponse error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(respBytes) == 0 {
				t.Errorf("Expected non-empty response bytes")
			}
		})
	}
}

func TestOCSPRequestRoundTrip(t *testing.T) {
	caCert, _, leafCert, _ := testFixtures(t)

	reqBytes, err := CreateOCSPRequest(leafCert, caCert)
	if err != nil {
		t.Fatalf("CreateOCSPRequest failed: %v", err)
	}
	if len(reqBytes) == 0 {
		t.Fatalf("Expected non-empty request bytes")
	}

	parsed, err := ParseOCSPRequest(reqBytes)
	if err != nil {
		t.Fatalf("ParseOCSPRequest failed: %v", err)
	}

	if parsed["serialNumber"] == nil {
		t.Errorf("Expected serialNumber in parsed request")
	}
	if parsed["hashAlgorithm"] == nil {
		t.Errorf("Expected hashAlgorithm in parsed request")
	}
}

func TestCreateOCSPRequestErrors(t *testing.T) {
	caCert, _, leafCert, _ := testFixtures(t)

	tests := []struct {
		name    string
		cert    *x509.Certificate
		issuer  *x509.Certificate
		wantErr bool
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			issuer:  caCert,
			wantErr: true,
		},
		{
			name:    "nil issuer",
			cert:    leafCert,
			issuer:  nil,
			wantErr: true,
		},
		{
			name:    "valid",
			cert:    leafCert,
			issuer:  caCert,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateOCSPRequest(tt.cert, tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateOCSPRequest error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOCSPRequestErrors(t *testing.T) {
	_, err := ParseOCSPRequest([]byte{})
	if err == nil {
		t.Errorf("Expected error for empty request bytes")
	}

	_, err = ParseOCSPRequest([]byte("not a valid der request"))
	if err == nil {
		t.Errorf("Expected error for malformed request bytes")
	}
}

func TestGenerateAndParseOCSPResponse_Good(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	config := &OCSPConfig{
		Certificate:         leafCert,
		CACertificate:       caCert,
		ResponderPrivateKey: caKey,
		Status:              0,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	respBytes, err := GenerateOCSPResponse(config)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse failed: %v", err)
	}

	result, err := ParseOCSPResponse(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	if result["status"] != "good" {
		t.Errorf("Expected status 'good', got %v", result["status"])
	}
	if result["serialNumber"] == nil {
		t.Errorf("Expected serialNumber in parsed response")
	}
}

func TestGenerateAndParseOCSPResponse_Revoked(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	revokedAt := time.Now().Add(-24 * time.Hour)
	config := &OCSPConfig{
		Certificate:         leafCert,
		CACertificate:       caCert,
		ResponderPrivateKey: caKey,
		Status:              1,
		RevocationTime:      revokedAt,
		RevocationReason:    1, // key compromise
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	respBytes, err := GenerateOCSPResponse(config)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse failed: %v", err)
	}

	result, err := ParseOCSPResponse(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	if result["status"] != "revoked" {
		t.Errorf("Expected status 'revoked', got %v", result["status"])
	}
	if result["revokedAt"] == nil {
		t.Errorf("Expected revokedAt in parsed response")
	}
	if result["revocationReason"] != 1 {
		t.Errorf("Expected revocationReason 1, got %v", result["revocationReason"])
	}
}

func TestGenerateAndParseOCSPResponse_Unknown(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	config := &OCSPConfig{
		Certificate:         leafCert,
		CACertificate:       caCert,
		ResponderPrivateKey: caKey,
		Status:              2,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	respBytes, err := GenerateOCSPResponse(config)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse failed: %v", err)
	}

	result, err := ParseOCSPResponse(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	if result["status"] != "unknown" {
		t.Errorf("Expected status 'unknown', got %v", result["status"])
	}
}

func TestParseOCSPResponseErrors(t *testing.T) {
	caCert, _, _, _ := testFixtures(t)

	_, err := ParseOCSPResponse([]byte{}, caCert)
	if err == nil {
		t.Errorf("Expected error for empty response bytes")
	}

	_, err = ParseOCSPResponse([]byte("test"), nil)
	if err == nil {
		t.Errorf("Expected error for nil issuer")
	}

	_, err = ParseOCSPResponse([]byte("not a valid der response"), caCert)
	if err == nil {
		t.Errorf("Expected error for malformed response bytes")
	}
}

func TestVerifyOCSPResponse(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	config := &OCSPConfig{
		Certificate:         leafCert,
		CACertificate:       caCert,
		ResponderPrivateKey: caKey,
		Status:              0,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	respBytes, err := GenerateOCSPResponse(config)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse failed: %v", err)
	}

	tests := []struct {
		name      string
		respBytes []byte
		cert      *x509.Certificate
		issuer    *x509.Certificate
		wantErr   bool
	}{
		{
			name:      "nil certificate",
			respBytes: respBytes,
			cert:      nil,
			issuer:    caCert,
			wantErr:   true,
		},
		{
			name:      "nil issuer",
			respBytes: respBytes,
			cert:      leafCert,
			issuer:    nil,
			wantErr:   true,
		},
		{
			name:      "valid response verifies successfully",
			respBytes: respBytes,
			cert:      leafCert,
			issuer:    caCert,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := VerifyOCSPResponse(tt.respBytes, tt.cert, tt.issuer)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOCSPResponse error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Errorf("Expected non-nil result")
					return
				}
				if result["verified"] != true {
					t.Errorf("Expected verified=true, got %v", result["verified"])
				}
				if result["status"] != "good" {
					t.Errorf("Expected status 'good', got %v", result["status"])
				}
			}
		})
	}
}

func TestVerifyOCSPResponse_WrongCertificate(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)

	// Generate a second, unrelated leaf certificate signed by the same CA.
	otherCfg := &cert.CertificateConfig{
		CommonName:   "other.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}
	otherCert, _, err := cert.GenerateCASignedCertificate(otherCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate other cert: %v", err)
	}

	config := &OCSPConfig{
		Certificate:         leafCert,
		CACertificate:       caCert,
		ResponderPrivateKey: caKey,
		Status:              0,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	respBytes, err := GenerateOCSPResponse(config)
	if err != nil {
		t.Fatalf("GenerateOCSPResponse failed: %v", err)
	}

	// The response is for leafCert, not otherCert - verification against
	// otherCert should fail.
	result, err := VerifyOCSPResponse(respBytes, otherCert, caCert)
	if err == nil {
		t.Errorf("Expected error when verifying response against the wrong certificate")
	}
	if result != nil && result["verified"] == true {
		t.Errorf("Expected verified=false for mismatched certificate")
	}
}

// newOCSPTestResponder starts an httptest.Server that acts as a real OCSP
// responder: it parses the incoming DER request, signs a response for the
// requested status using the package's own GenerateOCSPResponse, and writes
// it back. httpStatus/rawBody override the response for failure-path tests.
func newOCSPTestResponder(t *testing.T, caCert *x509.Certificate, caKey interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBytes, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ocspReq, err := xocsp.ParseRequest(reqBytes)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		respBytes, err := GenerateOCSPResponse(&OCSPConfig{
			ResponderCertificate: caCert,
			ResponderPrivateKey:  caKey,
			CACertificate:        caCert,
			Certificate:          &x509.Certificate{SerialNumber: ocspReq.SerialNumber},
			Status:               status,
			ThisUpdate:           time.Now(),
			NextUpdate:           time.Now().Add(24 * time.Hour),
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
}

func TestCheckCertificateStatusGood(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)
	server := newOCSPTestResponder(t, caCert, caKey, 0)
	defer server.Close()

	status, err := CheckCertificateStatus(leafCert, caCert, server.URL)
	if err != nil {
		t.Fatalf("CheckCertificateStatus failed: %v", err)
	}
	if status.Status != "good" {
		t.Errorf("Status = %q, want %q", status.Status, "good")
	}
	if status.Serial.Cmp(leafCert.SerialNumber) != 0 {
		t.Errorf("Serial number mismatch in status")
	}
	if status.ResponderURL != server.URL {
		t.Errorf("ResponderURL = %q, want %q", status.ResponderURL, server.URL)
	}
	if status.NextUpdate.Before(status.ThisUpdate) {
		t.Errorf("NextUpdate should not be before ThisUpdate")
	}
}

func TestCheckCertificateStatusRevoked(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)
	server := newOCSPTestResponder(t, caCert, caKey, 1)
	defer server.Close()

	status, err := CheckCertificateStatus(leafCert, caCert, server.URL)
	if err != nil {
		t.Fatalf("CheckCertificateStatus failed: %v", err)
	}
	if status.Status != "revoked" {
		t.Errorf("Status = %q, want %q", status.Status, "revoked")
	}
}

func TestCheckCertificateStatusAIAFallback(t *testing.T) {
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

	server := newOCSPTestResponder(t, caCert, caKey, 0)
	defer server.Close()

	leafCfg := &cert.CertificateConfig{
		CommonName:   "aia.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
		OCSPServer:   []string{server.URL},
	}
	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}
	if len(leafCert.OCSPServer) != 1 {
		t.Fatalf("expected leaf cert to carry an OCSP AIA entry, got %v", leafCert.OCSPServer)
	}

	// Passing an empty ocspURL must fall back to the certificate's AIA entry.
	status, err := CheckCertificateStatus(leafCert, caCert, "")
	if err != nil {
		t.Fatalf("CheckCertificateStatus failed: %v", err)
	}
	if status.ResponderURL != server.URL {
		t.Errorf("ResponderURL = %q, want AIA URL %q", status.ResponderURL, server.URL)
	}
}

func TestCheckCertificateStatusErrors(t *testing.T) {
	caCert, caKey, leafCert, _ := testFixtures(t)
	server := newOCSPTestResponder(t, caCert, caKey, 0)
	defer server.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badServer.Close()

	garbageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a valid ocsp response"))
	}))
	defer garbageServer.Close()

	tests := []struct {
		name    string
		cert    *x509.Certificate
		issuer  *x509.Certificate
		ocspURL string
	}{
		{name: "nil certificate", cert: nil, issuer: caCert, ocspURL: server.URL},
		{name: "nil issuer", cert: leafCert, issuer: nil, ocspURL: server.URL},
		{name: "no url and no AIA", cert: leafCert, issuer: caCert, ocspURL: ""},
		{name: "non-200 response", cert: leafCert, issuer: caCert, ocspURL: badServer.URL},
		{name: "unparsable response body", cert: leafCert, issuer: caCert, ocspURL: garbageServer.URL},
		{name: "unreachable responder", cert: leafCert, issuer: caCert, ocspURL: "http://127.0.0.1:0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CheckCertificateStatus(tt.cert, tt.issuer, tt.ocspURL); err == nil {
				t.Errorf("expected an error, got nil")
			}
		})
	}
}

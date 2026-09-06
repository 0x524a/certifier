package ocsp

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPConfig holds configuration for OCSP responder
type OCSPConfig struct {
	// OCSP responder certificate (should be signed by CA)
	ResponderCertificate *x509.Certificate

	// OCSP responder private key
	ResponderPrivateKey crypto.PrivateKey

	// CA certificate
	CACertificate *x509.Certificate

	// Certificate to create response for
	Certificate *x509.Certificate

	// Certificate status (0 = good, 1 = revoked, 2 = unknown)
	Status int

	// Revocation time (if revoked)
	RevocationTime time.Time

	// Revocation reason (if revoked)
	RevocationReason int

	// This update time
	ThisUpdate time.Time

	// Next update time
	NextUpdate time.Time
}

// GenerateOCSPResponse generates a signed OCSP response for the certificate described by config.
func GenerateOCSPResponse(config *OCSPConfig) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("OCSP config is required")
	}
	if config.Certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if config.CACertificate == nil {
		return nil, fmt.Errorf("CA certificate is required")
	}
	if config.ResponderPrivateKey == nil {
		return nil, fmt.Errorf("responder private key is required")
	}

	signer, ok := config.ResponderPrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("responder private key does not implement crypto.Signer")
	}

	responderCert := config.ResponderCertificate
	if responderCert == nil {
		// No dedicated responder certificate: the CA itself is acting as the responder.
		responderCert = config.CACertificate
	}

	status, err := statusToOCSP(config.Status)
	if err != nil {
		return nil, err
	}

	thisUpdate := config.ThisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now()
	}

	template := ocsp.Response{
		Status:           status,
		SerialNumber:     config.Certificate.SerialNumber,
		ThisUpdate:       thisUpdate,
		NextUpdate:       config.NextUpdate,
		RevocationReason: config.RevocationReason,
	}
	if status == ocsp.Revoked {
		template.RevokedAt = config.RevocationTime
	}

	respBytes, err := ocsp.CreateResponse(config.CACertificate, responderCert, template, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", err)
	}

	return respBytes, nil
}

// ParseOCSPResponse parses an OCSP response, verifying its signature against issuer.
func ParseOCSPResponse(respBytes []byte, issuer *x509.Certificate) (map[string]interface{}, error) {
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("OCSP response is empty")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}

	resp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return responseToMap(resp), nil
}

// VerifyOCSPResponse parses and verifies an OCSP response against the given certificate and issuer.
func VerifyOCSPResponse(
	respBytes []byte,
	cert *x509.Certificate,
	issuer *x509.Certificate,
) (map[string]interface{}, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("certificate and issuer are required")
	}
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("OCSP response is empty")
	}

	resp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return map[string]interface{}{"verified": false}, fmt.Errorf("failed to verify OCSP response: %w", err)
	}

	result := responseToMap(resp)
	result["verified"] = true
	return result, nil
}

// CreateOCSPRequest creates a DER-encoded OCSP request for cert, issued by issuer.
func CreateOCSPRequest(cert *x509.Certificate, issuer *x509.Certificate) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("certificate and issuer are required")
	}

	reqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	return reqBytes, nil
}

// ParseOCSPRequest parses a DER-encoded OCSP request.
func ParseOCSPRequest(reqBytes []byte) (map[string]interface{}, error) {
	if len(reqBytes) == 0 {
		return nil, fmt.Errorf("OCSP request is empty")
	}

	req, err := ocsp.ParseRequest(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %w", err)
	}

	return map[string]interface{}{
		"serialNumber":  req.SerialNumber,
		"hashAlgorithm": req.HashAlgorithm,
	}, nil
}

// statusToOCSP maps the OCSPConfig.Status int (0=good,1=revoked,2=unknown) to the
// corresponding golang.org/x/crypto/ocsp status constant.
func statusToOCSP(status int) (int, error) {
	switch status {
	case 0:
		return ocsp.Good, nil
	case 1:
		return ocsp.Revoked, nil
	case 2:
		return ocsp.Unknown, nil
	default:
		return 0, fmt.Errorf("invalid OCSP status: %d", status)
	}
}

// statusToString converts an x/crypto/ocsp status constant to its string representation.
func statusToString(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// responseToMap converts a parsed *ocsp.Response into the map[string]interface{} result
// shape returned by ParseOCSPResponse and VerifyOCSPResponse.
func responseToMap(resp *ocsp.Response) map[string]interface{} {
	result := map[string]interface{}{
		"status":       statusToString(resp.Status),
		"serialNumber": resp.SerialNumber,
		"thisUpdate":   resp.ThisUpdate,
		"nextUpdate":   resp.NextUpdate,
		"producedAt":   resp.ProducedAt,
	}

	if resp.Status == ocsp.Revoked {
		result["revokedAt"] = resp.RevokedAt
		result["revocationReason"] = resp.RevocationReason
	}

	return result
}

// OCSPCertificateStatus represents the status of a certificate in OCSP
type OCSPCertificateStatus struct {
	Serial           *big.Int
	Status           string // "good", "revoked", or "unknown"
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevocationTime   time.Time
	RevocationReason string
	ResponderURL     string
	ProducedAt       time.Time
}

// CheckCertificateStatus checks the status of a certificate via OCSP
func CheckCertificateStatus(
	cert *x509.Certificate,
	ocspURL string,
) (*OCSPCertificateStatus, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if ocspURL == "" {
		return nil, fmt.Errorf("OCSP URL is required")
	}

	// NOTE: This does not perform the network round-trip to the OCSP responder.
	// A full client implementation would build a request with CreateOCSPRequest,
	// POST it to ocspURL (Content-Type: application/ocsp-request), and parse the
	// response with ParseOCSPResponse/VerifyOCSPResponse. That network I/O is not
	// implemented here.
	status := &OCSPCertificateStatus{
		Serial:       cert.SerialNumber,
		Status:       "unknown",
		ResponderURL: ocspURL,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(7 * 24 * time.Hour),
	}

	return status, nil
}

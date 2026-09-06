package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspHTTPClient is used to POST OCSP requests to responders. A package-level
// client (rather than http.DefaultClient) keeps the timeout local to this
// package instead of mutating shared global state.
var ocspHTTPClient = &http.Client{Timeout: 10 * time.Second}

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

// CheckCertificateStatus checks the status of a certificate by building an OCSP
// request, POSTing it to the responder, and verifying the signed response
// against issuer. If ocspURL is empty, the responder URL is taken from cert's
// Authority Information Access extension (cert.OCSPServer).
func CheckCertificateStatus(
	cert *x509.Certificate,
	issuer *x509.Certificate,
	ocspURL string,
) (*OCSPCertificateStatus, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}

	if ocspURL == "" {
		if len(cert.OCSPServer) == 0 {
			return nil, fmt.Errorf("OCSP URL is required: no --url given and the certificate has no OCSP AIA entry")
		}
		ocspURL = cert.OCSPServer[0]
	}

	reqBytes, err := CreateOCSPRequest(cert, issuer)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to build OCSP HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	httpResp, err := ocspHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to reach OCSP responder %s: %w", ocspURL, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder %s returned HTTP %d", ocspURL, httpResp.StatusCode)
	}

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response body: %w", err)
	}

	resp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to verify OCSP response from %s: %w", ocspURL, err)
	}

	status := &OCSPCertificateStatus{
		Serial:       resp.SerialNumber,
		Status:       statusToString(resp.Status),
		ResponderURL: ocspURL,
		ThisUpdate:   resp.ThisUpdate,
		NextUpdate:   resp.NextUpdate,
		ProducedAt:   resp.ProducedAt,
	}
	if resp.Status == ocsp.Revoked {
		status.RevocationTime = resp.RevokedAt
		status.RevocationReason = fmt.Sprintf("%d", resp.RevocationReason)
	}

	return status, nil
}

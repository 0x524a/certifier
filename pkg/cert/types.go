package cert

import (
	"crypto/x509"
	"net"
	"time"
)

// KeyType represents the type of cryptographic key to use
type KeyType string

const (
	// KeyTypeRSA2048 - RSA key with 2048 bits
	KeyTypeRSA2048 KeyType = "rsa2048"
	// KeyTypeRSA4096 - RSA key with 4096 bits
	KeyTypeRSA4096 KeyType = "rsa4096"
	// KeyTypeECDSAP256 - ECDSA key with P-256 curve
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	// KeyTypeECDSAP384 - ECDSA key with P-384 curve
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	// KeyTypeECDSAP521 - ECDSA key with P-521 curve
	KeyTypeECDSAP521 KeyType = "ecdsa-p521"
	// KeyTypeEd25519 - Ed25519 key
	KeyTypeEd25519 KeyType = "ed25519"
)

// CertificateType represents the type of certificate being generated
type CertificateType string

const (
	// CertTypeClient - Client certificate (client authentication)
	CertTypeClient CertificateType = "client"
	// CertTypeServer - Server certificate (server authentication)
	CertTypeServer CertificateType = "server"
	// CertTypeBoth - Certificate for both client and server authentication
	CertTypeBoth CertificateType = "both"
)

// CertificateConfig holds configuration for certificate generation
type CertificateConfig struct {
	// Required
	CommonName string

	// Optional subject information
	Country            string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string

	// Key configuration
	KeyType KeyType // Defaults to RSA2048

	// Certificate type (client, server, or both)
	CertType CertificateType // Defaults to "server" for non-CA certs

	// Certificate validity
	Validity int // Validity period in days

	// For server certificates
	DNSNames    []string
	IPAddresses []net.IP

	// For client certificates
	EmailAddresses []string

	// CA certificate specific
	IsCA          bool
	MaxPathLength int // -1 for unlimited

	// Extensions
	KeyUsage                x509.KeyUsage
	ExtendedKeyUsage        []x509.ExtKeyUsage
	ExtendedKeyUsageOIDs    []string // Custom EKU OIDs (e.g., "2.5.29.37.0" for module signing)
	BasicConstraintsValid   bool
	CRLDistributionPoints   []string
	OCSPServer              []string
	IssuingCertificateURL   []string
	AuthorityInfoAccessOCSP []string

	// Subject Key Identifier and Authority Key Identifier are auto-generated

	// UseRSAPSS enables RSA-PSS signature algorithm for enhanced security (only for RSA keys)
	// RSA-PSS provides better security properties than PKCS#1 v1.5:
	// - Uses randomized padding (probabilistic) making it resistant to certain attacks
	// - Recommended for new deployments and security-critical applications
	// - If false, uses PKCS#1 v1.5 (default for backward compatibility)
	// Note: Certificates signed with PSS require the verifier to support PSS
	UseRSAPSS bool
}

// KeyPair holds a private and public key pair
type KeyPair struct {
	PrivateKey interface{} // *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey
	PublicKey  interface{}
}

// CertificateChain represents a certificate and its chain
type CertificateChain struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate // Root CA to leaf certificate
}

// CSRConfig holds configuration for Certificate Signing Request
type CSRConfig struct {
	CommonName   string
	Country      string
	Organization string
	KeyType      KeyType
	DNSNames     []string
	IPAddresses  []net.IP
}

// RevocationInfo holds information for certificate revocation
type RevocationInfo struct {
	Certificate      *x509.Certificate
	RevocationTime   time.Time
	RevocationReason int // CRL reason code
}

// SigningConfig holds configuration for signing operations
type SigningConfig struct {
	// Signer CA certificate
	CAConfig *CertificateConfig

	// The key pair for the CA
	CAKeyPair *KeyPair

	// Certificate to sign
	CSRCert *x509.CertificateRequest

	// Configuration for the certificate to be signed
	CertConfig *CertificateConfig

	// Serial number for the new certificate
	SerialNumber int64
}

// ValidationConfig holds configuration for certificate validation
type ValidationConfig struct {
	// Root CA certificates for chain validation
	RootCAs []*x509.Certificate

	// Intermediate certificates
	IntermediateCAs []*x509.Certificate

	// Check expiration
	CheckExpiration bool

	// Current time for validation (defaults to now)
	CurrentTime time.Time

	// DNS name to verify (for hostname verification)
	DNSName string

	// Allow expired certificates
	AllowExpired bool
}

// ValidationResult holds the result of certificate validation
type ValidationResult struct {
	Valid              bool
	Errors             []string
	Warnings           []string
	ChainValid         bool
	NotExpired         bool
	HostnameValid      bool
	PurposeValid       bool
	CRLDistributionURL string
	OCSPURL            string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	ExpiresIn          time.Duration
	ValidFrom          time.Time
	ValidUntil         time.Time
}

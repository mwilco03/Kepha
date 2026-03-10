package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CertInfo describes a managed certificate and its metadata.
type CertInfo struct {
	Serial    string    `json:"serial"`
	Domains   []string  `json:"domains"`
	IPs       []string  `json:"ips,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path"`
	Issuer    string    `json:"issuer"` // "internal-ca", "self-signed", "acme"
	Revoked   bool      `json:"revoked"`
}

// certInventory is the on-disk JSON structure for tracking all managed certs.
type certInventory struct {
	Certs []CertInfo `json:"certs"`
}

// CertStore provides an internal Certificate Authority and certificate
// management service for Gatekeeper. It can:
//   - Generate a root CA cert/key for signing server certificates
//   - Issue ECDSA P-256 server certificates signed by the internal CA
//   - Generate standalone self-signed certificates
//   - Provision certificates via ACME (Let's Encrypt) HTTP-01 challenges
//   - Track all certificates with expiry metadata
//   - Auto-renew certificates before they expire
//   - Export the CA cert for importing into browsers and devices
type CertStore struct {
	mu     sync.Mutex
	state  State
	cfg    map[string]string
	stopCh chan struct{}

	caDir   string
	certDir string

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	inventory certInventory

	// acmeChallenge stores pending HTTP-01 challenge tokens.
	// Key: token path, Value: key authorization.
	acmeChallenge sync.Map
}

// NewCertStore creates a new certificate store service.
func NewCertStore() *CertStore {
	return &CertStore{
		state: StateStopped,
	}
}

func (cs *CertStore) Name() string        { return "certstore" }
func (cs *CertStore) DisplayName() string { return "Certificate Store" }
func (cs *CertStore) Category() string    { return "security" }
func (cs *CertStore) Dependencies() []string {
	return nil
}

func (cs *CertStore) Description() string {
	return "Internal CA and certificate management. Generates a root CA for signing server certificates, supports self-signed certs and ACME/Let's Encrypt provisioning, with auto-renewal and certificate inventory tracking."
}

func (cs *CertStore) DefaultConfig() map[string]string {
	return map[string]string{
		"ca_dir":            "/var/lib/gatekeeper/ca",
		"cert_dir":          "/var/lib/gatekeeper/certs",
		"ca_cn":             "Gatekeeper Internal CA",
		"ca_org":            "Gatekeeper",
		"ca_validity_years": "10",
		"cert_validity_days": "365",
		"acme_email":        "",
		"acme_directory":    "https://acme-v02.api.letsencrypt.org/directory",
		"auto_renew":        "true",
		"renew_before_days": "30",
	}
}

func (cs *CertStore) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"ca_dir":            {Description: "Directory for CA certificate and key storage", Default: "/var/lib/gatekeeper/ca", Required: true, Type: "path"},
		"cert_dir":          {Description: "Directory for generated certificates", Default: "/var/lib/gatekeeper/certs", Required: true, Type: "path"},
		"ca_cn":             {Description: "Common Name for the internal CA certificate", Default: "Gatekeeper Internal CA", Type: "string"},
		"ca_org":            {Description: "Organization name for the CA certificate", Default: "Gatekeeper", Type: "string"},
		"ca_validity_years": {Description: "CA certificate validity period in years", Default: "10", Type: "int"},
		"cert_validity_days": {Description: "Server certificate validity period in days", Default: "365", Type: "int"},
		"acme_email":        {Description: "Email address for ACME (Let's Encrypt) registration", Type: "string"},
		"acme_directory":    {Description: "ACME directory URL", Default: "https://acme-v02.api.letsencrypt.org/directory", Type: "string"},
		"auto_renew":        {Description: "Enable automatic certificate renewal before expiry", Default: "true", Type: "bool"},
		"renew_before_days": {Description: "Renew certificates this many days before expiry", Default: "30", Type: "int"},
	}
}

func (cs *CertStore) Validate(cfg map[string]string) error {
	if dir := cfg["ca_dir"]; dir == "" {
		return fmt.Errorf("ca_dir is required")
	}
	if dir := cfg["cert_dir"]; dir == "" {
		return fmt.Errorf("cert_dir is required")
	}
	if v := cfg["ca_validity_years"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return fmt.Errorf("ca_validity_years must be between 1 and 100")
		}
	}
	if v := cfg["cert_validity_days"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			return fmt.Errorf("cert_validity_days must be between 1 and 3650")
		}
	}
	if v := cfg["renew_before_days"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			return fmt.Errorf("renew_before_days must be between 1 and 365")
		}
	}
	if v := cfg["auto_renew"]; v != "" && v != "true" && v != "false" {
		return fmt.Errorf("auto_renew must be 'true' or 'false'")
	}
	return nil
}

func (cs *CertStore) Start(cfg map[string]string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.cfg = cfg
	cs.caDir = cfg["ca_dir"]
	cs.certDir = cfg["cert_dir"]

	if err := os.MkdirAll(cs.caDir, 0o700); err != nil {
		return fmt.Errorf("create ca_dir: %w", err)
	}
	if err := os.MkdirAll(cs.certDir, 0o700); err != nil {
		return fmt.Errorf("create cert_dir: %w", err)
	}

	// Load or generate the internal CA.
	if err := cs.loadOrGenerateCA(); err != nil {
		return fmt.Errorf("CA init: %w", err)
	}

	// Load certificate inventory.
	if err := cs.loadInventory(); err != nil {
		slog.Warn("certstore: failed to load inventory, starting fresh", "error", err)
		cs.inventory = certInventory{}
	}

	// Start auto-renewal goroutine if enabled.
	cs.stopCh = make(chan struct{})
	if cfg["auto_renew"] == "true" {
		go cs.renewalLoop()
	}

	cs.state = StateRunning
	slog.Info("certstore started", "ca_dir", cs.caDir, "cert_dir", cs.certDir)
	return nil
}

func (cs *CertStore) Stop() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.stopCh != nil {
		close(cs.stopCh)
		cs.stopCh = nil
	}

	cs.caCert = nil
	cs.caKey = nil
	cs.state = StateStopped
	slog.Info("certstore stopped")
	return nil
}

func (cs *CertStore) Reload(cfg map[string]string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.cfg = cfg
	cs.caDir = cfg["ca_dir"]
	cs.certDir = cfg["cert_dir"]

	// Reload CA if directories changed.
	if err := cs.loadOrGenerateCA(); err != nil {
		return fmt.Errorf("CA reload: %w", err)
	}
	if err := cs.loadInventory(); err != nil {
		slog.Warn("certstore: failed to reload inventory", "error", err)
	}

	slog.Info("certstore reloaded")
	return nil
}

func (cs *CertStore) Status() State {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.state
}

// ---------------------------------------------------------------------------
// CA management
// ---------------------------------------------------------------------------

// caCertPath returns the path to the CA certificate PEM file.
func (cs *CertStore) caCertPath() string {
	return filepath.Join(cs.caDir, "ca.crt")
}

// caKeyPath returns the path to the CA private key PEM file.
func (cs *CertStore) caKeyPath() string {
	return filepath.Join(cs.caDir, "ca.key")
}

// inventoryPath returns the path to the certificate inventory JSON file.
func (cs *CertStore) inventoryPath() string {
	return filepath.Join(cs.certDir, "inventory.json")
}

// loadOrGenerateCA loads an existing CA from disk or generates a new one.
func (cs *CertStore) loadOrGenerateCA() error {
	certPath := cs.caCertPath()
	keyPath := cs.caKeyPath()

	// Try to load existing CA.
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return cs.loadCA(certPath, keyPath)
		}
	}

	// Generate new CA.
	slog.Info("certstore: generating new internal CA")
	return cs.generateCA()
}

// loadCA reads an existing CA cert and key from disk.
func (cs *CertStore) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	cs.caCert = cert
	cs.caKey = key
	slog.Info("certstore: loaded existing CA", "subject", cert.Subject.CommonName, "expires", cert.NotAfter)
	return nil
}

// generateCA creates a new ECDSA P-384 CA certificate and key.
func (cs *CertStore) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	validityYears := 10
	if v := cs.cfg["ca_validity_years"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			validityYears = n
		}
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return err
	}

	cn := cs.cfg["ca_cn"]
	if cn == "" {
		cn = "Gatekeeper Internal CA"
	}
	org := cs.cfg["ca_org"]
	if org == "" {
		org = "Gatekeeper"
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             now.Add(-1 * time.Hour), // Clock skew tolerance.
		NotAfter:              now.AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse generated CA cert: %w", err)
	}

	// Write cert PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(cs.caCertPath(), certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Write key PEM with restrictive permissions.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(cs.caKeyPath(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	cs.caCert = cert
	cs.caKey = key
	slog.Info("certstore: CA generated", "cn", cn, "expires", cert.NotAfter)
	return nil
}

// GenerateCACert forces regeneration of the CA certificate and key.
// Any previously issued certificates will no longer chain to the new CA.
func (cs *CertStore) GenerateCACert() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return fmt.Errorf("certstore is not running")
	}
	return cs.generateCA()
}

// ---------------------------------------------------------------------------
// Certificate issuance
// ---------------------------------------------------------------------------

// IssueCert generates a server certificate signed by the internal CA.
// domains is a list of DNS names; ips is a list of IP address strings.
// Returns the paths to the generated certificate and key files.
func (cs *CertStore) IssueCert(domains []string, ips []string) (certPath, keyPath string, err error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return "", "", fmt.Errorf("certstore is not running")
	}
	if cs.caCert == nil || cs.caKey == nil {
		return "", "", fmt.Errorf("CA not initialized")
	}
	if len(domains) == 0 && len(ips) == 0 {
		return "", "", fmt.Errorf("at least one domain or IP is required")
	}

	return cs.issueCertInternal(domains, ips, "internal-ca")
}

// issueCertInternal generates an ECDSA P-256 server certificate.
// Must be called with cs.mu held.
func (cs *CertStore) issueCertInternal(domains []string, ips []string, issuer string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate server key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return "", "", err
	}

	validityDays := 365
	if v := cs.cfg["cert_validity_days"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			validityDays = n
		}
	}

	now := time.Now()
	cn := ""
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0]
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.AddDate(0, 0, validityDays),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames: domains,
	}

	// Parse and add IP SANs.
	for _, ipStr := range ips {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			return "", "", fmt.Errorf("invalid IP address: %s", ipStr)
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	// Sign with the CA.
	var certDER []byte
	if issuer == "self-signed" {
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	} else {
		certDER, err = x509.CreateCertificate(rand.Reader, template, cs.caCert, &key.PublicKey, cs.caKey)
	}
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	// Determine file name from primary domain or serial.
	baseName := cn
	if baseName == "" {
		baseName = serialNumber.Text(16)
	}
	// Sanitize for filesystem.
	baseName = strings.ReplaceAll(baseName, "*", "_wildcard")
	baseName = strings.ReplaceAll(baseName, "/", "_")

	certPath := filepath.Join(cs.certDir, baseName+".crt")
	keyPath := filepath.Join(cs.certDir, baseName+".key")

	// Write cert PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}

	// Write key PEM.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}

	// Add to inventory.
	info := CertInfo{
		Serial:    serialNumber.Text(16),
		Domains:   domains,
		IPs:       ips,
		IssuedAt:  now,
		ExpiresAt: template.NotAfter,
		CertPath:  certPath,
		KeyPath:   keyPath,
		Issuer:    issuer,
	}
	cs.inventory.Certs = append(cs.inventory.Certs, info)
	if err := cs.saveInventory(); err != nil {
		slog.Warn("certstore: failed to save inventory", "error", err)
	}

	slog.Info("certstore: certificate issued",
		"serial", info.Serial,
		"domains", domains,
		"ips", ips,
		"issuer", issuer,
		"expires", template.NotAfter,
	)
	return certPath, keyPath, nil
}

// IssueSelfSignedCert generates a standalone self-signed certificate
// (not signed by the internal CA).
func (cs *CertStore) IssueSelfSignedCert(domains []string, ips []string) (certPath, keyPath string, err error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return "", "", fmt.Errorf("certstore is not running")
	}
	if len(domains) == 0 && len(ips) == 0 {
		return "", "", fmt.Errorf("at least one domain or IP is required")
	}

	return cs.issueCertInternal(domains, ips, "self-signed")
}

// ---------------------------------------------------------------------------
// ACME / Let's Encrypt
// ---------------------------------------------------------------------------

// IssueACMECert provisions a certificate via ACME HTTP-01 challenge.
// The caller must ensure port 80 is reachable and pointed at the
// ACME challenge handler (use ACMEHTTPHandler).
//
// This is a minimal ACME client implementation. For production use with
// complex requirements, consider integrating a full ACME library.
func (cs *CertStore) IssueACMECert(domains []string) (certPath, keyPath string, err error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return "", "", fmt.Errorf("certstore is not running")
	}
	if len(domains) == 0 {
		return "", "", fmt.Errorf("at least one domain is required for ACME")
	}
	if cs.cfg["acme_email"] == "" {
		return "", "", fmt.Errorf("acme_email must be configured for ACME certificate provisioning")
	}

	// Generate a key pair for the certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ACME cert key: %w", err)
	}

	// Create a CSR.
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return "", "", fmt.Errorf("create CSR: %w", err)
	}

	// Store CSR for ACME flow reference.
	_ = csrDER // CSR would be submitted to ACME server in full implementation.

	slog.Info("certstore: ACME certificate request prepared",
		"domains", domains,
		"directory", cs.cfg["acme_directory"],
	)

	// In a full implementation, this would:
	// 1. Create/load an ACME account key
	// 2. Register or fetch account from the ACME directory
	// 3. Create a new order for the domains
	// 4. Solve HTTP-01 challenges using cs.acmeChallenge map
	// 5. Finalize the order with the CSR
	// 6. Download the certificate chain
	//
	// For now, we prepare the key and CSR. A production deployment should
	// integrate golang.org/x/crypto/acme or a similar library.

	baseName := strings.ReplaceAll(domains[0], "*", "_wildcard")
	keyPath = filepath.Join(cs.certDir, baseName+".key")

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal ACME key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write ACME key: %w", err)
	}

	return "", keyPath, fmt.Errorf("ACME flow requires external integration; key generated at %s, CSR prepared for domains %v", keyPath, domains)
}

// ACMEHTTPChallengeResponse returns the key authorization for an HTTP-01
// challenge token, or empty string if no challenge is pending for that token.
// Use this from an HTTP handler on /.well-known/acme-challenge/{token}.
func (cs *CertStore) ACMEHTTPChallengeResponse(token string) string {
	if v, ok := cs.acmeChallenge.Load(token); ok {
		return v.(string)
	}
	return ""
}

// SetACMEChallenge registers an HTTP-01 challenge token and key authorization.
func (cs *CertStore) SetACMEChallenge(token, keyAuth string) {
	cs.acmeChallenge.Store(token, keyAuth)
}

// ClearACMEChallenge removes a completed HTTP-01 challenge token.
func (cs *CertStore) ClearACMEChallenge(token string) {
	cs.acmeChallenge.Delete(token)
}

// ---------------------------------------------------------------------------
// Certificate inventory
// ---------------------------------------------------------------------------

// ListCerts returns information about all managed certificates.
func (cs *CertStore) ListCerts() []CertInfo {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	result := make([]CertInfo, len(cs.inventory.Certs))
	copy(result, cs.inventory.Certs)
	return result
}

// RevokeCert marks a certificate as revoked by serial number and removes
// the cert and key files from disk.
func (cs *CertStore) RevokeCert(serial string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return fmt.Errorf("certstore is not running")
	}

	for i := range cs.inventory.Certs {
		if cs.inventory.Certs[i].Serial == serial {
			cs.inventory.Certs[i].Revoked = true

			// Remove files from disk.
			if err := os.Remove(cs.inventory.Certs[i].CertPath); err != nil && !os.IsNotExist(err) {
				slog.Warn("certstore: failed to remove revoked cert file", "path", cs.inventory.Certs[i].CertPath, "error", err)
			}
			if err := os.Remove(cs.inventory.Certs[i].KeyPath); err != nil && !os.IsNotExist(err) {
				slog.Warn("certstore: failed to remove revoked key file", "path", cs.inventory.Certs[i].KeyPath, "error", err)
			}

			if err := cs.saveInventory(); err != nil {
				return fmt.Errorf("save inventory after revoke: %w", err)
			}

			slog.Info("certstore: certificate revoked", "serial", serial)
			return nil
		}
	}
	return fmt.Errorf("certificate with serial %s not found", serial)
}

// ExportCA returns the CA certificate in PEM format, suitable for importing
// into browsers and operating system trust stores.
func (cs *CertStore) ExportCA() ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return nil, fmt.Errorf("certstore is not running")
	}

	data, err := os.ReadFile(cs.caCertPath())
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	return data, nil
}

// RenewCert reissues a certificate with the same domains and IPs,
// extending the validity period. The old certificate files are replaced.
func (cs *CertStore) RenewCert(serial string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.state != StateRunning {
		return fmt.Errorf("certstore is not running")
	}

	var target *CertInfo
	var idx int
	for i := range cs.inventory.Certs {
		if cs.inventory.Certs[i].Serial == serial {
			target = &cs.inventory.Certs[i]
			idx = i
			break
		}
	}
	if target == nil {
		return fmt.Errorf("certificate with serial %s not found", serial)
	}
	if target.Revoked {
		return fmt.Errorf("cannot renew a revoked certificate")
	}

	// Remove old files.
	os.Remove(target.CertPath)
	os.Remove(target.KeyPath)

	// Reissue.
	certPath, keyPath, err := cs.issueCertInternal(target.Domains, target.IPs, target.Issuer)
	if err != nil {
		return fmt.Errorf("renew cert: %w", err)
	}

	// The issueCertInternal call appended a new entry. Remove the old one
	// and update the new entry's serial reference.
	cs.inventory.Certs = append(cs.inventory.Certs[:idx], cs.inventory.Certs[idx+1:]...)

	slog.Info("certstore: certificate renewed",
		"old_serial", serial,
		"cert_path", certPath,
		"key_path", keyPath,
	)
	return nil
}

// ---------------------------------------------------------------------------
// Auto-renewal
// ---------------------------------------------------------------------------

// renewalLoop periodically checks certificates and renews those nearing expiry.
func (cs *CertStore) renewalLoop() {
	// Check every 6 hours.
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-cs.stopCh:
			return
		case <-ticker.C:
			cs.checkAndRenew()
		}
	}
}

// checkAndRenew inspects the inventory for certs nearing expiry and renews them.
func (cs *CertStore) checkAndRenew() {
	cs.mu.Lock()
	renewDays := 30
	if v := cs.cfg["renew_before_days"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			renewDays = n
		}
	}

	// Collect serials that need renewal (avoid modifying inventory while iterating).
	var renewSerials []string
	threshold := time.Now().AddDate(0, 0, renewDays)
	for _, info := range cs.inventory.Certs {
		if info.Revoked {
			continue
		}
		if info.Issuer == "acme" {
			// ACME certs need external renewal flow; skip auto-renewal here.
			continue
		}
		if info.ExpiresAt.Before(threshold) {
			renewSerials = append(renewSerials, info.Serial)
		}
	}
	cs.mu.Unlock()

	for _, serial := range renewSerials {
		slog.Info("certstore: auto-renewing certificate", "serial", serial)
		if err := cs.RenewCert(serial); err != nil {
			slog.Error("certstore: auto-renewal failed", "serial", serial, "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Inventory persistence
// ---------------------------------------------------------------------------

func (cs *CertStore) loadInventory() error {
	data, err := os.ReadFile(cs.inventoryPath())
	if err != nil {
		if os.IsNotExist(err) {
			cs.inventory = certInventory{}
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &cs.inventory)
}

func (cs *CertStore) saveInventory() error {
	data, err := json.MarshalIndent(cs.inventory, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write: write to temp file, then rename.
	tmpPath := cs.inventoryPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, cs.inventoryPath())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// generateSerialNumber creates a random 128-bit serial number for certificates.
func generateSerialNumber() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

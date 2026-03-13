package inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestFingerprintCert_Basic(t *testing.T) {
	e := NewEngine(nil)

	cert := buildTestCert(t, "example.com", "Let's Encrypt", false, false)
	chain := &TLSCertChain{
		Certificates: []*x509.Certificate{cert},
		SrcIP:        "10.0.0.1",
		DstIP:        "192.168.1.100",
		SNI:          "example.com",
	}

	fp, err := e.FingerprintCert(chain)
	if err != nil {
		t.Fatalf("FingerprintCert: %v", err)
	}

	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.LeafSubject != "example.com" {
		t.Errorf("leaf_subject = %q, want example.com", fp.LeafSubject)
	}
	if fp.LeafIssuer != "Let's Encrypt" {
		t.Errorf("leaf_issuer = %q, want Let's Encrypt", fp.LeafIssuer)
	}
	if fp.SelfSigned {
		t.Error("should not be self-signed")
	}
	if fp.ChainLength != 1 {
		t.Errorf("chain_length = %d, want 1", fp.ChainLength)
	}
	if fp.KeyType != "ECDSA" {
		t.Errorf("key_type = %q, want ECDSA", fp.KeyType)
	}
	if len(fp.SANs) == 0 {
		t.Error("should have SANs")
	}
}

func TestFingerprintCert_SelfSigned(t *testing.T) {
	e := NewEngine(nil)

	cert := buildTestCert(t, "malware.evil", "malware.evil", false, false)
	chain := &TLSCertChain{
		Certificates: []*x509.Certificate{cert},
		SrcIP:        "10.0.0.1",
	}

	fp, err := e.FingerprintCert(chain)
	if err != nil {
		t.Fatalf("FingerprintCert: %v", err)
	}

	if !fp.SelfSigned {
		t.Error("should be self-signed")
	}
	found := false
	for _, alert := range fp.Alerts {
		if alert == "self-signed certificate" {
			found = true
		}
	}
	if !found {
		t.Error("should have self-signed alert")
	}
}

func TestFingerprintCert_Expired(t *testing.T) {
	e := NewEngine(nil)

	cert := buildTestCert(t, "expired.com", "CA", true, false)
	chain := &TLSCertChain{
		Certificates: []*x509.Certificate{cert},
		SrcIP:        "10.0.0.1",
	}

	fp, err := e.FingerprintCert(chain)
	if err != nil {
		t.Fatalf("FingerprintCert: %v", err)
	}

	if !fp.Expired {
		t.Error("should be expired")
	}
	found := false
	for _, alert := range fp.Alerts {
		if alert == "certificate expired" {
			found = true
		}
	}
	if !found {
		t.Error("should have expired alert")
	}
}

func TestFingerprintCert_NoSANs(t *testing.T) {
	e := NewEngine(nil)

	cert := buildTestCert(t, "nosans.com", "CA", false, true)
	chain := &TLSCertChain{
		Certificates: []*x509.Certificate{cert},
		SrcIP:        "10.0.0.1",
	}

	fp, err := e.FingerprintCert(chain)
	if err != nil {
		t.Fatalf("FingerprintCert: %v", err)
	}

	found := false
	for _, alert := range fp.Alerts {
		if alert == "no SANs present" {
			found = true
		}
	}
	if !found {
		t.Error("should have no SANs alert")
	}
}

func TestFingerprintCert_Chain(t *testing.T) {
	e := NewEngine(nil)

	leaf := buildTestCert(t, "example.com", "Intermediate CA", false, false)
	intermediate := buildTestCert(t, "Intermediate CA", "Root CA", false, false)

	chain := &TLSCertChain{
		Certificates: []*x509.Certificate{leaf, intermediate},
		SrcIP:        "10.0.0.1",
	}

	fp, err := e.FingerprintCert(chain)
	if err != nil {
		t.Fatalf("FingerprintCert: %v", err)
	}

	if fp.ChainLength != 2 {
		t.Errorf("chain_length = %d, want 2", fp.ChainLength)
	}
	if len(fp.ChainHashes) != 2 {
		t.Errorf("chain_hashes = %d, want 2", len(fp.ChainHashes))
	}
}

func TestFingerprintCert_Nil(t *testing.T) {
	e := NewEngine(nil)

	_, err := e.FingerprintCert(nil)
	if err == nil {
		t.Error("expected error for nil chain")
	}

	_, err = e.FingerprintCert(&TLSCertChain{})
	if err == nil {
		t.Error("expected error for empty chain")
	}
}

func TestFingerprintCert_DifferentCertsProduceDifferentHashes(t *testing.T) {
	e := NewEngine(nil)

	cert1 := buildTestCert(t, "example.com", "CA1", false, false)
	cert2 := buildTestCert(t, "other.com", "CA2", false, false)

	fp1, _ := e.FingerprintCert(&TLSCertChain{Certificates: []*x509.Certificate{cert1}})
	fp2, _ := e.FingerprintCert(&TLSCertChain{Certificates: []*x509.Certificate{cert2}})

	if fp1.Hash == fp2.Hash {
		t.Error("different certs should produce different hashes")
	}
}

func TestParseCertificateMessage(t *testing.T) {
	// Build a TLS Certificate message with a real cert.
	cert := buildTestCert(t, "test.com", "Test CA", false, false)
	certDER := cert.Raw

	// TLS Certificate message structure:
	// Record header: type(1) + version(2) + length(2)
	// Handshake header: type(1) + length(3)
	// Certificates length(3)
	// Certificate: length(3) + DER data

	certEntry := make([]byte, 3+len(certDER))
	certEntry[0] = byte(len(certDER) >> 16)
	certEntry[1] = byte(len(certDER) >> 8)
	certEntry[2] = byte(len(certDER))
	copy(certEntry[3:], certDER)

	certsLen := len(certEntry)
	certsLenBytes := []byte{byte(certsLen >> 16), byte(certsLen >> 8), byte(certsLen)}

	hsPayload := append(certsLenBytes, certEntry...)
	hsLen := len(hsPayload)
	handshake := make([]byte, 4+hsLen)
	handshake[0] = 0x0b // Certificate
	handshake[1] = byte(hsLen >> 16)
	handshake[2] = byte(hsLen >> 8)
	handshake[3] = byte(hsLen)
	copy(handshake[4:], hsPayload)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Handshake
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	chain, err := ParseCertificateMessage(record)
	if err != nil {
		t.Fatalf("ParseCertificateMessage: %v", err)
	}

	if len(chain.Certificates) != 1 {
		t.Fatalf("certs = %d, want 1", len(chain.Certificates))
	}
	if chain.Certificates[0].Subject.CommonName != "test.com" {
		t.Errorf("subject = %q, want test.com", chain.Certificates[0].Subject.CommonName)
	}
}

func TestParseCertificateMessage_NotHandshake(t *testing.T) {
	_, err := ParseCertificateMessage([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for non-handshake record")
	}
}

func TestParseCertificateMessage_NotCertificate(t *testing.T) {
	// Handshake type 0x01 (ClientHello) instead of 0x0b (Certificate).
	record := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
	_, err := ParseCertificateMessage(record)
	if err == nil {
		t.Error("expected error for non-Certificate message")
	}
}

// buildTestCert creates a test certificate.
// When cn == issuerCN it is truly self-signed; otherwise a separate issuer cert is
// created so the parsed cert has distinct Subject and Issuer DNs.
func buildTestCert(t *testing.T, cn, issuerCN string, expired, noSANs bool) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if expired {
		notBefore = time.Now().Add(-365 * 24 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	if !noSANs {
		template.DNSNames = []string{cn, "www." + cn}
	}

	// If issuerCN differs from cn, create a separate issuer to sign with.
	parent := template
	signerKey := key
	if issuerCN != cn {
		issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate issuer key: %v", err)
		}
		parent = &x509.Certificate{
			SerialNumber:          big.NewInt(100),
			Subject:               pkix.Name{CommonName: issuerCN, Organization: []string{"Issuer Org"}},
			NotBefore:             notBefore,
			NotAfter:              notAfter.Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		// Self-sign the issuer cert so it is valid.
		issuerDER, err := x509.CreateCertificate(rand.Reader, parent, parent, &issuerKey.PublicKey, issuerKey)
		if err != nil {
			t.Fatalf("create issuer cert: %v", err)
		}
		parent, err = x509.ParseCertificate(issuerDER)
		if err != nil {
			t.Fatalf("parse issuer cert: %v", err)
		}
		signerKey = issuerKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	return cert
}

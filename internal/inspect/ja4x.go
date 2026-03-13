package inspect

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TLSCertChain contains parsed certificate data from a TLS handshake.
type TLSCertChain struct {
	Certificates []*x509.Certificate // Parsed certs in chain order (leaf first)
	RawCerts     [][]byte            // DER-encoded certificates
	SrcIP        string
	DstIP        string
	SNI          string
	Timestamp    time.Time
}

// JA4XFingerprint is an X.509 certificate chain fingerprint.
//
// JA4X format: {issuer_hash}_{subject_hash}_{extensions_hash}
// Each component is the truncated SHA256 of the relevant fields from the leaf cert.
// For chain analysis: each cert in the chain gets its own hash tuple.
type JA4XFingerprint struct {
	Hash          string           `json:"hash"`           // Combined fingerprint hash
	IssuerHash    string           `json:"issuer_hash"`    // Hash of issuer DN fields
	SubjectHash   string           `json:"subject_hash"`   // Hash of subject DN fields
	ExtHash       string           `json:"ext_hash"`       // Hash of extension OIDs
	ChainLength   int              `json:"chain_length"`   // Number of certs in chain
	LeafSubject   string           `json:"leaf_subject"`   // Leaf cert subject CN
	LeafIssuer    string           `json:"leaf_issuer"`    // Leaf cert issuer CN
	SANs          []string         `json:"sans"`           // Subject Alternative Names
	KeyType       string           `json:"key_type"`       // RSA, ECDSA, Ed25519
	KeyBits       int              `json:"key_bits"`       // Key size in bits
	SelfSigned    bool             `json:"self_signed"`    // Issuer == Subject
	Expired       bool             `json:"expired"`        // NotAfter < now
	ChainHashes   []string         `json:"chain_hashes"`   // Per-cert hashes for full chain
	Alerts        []string         `json:"alerts"`         // Security warnings
	SrcIP         string           `json:"src_ip"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	Count         int64            `json:"count"`
}

// FingerprintCert extracts a JA4X fingerprint from a TLS certificate chain.
//
// For each certificate in the chain:
//   - Issuer hash: truncated SHA256 of issuer RDN sequence (C, O, OU, CN sorted)
//   - Subject hash: truncated SHA256 of subject RDN sequence
//   - Extension hash: truncated SHA256 of extension OID list
//
// The final JA4X hash combines the leaf cert's three hashes.
func (e *Engine) FingerprintCert(chain *TLSCertChain) (*JA4XFingerprint, error) {
	if chain == nil || len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("nil or empty certificate chain")
	}

	now := time.Now()
	leaf := chain.Certificates[0]

	// Build issuer hash from leaf cert.
	issuerStr := dnToString(leaf.Issuer.Country, leaf.Issuer.Organization,
		leaf.Issuer.OrganizationalUnit, leaf.Issuer.CommonName)
	issuerHash := truncHash(issuerStr)

	// Build subject hash from leaf cert.
	subjectStr := dnToString(leaf.Subject.Country, leaf.Subject.Organization,
		leaf.Subject.OrganizationalUnit, leaf.Subject.CommonName)
	subjectHash := truncHash(subjectStr)

	// Build extension hash from leaf cert OIDs.
	var extOIDs []string
	for _, ext := range leaf.Extensions {
		extOIDs = append(extOIDs, ext.Id.String())
	}
	extStr := strings.Join(extOIDs, ",")
	extHash := truncHash(extStr)

	// Combined hash.
	hash := fmt.Sprintf("%s_%s_%s", issuerHash, subjectHash, extHash)

	// Key type and size.
	keyType, keyBits := certKeyInfo(leaf)

	// Self-signed check.
	selfSigned := leaf.Issuer.CommonName == leaf.Subject.CommonName &&
		strings.Join(leaf.Issuer.Organization, ",") == strings.Join(leaf.Subject.Organization, ",")

	// Expiry check.
	expired := now.After(leaf.NotAfter)

	// SANs.
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Per-cert chain hashes.
	var chainHashes []string
	for _, cert := range chain.Certificates {
		is := dnToString(cert.Issuer.Country, cert.Issuer.Organization,
			cert.Issuer.OrganizationalUnit, cert.Issuer.CommonName)
		ss := dnToString(cert.Subject.Country, cert.Subject.Organization,
			cert.Subject.OrganizationalUnit, cert.Subject.CommonName)
		var oids []string
		for _, ext := range cert.Extensions {
			oids = append(oids, ext.Id.String())
		}
		ch := fmt.Sprintf("%s_%s_%s", truncHash(is), truncHash(ss), truncHash(strings.Join(oids, ",")))
		chainHashes = append(chainHashes, ch)
	}

	// Security alerts.
	var alerts []string
	if selfSigned {
		alerts = append(alerts, "self-signed certificate")
	}
	if expired {
		alerts = append(alerts, "certificate expired")
	}
	if keyType == "RSA" && keyBits < 2048 {
		alerts = append(alerts, fmt.Sprintf("weak RSA key: %d bits", keyBits))
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > 398*24*time.Hour {
		alerts = append(alerts, "validity period exceeds 398 days")
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		alerts = append(alerts, "no SANs present")
	}

	fp := &JA4XFingerprint{
		Hash:        hash,
		IssuerHash:  issuerHash,
		SubjectHash: subjectHash,
		ExtHash:     extHash,
		ChainLength: len(chain.Certificates),
		LeafSubject: leaf.Subject.CommonName,
		LeafIssuer:  leaf.Issuer.CommonName,
		SANs:        sans,
		KeyType:     keyType,
		KeyBits:     keyBits,
		SelfSigned:  selfSigned,
		Expired:     expired,
		ChainHashes: chainHashes,
		Alerts:      alerts,
		SrcIP:       chain.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "ja4x",
			Hash:      hash,
			SrcIP:     chain.SrcIP,
			DstIP:     chain.DstIP,
			SNI:       chain.SNI,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseCertificateMessage parses a TLS Certificate handshake message.
// The input should be the raw TLS record starting at content type byte.
// Returns parsed certificates suitable for JA4X fingerprinting.
func ParseCertificateMessage(data []byte) (*TLSCertChain, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record: %d bytes", len(data))
	}

	// TLS record header.
	if data[0] != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record: 0x%02x", data[0])
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) < recordLen {
		return nil, fmt.Errorf("record truncated: have %d, need %d", len(payload), recordLen)
	}
	payload = payload[:recordLen]

	// Handshake header: type(1) + length(3)
	if len(payload) < 4 {
		return nil, fmt.Errorf("handshake header too short")
	}
	if payload[0] != 0x0b { // Certificate message type
		return nil, fmt.Errorf("not a Certificate message: type 0x%02x", payload[0])
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	payload = payload[4:]
	if len(payload) < hsLen {
		return nil, fmt.Errorf("Certificate message truncated")
	}
	payload = payload[:hsLen]

	// Certificates length (3 bytes).
	if len(payload) < 3 {
		return nil, fmt.Errorf("truncated at certificates length")
	}
	certsLen := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
	payload = payload[3:]
	if len(payload) < certsLen {
		return nil, fmt.Errorf("certificates data truncated")
	}
	payload = payload[:certsLen]

	chain := &TLSCertChain{}

	// Parse individual certificates.
	pos := 0
	for pos+3 <= len(payload) {
		certLen := int(payload[pos])<<16 | int(payload[pos+1])<<8 | int(payload[pos+2])
		pos += 3
		if pos+certLen > len(payload) {
			break
		}

		certDER := payload[pos : pos+certLen]
		chain.RawCerts = append(chain.RawCerts, certDER)

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			// Skip unparseable certs but continue with the rest.
			pos += certLen
			continue
		}
		chain.Certificates = append(chain.Certificates, cert)
		pos += certLen
	}

	if len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates in chain")
	}

	return chain, nil
}

// dnToString builds a canonical string from distinguished name components.
func dnToString(country, org, ou []string, cn string) string {
	parts := make([]string, 0, 4)
	if len(country) > 0 {
		parts = append(parts, "C="+strings.Join(country, ","))
	}
	if len(org) > 0 {
		parts = append(parts, "O="+strings.Join(org, ","))
	}
	if len(ou) > 0 {
		parts = append(parts, "OU="+strings.Join(ou, ","))
	}
	if cn != "" {
		parts = append(parts, "CN="+cn)
	}
	return strings.Join(parts, "/")
}

// certKeyInfo returns the key type and bit size for a certificate.
func certKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		// RSA keys implement Size().
		return "RSA", pub.Size() * 8
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			return "RSA", 0
		case x509.ECDSA:
			// Infer from curve name.
			if cert.PublicKey != nil {
				if ec, ok := cert.PublicKey.(interface{ Params() interface{ BitSize() int } }); ok {
					_ = ec
				}
			}
			return "ECDSA", 256 // Default assumption
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return "Unknown", 0
		}
	}
}

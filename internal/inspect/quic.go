package inspect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/hkdf"
)

// QUICInitial contains parsed fields from a QUIC Initial packet.
type QUICInitial struct {
	Version          uint32   // QUIC version (e.g. 0x00000001 for v1)
	DCIDLength       int      // Destination Connection ID length
	SCIDLength       int      // Source Connection ID length
	DCID             []byte   // Destination Connection ID
	SCID             []byte   // Source Connection ID
	TokenLength      int      // Token length
	ClientHello      *ClientHello // Extracted TLS ClientHello from CRYPTO frame
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	Timestamp        time.Time
}

// QUICFingerprint is a QUIC Initial packet fingerprint.
// Uses the JA4 format with "q" prefix instead of "t" to indicate QUIC transport.
type QUICFingerprint struct {
	Hash        string    `json:"hash"`         // Full fingerprint (JA4 with q prefix)
	RawHash     string    `json:"raw_hash"`     // Unsorted hash
	QUICVersion string    `json:"quic_version"` // QUIC version string
	TLSHash     string    `json:"tls_hash"`     // JA4 hash of the inner ClientHello
	DCIDLen     int       `json:"dcid_len"`     // Destination Connection ID length
	SCIDLen     int       `json:"scid_len"`     // Source Connection ID length
	SrcIP       string    `json:"src_ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int64     `json:"count"`
}

// FingerprintQUIC extracts a fingerprint from a QUIC Initial packet.
// The inner ClientHello is fingerprinted using the JA4 algorithm with "q" prefix.
func (e *Engine) FingerprintQUIC(qi *QUICInitial) (*QUICFingerprint, error) {
	if qi == nil {
		return nil, fmt.Errorf("nil QUICInitial")
	}
	if qi.ClientHello == nil {
		return nil, fmt.Errorf("no ClientHello in QUIC Initial")
	}

	// Use the JA4 fingerprinting on the inner ClientHello,
	// but we'll build the hash ourselves with "q" prefix.
	hello := qi.ClientHello

	ciphers := filterGREASE(hello.CipherSuites)
	extensions := filterGREASE(hello.Extensions)

	ver := tlsVersionString(hello.Version)

	sni := "i"
	if hello.SNI != "" {
		sni = "d"
	}

	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	alpn := "00"
	if len(hello.ALPNProtocols) > 0 && len(hello.ALPNProtocols[0]) >= 2 {
		p := hello.ALPNProtocols[0]
		alpn = string(p[0]) + string(p[len(p)-1])
	} else if len(hello.ALPNProtocols) > 0 && len(hello.ALPNProtocols[0]) == 1 {
		alpn = string(hello.ALPNProtocols[0][0]) + string(hello.ALPNProtocols[0][0])
	}

	// "q" prefix for QUIC transport (vs "t" for TCP).
	prefix := fmt.Sprintf("q%s%s%02d%02d%s", ver, sni, cipherCount, extCount, alpn)

	cipherStr := uint16sToSortedString(ciphers)
	cipherHash := truncHash(cipherStr)

	extStr := uint16sToSortedString(extensions)
	sigAlgs := uint16sToSortedString(filterGREASE(hello.SignatureAlgs))
	curves := uint16sToSortedString(filterGREASE(hello.EllipticCurves))
	fullExtStr := extStr
	if sigAlgs != "" {
		fullExtStr += "_" + sigAlgs
	}
	if curves != "" {
		fullExtStr += "_" + curves
	}
	extHash := truncHash(fullExtStr)

	hash := fmt.Sprintf("%s_%s_%s", prefix, cipherHash, extHash)

	// Raw (unsorted) hash.
	rawCipherHash := truncHash(uint16sToString(ciphers))
	rawFullExtStr := uint16sToString(extensions)
	if sigAlgs != "" {
		rawFullExtStr += "_" + uint16sToString(filterGREASE(hello.SignatureAlgs))
	}
	if curves != "" {
		rawFullExtStr += "_" + uint16sToString(filterGREASE(hello.EllipticCurves))
	}
	rawExtHash := truncHash(rawFullExtStr)
	rawHash := fmt.Sprintf("%s_%s_%s", prefix, rawCipherHash, rawExtHash)

	qv := quicVersionString(qi.Version)

	now := time.Now()
	fp := &QUICFingerprint{
		Hash:        hash,
		RawHash:     rawHash,
		QUICVersion: qv,
		TLSHash:     hash,
		DCIDLen:     qi.DCIDLength,
		SCIDLen:     qi.SCIDLength,
		SrcIP:       qi.SrcIP,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      "quic",
			Hash:      hash,
			SrcIP:     qi.SrcIP,
			DstIP:     qi.DstIP,
			SNI:       hello.SNI,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseQUICInitial parses a QUIC Initial packet from raw UDP payload.
// QUIC Initial packets contain a TLS ClientHello in the CRYPTO frame.
// This handles QUIC v1 (RFC 9000) and v2 (RFC 9369) header protection removal
// and CRYPTO frame extraction.
func ParseQUICInitial(data []byte) (*QUICInitial, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for QUIC: %d bytes", len(data))
	}

	// First byte: form bit (1) | fixed bit (1) | long packet type (2) | reserved (2) | packet number length (2)
	// For Initial packets: form=1 (long header), type=0x00 (Initial)
	firstByte := data[0]
	if firstByte&0x80 == 0 {
		return nil, fmt.Errorf("not a long header QUIC packet")
	}

	// Version (4 bytes at offset 1).
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		return nil, fmt.Errorf("QUIC version negotiation packet, not Initial")
	}

	// Check packet type based on version.
	packetType := (firstByte & 0x30) >> 4
	if version == quicV2 {
		// QUIC v2 swaps Initial (0x01) and 0-RTT (0x00) type bits.
		if packetType != 0x01 {
			return nil, fmt.Errorf("not a QUIC v2 Initial packet: type %d", packetType)
		}
	} else {
		if packetType != 0x00 {
			return nil, fmt.Errorf("not a QUIC Initial packet: type %d", packetType)
		}
	}

	pos := 5

	// DCID length (1 byte) + DCID.
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at DCID length")
	}
	dcidLen := int(data[pos])
	pos++
	if pos+dcidLen > len(data) {
		return nil, fmt.Errorf("truncated at DCID")
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, data[pos:pos+dcidLen])
	pos += dcidLen

	// SCID length (1 byte) + SCID.
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(data[pos])
	pos++
	if pos+scidLen > len(data) {
		return nil, fmt.Errorf("truncated at SCID")
	}
	scid := make([]byte, scidLen)
	copy(scid, data[pos:pos+scidLen])
	pos += scidLen

	// Token length (variable-length integer) + token.
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at token length")
	}
	tokenLen, tokenLenBytes, err := readVarInt(data[pos:])
	if err != nil {
		return nil, fmt.Errorf("invalid token length: %w", err)
	}
	pos += tokenLenBytes
	if pos+int(tokenLen) > len(data) {
		return nil, fmt.Errorf("truncated at token")
	}
	pos += int(tokenLen)

	// Packet length (variable-length integer).
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at packet length")
	}
	pktLen, pktLenBytes, err := readVarInt(data[pos:])
	if err != nil {
		return nil, fmt.Errorf("invalid packet length: %w", err)
	}
	pos += pktLenBytes

	if pos+int(pktLen) > len(data) {
		return nil, fmt.Errorf("packet payload truncated")
	}

	// The remaining data is header-protected. We need to remove header protection
	// to get the packet number, then decrypt the payload to extract the CRYPTO frame.
	headerEnd := pos
	protected := data[pos : pos+int(pktLen)]

	// Derive initial keys from DCID.
	clientKey, clientIV, clientHP, err := deriveInitialKeys(dcid, version)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}

	// Remove header protection.
	if len(protected) < 4+16 {
		return nil, fmt.Errorf("payload too short for header protection removal")
	}

	// Sample starts at 4 bytes into the payload (after max packet number bytes).
	sample := protected[4:20]
	hpBlock, err := aes.NewCipher(clientHP)
	if err != nil {
		return nil, fmt.Errorf("HP cipher: %w", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, sample)

	// Unmask first byte.
	unmaskedFirst := data[0] ^ (mask[0] & 0x0f) // Long header: lower 4 bits
	pnLen := int(unmaskedFirst&0x03) + 1

	// Unmask packet number.
	pn := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pn[i] = protected[i] ^ mask[i+1]
	}

	// Build nonce: IV XOR packet number (right-aligned).
	nonce := make([]byte, 12)
	copy(nonce, clientIV)
	for i := 0; i < pnLen; i++ {
		nonce[12-pnLen+i] ^= pn[i]
	}

	// Decrypt payload.
	aesBlock, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, fmt.Errorf("AEAD cipher: %w", err)
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}

	// Associated data: the unprotected header.
	header := make([]byte, headerEnd+pnLen)
	copy(header, data[:headerEnd+pnLen])
	header[0] = unmaskedFirst
	for i := 0; i < pnLen; i++ {
		header[headerEnd+i] = pn[i]
	}

	ciphertext := protected[pnLen:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("AEAD decrypt: %w", err)
	}

	// Find CRYPTO frame in the decrypted payload.
	// CRYPTO frame type = 0x06.
	clientHello, err := extractCryptoFrame(plaintext)
	if err != nil {
		return nil, fmt.Errorf("CRYPTO frame: %w", err)
	}

	// Parse the ClientHello from the CRYPTO frame data.
	// The CRYPTO frame contains a raw TLS handshake message (no TLS record header).
	// We need to wrap it in a TLS record header for ParseClientHello.
	tlsRecord := buildTLSRecord(clientHello)
	hello, err := ParseClientHello(tlsRecord)
	if err != nil {
		return nil, fmt.Errorf("inner ClientHello: %w", err)
	}

	qi := &QUICInitial{
		Version:     version,
		DCIDLength:  dcidLen,
		SCIDLength:  scidLen,
		DCID:        dcid,
		SCID:        scid,
		TokenLength: int(tokenLen),
		ClientHello: hello,
	}

	return qi, nil
}

// QUIC version constants.
const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

// readVarInt reads a QUIC variable-length integer (RFC 9000 Section 16).
func readVarInt(data []byte) (uint64, int, error) {
	if len(data) < 1 {
		return 0, 0, fmt.Errorf("empty data")
	}

	prefix := data[0] >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0, fmt.Errorf("need %d bytes, have %d", length, len(data))
	}

	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3f)
	case 2:
		val = uint64(binary.BigEndian.Uint16(data[:2]) & 0x3fff)
	case 4:
		val = uint64(binary.BigEndian.Uint32(data[:4]) & 0x3fffffff)
	case 8:
		val = binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff
	}

	return val, length, nil
}

// extractCryptoFrame finds and extracts CRYPTO frame data from decrypted QUIC payload.
func extractCryptoFrame(data []byte) ([]byte, error) {
	pos := 0
	for pos < len(data) {
		// PADDING frames are single zero bytes — handle them without reading varint.
		if data[pos] == 0x00 {
			pos++
			continue
		}

		frameType, typeLen, err := readVarInt(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("frame type: %w", err)
		}
		pos += typeLen

		switch frameType {
		case 0x06: // CRYPTO
			// Offset (variable-length integer).
			_, offsetLen, err := readVarInt(data[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO offset: %w", err)
			}
			pos += offsetLen

			// Length (variable-length integer).
			cryptoLen, lenLen, err := readVarInt(data[pos:])
			if err != nil {
				return nil, fmt.Errorf("CRYPTO length: %w", err)
			}
			pos += lenLen

			if pos+int(cryptoLen) > len(data) {
				return nil, fmt.Errorf("CRYPTO data truncated")
			}
			return data[pos : pos+int(cryptoLen)], nil
		case 0x01: // PING
			continue
		default:
			// Skip unknown frames. Most frames have a length we can skip.
			// ACK frames (0x02, 0x03) are complex; for Initial packets,
			// we mainly expect PADDING, CRYPTO, and maybe ACK.
			if frameType == 0x02 || frameType == 0x03 {
				// ACK frame: skip it by parsing its structure.
				if err := skipACKFrame(data[pos:]); err != nil {
					return nil, fmt.Errorf("skipping ACK: %w", err)
				}
			}
			return nil, fmt.Errorf("unexpected frame type 0x%x before CRYPTO", frameType)
		}
	}
	return nil, fmt.Errorf("no CRYPTO frame found")
}

// skipACKFrame returns the number of bytes in an ACK frame body (after the type byte).
func skipACKFrame(data []byte) error {
	pos := 0
	// Largest Acknowledged.
	_, n, err := readVarInt(data[pos:])
	if err != nil {
		return err
	}
	pos += n
	// ACK Delay.
	_, n, err = readVarInt(data[pos:])
	if err != nil {
		return err
	}
	pos += n
	// ACK Range Count.
	rangeCount, n, err := readVarInt(data[pos:])
	if err != nil {
		return err
	}
	pos += n
	// First ACK Range.
	_, n, err = readVarInt(data[pos:])
	if err != nil {
		return err
	}
	pos += n
	// Additional ACK Ranges.
	for i := uint64(0); i < rangeCount; i++ {
		// Gap.
		_, n, err = readVarInt(data[pos:])
		if err != nil {
			return err
		}
		pos += n
		// ACK Range Length.
		_, n, err = readVarInt(data[pos:])
		if err != nil {
			return err
		}
		pos += n
	}
	return nil
}

// buildTLSRecord wraps raw TLS handshake data in a TLS record header.
func buildTLSRecord(handshake []byte) []byte {
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Handshake content type
	record[1] = 0x03 // TLS 1.0 record version (always 0x0301 for compat)
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

// deriveInitialKeys derives the client initial keys from the DCID.
// Per RFC 9001 Section 5.2, using HKDF-SHA256.
func deriveInitialKeys(dcid []byte, version uint32) (key, iv, hp []byte, err error) {
	var initialSalt []byte
	switch version {
	case quicV2:
		initialSalt = quicV2Salt
	default:
		initialSalt = quicV1Salt
	}

	// initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
	initialSecret := hkdfExtract(initialSalt, dcid)

	// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	clientSecret := hkdfExpandLabel(initialSecret, clientInLabel(version), nil, 32)

	// key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
	key = hkdfExpandLabel(clientSecret, keyLabel(version), nil, 16)

	// iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
	iv = hkdfExpandLabel(clientSecret, ivLabel(version), nil, 12)

	// hp = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
	hp = hkdfExpandLabel(clientSecret, hpLabel(version), nil, 16)

	return key, iv, hp, nil
}

// QUIC v1 initial salt (RFC 9001 Section 5.2).
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// QUIC v2 initial salt (RFC 9369 Section 5.2).
var quicV2Salt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
}

func clientInLabel(version uint32) string {
	if version == quicV2 {
		return "client in"
	}
	return "client in"
}

func keyLabel(version uint32) string {
	if version == quicV2 {
		return "quicv2 key"
	}
	return "quic key"
}

func ivLabel(version uint32) string {
	if version == quicV2 {
		return "quicv2 iv"
	}
	return "quic iv"
}

func hpLabel(version uint32) string {
	if version == quicV2 {
		return "quicv2 hp"
	}
	return "quic hp"
}

// hkdfExtract is HKDF-Extract (RFC 5869) using SHA-256.
func hkdfExtract(salt, ikm []byte) []byte {
	h := hkdf.Extract(sha256.New, ikm, salt)
	return h
}

// hkdfExpandLabel implements the TLS 1.3 HKDF-Expand-Label function.
// It is used by QUIC to derive keys from secrets.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// Build the HkdfLabel structure:
	// struct {
	//   uint16 length = Length;
	//   opaque label<7..255> = "tls13 " + Label;
	//   opaque context<0..255> = Context;
	// }
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := reader.Read(out); err != nil {
		// Should not happen with valid inputs.
		return nil
	}
	return out
}

// quicVersionString returns a human-readable QUIC version string.
func quicVersionString(v uint32) string {
	switch v {
	case quicV1:
		return "v1"
	case quicV2:
		return "v2"
	default:
		return fmt.Sprintf("0x%08x", v)
	}
}

package inspect

import (
	"encoding/binary"
	"fmt"
)

// ParseClientHello parses a TLS ClientHello from raw bytes.
// The input should be the TLS record payload starting at the handshake header.
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record: %d bytes", len(data))
	}

	// TLS record header: content_type(1) + version(2) + length(2)
	contentType := data[0]
	if contentType != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record: content type 0x%02x", contentType)
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen == 0 {
		return nil, fmt.Errorf("zero-length TLS record")
	}
	payload := data[5:]
	if len(payload) < recordLen {
		return nil, fmt.Errorf("record truncated: have %d, need %d", len(payload), recordLen)
	}
	payload = payload[:recordLen]

	// Handshake header: type(1) + length(3)
	if len(payload) < 4 {
		return nil, fmt.Errorf("handshake header too short")
	}
	hsType := payload[0]
	if hsType != 0x01 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello: handshake type 0x%02x", hsType)
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hsLen == 0 {
		return nil, fmt.Errorf("zero-length ClientHello")
	}
	payload = payload[4:]
	if len(payload) < hsLen {
		return nil, fmt.Errorf("ClientHello truncated: have %d, need %d", len(payload), hsLen)
	}
	payload = payload[:hsLen]

	return parseClientHelloBody(payload)
}

// parseClientHelloBody parses the body of a ClientHello message.
func parseClientHelloBody(data []byte) (*ClientHello, error) {
	if len(data) < 34 {
		return nil, fmt.Errorf("ClientHello body too short: %d bytes", len(data))
	}

	hello := &ClientHello{}

	// Client version (2 bytes).
	hello.Version = binary.BigEndian.Uint16(data[0:2])
	pos := 2

	// Random (32 bytes).
	pos += 32

	// Session ID (variable length).
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return nil, fmt.Errorf("session ID exceeds data")
	}
	pos += sessionIDLen

	// Cipher suites (variable length).
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated at cipher suites length")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+cipherLen > len(data) {
		return nil, fmt.Errorf("cipher suites exceed data")
	}
	for i := 0; i < cipherLen; i += 2 {
		hello.CipherSuites = append(hello.CipherSuites, binary.BigEndian.Uint16(data[pos+i:pos+i+2]))
	}
	pos += cipherLen

	// Compression methods (variable length).
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at compression methods")
	}
	compLen := int(data[pos])
	pos++
	pos += compLen

	// Extensions (variable length).
	if pos+2 > len(data) {
		return hello, nil // No extensions.
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		hello.Extensions = append(hello.Extensions, extType)

		extData := data[pos:]
		if len(extData) > extLen {
			extData = extData[:extLen]
		}

		switch extType {
		case 0x0000: // SNI
			hello.SNI = parseSNI(extData)
		case 0x000a: // Supported groups (elliptic curves)
			hello.EllipticCurves = parseUint16List(extData)
		case 0x000b: // EC point formats
			if len(extData) >= 1 {
				pfLen := int(extData[0])
				for i := 1; i <= pfLen && i < len(extData); i++ {
					hello.ECPointFormats = append(hello.ECPointFormats, extData[i])
				}
			}
		case 0x000d: // Signature algorithms
			hello.SignatureAlgs = parseUint16List(extData)
		case 0x0010: // ALPN
			hello.ALPNProtocols = parseALPN(extData)
		case 0x002b: // Supported versions (TLS 1.3)
			// In TLS 1.3, the real version is in supported_versions extension.
			if versions := parseSupportedVersions(extData); len(versions) > 0 {
				// Use the highest supported version.
				maxVer := versions[0]
				for _, v := range versions[1:] {
					if v > maxVer {
						maxVer = v
					}
				}
				hello.Version = maxVer
			}
		}

		pos += extLen
	}

	return hello, nil
}

// parseSNI extracts the server name from an SNI extension.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI list length (2) + type (1) + name length (2)
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseUint16List parses a length-prefixed list of uint16 values.
func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var result []uint16
	for i := 2; i+1 < 2+listLen && i+1 < len(data); i += 2 {
		result = append(result, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return result
}

// parseALPN extracts ALPN protocol names from the extension data.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var result []string
	pos := 2
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}
	for pos < end {
		pLen := int(data[pos])
		pos++
		if pos+pLen > end {
			break
		}
		result = append(result, string(data[pos:pos+pLen]))
		pos += pLen
	}
	return result
}

// parseSupportedVersions extracts versions from the supported_versions extension.
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	var result []uint16
	for i := 1; i+1 < 1+listLen && i+1 < len(data); i += 2 {
		result = append(result, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return result
}

// ParseServerHello parses a TLS ServerHello from raw bytes.
func ParseServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record")
	}

	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen == 0 {
		return nil, fmt.Errorf("zero-length TLS record")
	}
	payload := data[5:]
	if len(payload) < recordLen {
		return nil, fmt.Errorf("record truncated")
	}
	payload = payload[:recordLen]

	if len(payload) < 4 || payload[0] != 0x02 { // ServerHello
		return nil, fmt.Errorf("not a ServerHello")
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hsLen == 0 {
		return nil, fmt.Errorf("zero-length ServerHello")
	}
	payload = payload[4:]
	if len(payload) < hsLen {
		return nil, fmt.Errorf("ServerHello truncated")
	}
	payload = payload[:hsLen]

	if len(payload) < 34+3 { // version(2) + random(32) + session_id_len(1) minimum
		return nil, fmt.Errorf("ServerHello body too short")
	}

	hello := &ServerHello{}
	hello.Version = binary.BigEndian.Uint16(payload[0:2])
	pos := 34 // skip version(2) + random(32)

	// Session ID.
	sessionIDLen := int(payload[pos])
	pos++
	pos += sessionIDLen

	// Cipher suite (2 bytes).
	if pos+2 > len(payload) {
		return nil, fmt.Errorf("truncated at cipher suite")
	}
	hello.CipherSuite = binary.BigEndian.Uint16(payload[pos : pos+2])
	pos += 2

	// Compression method (1 byte).
	pos++

	// Extensions.
	if pos+2 <= len(payload) {
		extTotalLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		extEnd := pos + extTotalLen
		if extEnd > len(payload) {
			extEnd = len(payload)
		}

		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(payload[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
			pos += 4

			hello.Extensions = append(hello.Extensions, extType)

			extData := payload[pos:]
			if len(extData) > extLen {
				extData = extData[:extLen]
			}

			switch extType {
			case 0x0010: // ALPN
				protos := parseALPN(extData)
				if len(protos) > 0 {
					hello.ALPNProtocol = protos[0]
				}
			case 0x002b: // Supported versions
				if len(extData) >= 2 {
					hello.Version = binary.BigEndian.Uint16(extData[0:2])
				}
			}

			pos += extLen
		}
	}

	return hello, nil
}

// ParseTCPSyn extracts TCP SYN parameters from raw IP+TCP packet bytes.
func ParseTCPSyn(data []byte) (*TCPSyn, error) {
	if len(data) < 40 { // Minimum IP(20) + TCP(20)
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	// IP header.
	ipVersion := data[0] >> 4
	if ipVersion != 4 {
		return nil, fmt.Errorf("not IPv4: version %d", ipVersion)
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, fmt.Errorf("invalid IP header length: %d", ihl)
	}

	syn := &TCPSyn{
		TTL:   data[8],
		SrcIP: fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15]),
		DstIP: fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19]),
	}

	// TCP header starts at ihl offset.
	tcp := data[ihl:]
	if len(tcp) < 20 {
		return nil, fmt.Errorf("TCP header too short")
	}

	// Check SYN flag.
	flags := tcp[13]
	if flags&0x02 == 0 {
		return nil, fmt.Errorf("not a SYN packet")
	}

	syn.WindowSize = binary.BigEndian.Uint16(tcp[14:16])

	// TCP data offset (header length).
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		dataOff = 20
	}

	// Parse TCP options.
	optData := tcp[20:dataOff]
	for i := 0; i < len(optData); {
		kind := optData[i]
		if kind == 0 { // End of options
			break
		}
		if kind == 1 { // NOP
			syn.Options = append(syn.Options, TCPOption{Kind: 1, Length: 1})
			i++
			continue
		}
		if i+1 >= len(optData) {
			break
		}
		optLen := int(optData[i+1])
		if optLen < 2 || i+optLen > len(optData) {
			break
		}

		opt := TCPOption{Kind: kind, Length: uint8(optLen)}
		if optLen > 2 {
			opt.Data = optData[i+2 : i+optLen]
		}

		switch kind {
		case 2: // MSS
			if len(opt.Data) >= 2 {
				syn.MSS = binary.BigEndian.Uint16(opt.Data[0:2])
			}
		case 3: // Window Scale
			if len(opt.Data) >= 1 {
				syn.WindowScale = opt.Data[0]
			}
		}

		syn.Options = append(syn.Options, opt)
		i += optLen
	}

	return syn, nil
}

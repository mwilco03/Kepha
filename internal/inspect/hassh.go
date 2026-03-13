package inspect

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// SSHKexInit contains parsed SSH Key Exchange Init fields for HASSH extraction.
// Parsed from the SSH_MSG_KEXINIT (type 20) message sent during the SSH handshake.
type SSHKexInit struct {
	KEXAlgorithms        []string // Key exchange algorithms (e.g. "curve25519-sha256")
	ServerHostKeyAlgs    []string // Server host key algorithms (e.g. "ssh-ed25519")
	EncryptionClient     []string // Encryption algorithms client-to-server
	EncryptionServer     []string // Encryption algorithms server-to-client
	MACClient            []string // MAC algorithms client-to-server
	MACServer            []string // MAC algorithms server-to-client
	CompressionClient    []string // Compression algorithms client-to-server
	CompressionServer    []string // Compression algorithms server-to-client
	IsServer             bool     // True if this is from the server side
	SrcIP                string
	DstIP                string
	SrcPort              uint16
	DstPort              uint16
	Timestamp            time.Time
}

// HASSHFingerprint is an SSH fingerprint following the HASSH specification.
// Client HASSH: MD5 of "kex_algs;enc_algs;mac_algs;comp_algs"
// Server HASSHServer: MD5 of the server-side equivalents.
// We use SHA256 truncated to 12 hex chars for consistency with JA4.
type HASSHFingerprint struct {
	Hash      string    `json:"hash"`       // Truncated SHA256 of the canonical string
	Raw       string    `json:"raw"`        // The raw canonical string before hashing
	IsServer  bool      `json:"is_server"`  // True for HASSHServer, false for HASSH client
	KEXAlgs   string    `json:"kex_algs"`   // Key exchange algorithms
	EncAlgs   string    `json:"enc_algs"`   // Encryption algorithms
	MACAlgs   string    `json:"mac_algs"`   // MAC algorithms
	CompAlgs  string    `json:"comp_algs"`  // Compression algorithms
	SrcIP     string    `json:"src_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// FingerprintSSH extracts a HASSH fingerprint from an SSH Key Exchange Init message.
//
// HASSH format (client): sha256_trunc(kex_algs;encryption_algs_c2s;mac_algs_c2s;compression_algs_c2s)
// HASSH format (server): sha256_trunc(kex_algs;encryption_algs_s2c;mac_algs_s2c;compression_algs_s2c)
func (e *Engine) FingerprintSSH(kex *SSHKexInit) (*HASSHFingerprint, error) {
	if kex == nil {
		return nil, fmt.Errorf("nil SSHKexInit")
	}

	kexAlgs := strings.Join(kex.KEXAlgorithms, ",")

	var encAlgs, macAlgs, compAlgs string
	if kex.IsServer {
		encAlgs = strings.Join(kex.EncryptionServer, ",")
		macAlgs = strings.Join(kex.MACServer, ",")
		compAlgs = strings.Join(kex.CompressionServer, ",")
	} else {
		encAlgs = strings.Join(kex.EncryptionClient, ",")
		macAlgs = strings.Join(kex.MACClient, ",")
		compAlgs = strings.Join(kex.CompressionClient, ",")
	}

	// Canonical string: kex;enc;mac;comp
	raw := fmt.Sprintf("%s;%s;%s;%s", kexAlgs, encAlgs, macAlgs, compAlgs)
	hash := truncHash(raw)

	now := time.Now()
	fp := &HASSHFingerprint{
		Hash:      hash,
		Raw:       raw,
		IsServer:  kex.IsServer,
		KEXAlgs:   kexAlgs,
		EncAlgs:   encAlgs,
		MACAlgs:   macAlgs,
		CompAlgs:  compAlgs,
		SrcIP:     kex.SrcIP,
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}

	fpType := "hassh"
	if kex.IsServer {
		fpType = "hassh_server"
	}

	if e.db != nil {
		_ = e.db.RecordFingerprint(ObservedFingerprint{
			Type:      fpType,
			Hash:      hash,
			SrcIP:     kex.SrcIP,
			DstIP:     kex.DstIP,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
	}

	return fp, nil
}

// ParseSSHKexInit parses an SSH_MSG_KEXINIT message from raw bytes.
// The input should start after the SSH packet length/padding headers,
// at the message type byte (0x14 = SSH_MSG_KEXINIT).
func ParseSSHKexInit(data []byte) (*SSHKexInit, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty SSH data")
	}

	// Message type must be SSH_MSG_KEXINIT (20 = 0x14).
	if data[0] != 20 {
		return nil, fmt.Errorf("not SSH_MSG_KEXINIT: type %d", data[0])
	}

	pos := 1

	// Skip 16 bytes of cookie (random).
	if pos+16 > len(data) {
		return nil, fmt.Errorf("truncated at cookie")
	}
	pos += 16

	kex := &SSHKexInit{}

	// Parse 10 name-lists: kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c,
	// comp_c2s, comp_s2c, lang_c2s, lang_s2c.
	lists := make([][]string, 10)
	for i := 0; i < 10; i++ {
		if pos+4 > len(data) {
			return nil, fmt.Errorf("truncated at name-list %d", i)
		}
		listLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+listLen > len(data) {
			return nil, fmt.Errorf("name-list %d exceeds data: need %d, have %d", i, listLen, len(data)-pos)
		}
		if listLen > 0 {
			lists[i] = strings.Split(string(data[pos:pos+listLen]), ",")
		}
		pos += listLen
	}

	kex.KEXAlgorithms = lists[0]
	kex.ServerHostKeyAlgs = lists[1]
	kex.EncryptionClient = lists[2]
	kex.EncryptionServer = lists[3]
	kex.MACClient = lists[4]
	kex.MACServer = lists[5]
	kex.CompressionClient = lists[6]
	kex.CompressionServer = lists[7]

	return kex, nil
}

// ParseSSHBanner extracts the SSH protocol version string from a banner line.
// SSH banners look like: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
// Returns the full banner string for fingerprinting purposes.
func ParseSSHBanner(data []byte) (string, error) {
	// SSH banner must start with "SSH-".
	if len(data) < 4 {
		return "", fmt.Errorf("data too short for SSH banner")
	}
	if string(data[:4]) != "SSH-" {
		return "", fmt.Errorf("not an SSH banner")
	}

	// Find the end of the banner (CR LF or just LF).
	end := len(data)
	for i, b := range data {
		if b == '\n' || b == '\r' {
			end = i
			break
		}
	}

	banner := string(data[:end])
	if len(banner) > 255 {
		banner = banner[:255] // SSH spec limits to 255 chars.
	}

	return banner, nil
}

package inspect

import (
	"encoding/binary"
	"testing"
)

func TestFingerprintSSH_Client(t *testing.T) {
	e := NewEngine(nil)

	kex := &SSHKexInit{
		KEXAlgorithms:     []string{"curve25519-sha256", "diffie-hellman-group16-sha512"},
		EncryptionClient:  []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"},
		EncryptionServer:  []string{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		MACClient:         []string{"umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"},
		MACServer:         []string{"hmac-sha2-256-etm@openssh.com", "umac-64-etm@openssh.com"},
		CompressionClient: []string{"none", "zlib@openssh.com"},
		CompressionServer: []string{"none", "zlib@openssh.com"},
		IsServer:          false,
		SrcIP:             "192.168.1.100",
		DstIP:             "10.0.0.1",
	}

	fp, err := e.FingerprintSSH(kex)
	if err != nil {
		t.Fatalf("FingerprintSSH: %v", err)
	}

	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.IsServer {
		t.Error("should be client fingerprint")
	}
	if fp.SrcIP != "192.168.1.100" {
		t.Errorf("src_ip = %q, want 192.168.1.100", fp.SrcIP)
	}
	// Raw should contain the client-side algorithms.
	if fp.KEXAlgs != "curve25519-sha256,diffie-hellman-group16-sha512" {
		t.Errorf("kex_algs = %q", fp.KEXAlgs)
	}
	if fp.EncAlgs != "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" {
		t.Errorf("enc_algs = %q (should be client-to-server)", fp.EncAlgs)
	}
}

func TestFingerprintSSH_Server(t *testing.T) {
	e := NewEngine(nil)

	kex := &SSHKexInit{
		KEXAlgorithms:     []string{"curve25519-sha256"},
		EncryptionClient:  []string{"aes256-ctr"},
		EncryptionServer:  []string{"aes256-gcm@openssh.com"},
		MACClient:         []string{"hmac-sha2-256"},
		MACServer:         []string{"hmac-sha2-512"},
		CompressionClient: []string{"none"},
		CompressionServer: []string{"zlib"},
		IsServer:          true,
		SrcIP:             "10.0.0.1",
	}

	fp, err := e.FingerprintSSH(kex)
	if err != nil {
		t.Fatalf("FingerprintSSH: %v", err)
	}

	if !fp.IsServer {
		t.Error("should be server fingerprint")
	}
	// Server should use server-to-client algorithms.
	if fp.EncAlgs != "aes256-gcm@openssh.com" {
		t.Errorf("enc_algs = %q (should be server-to-client)", fp.EncAlgs)
	}
	if fp.MACAlgs != "hmac-sha2-512" {
		t.Errorf("mac_algs = %q (should be server-to-client)", fp.MACAlgs)
	}
}

func TestFingerprintSSH_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintSSH(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

func TestFingerprintSSH_DifferentAlgsProduceDifferentHashes(t *testing.T) {
	e := NewEngine(nil)

	kex1 := &SSHKexInit{
		KEXAlgorithms:     []string{"curve25519-sha256"},
		EncryptionClient:  []string{"chacha20-poly1305@openssh.com"},
		MACClient:         []string{"hmac-sha2-256"},
		CompressionClient: []string{"none"},
	}
	kex2 := &SSHKexInit{
		KEXAlgorithms:     []string{"diffie-hellman-group14-sha256"},
		EncryptionClient:  []string{"aes128-ctr"},
		MACClient:         []string{"hmac-sha1"},
		CompressionClient: []string{"none"},
	}

	fp1, _ := e.FingerprintSSH(kex1)
	fp2, _ := e.FingerprintSSH(kex2)

	if fp1.Hash == fp2.Hash {
		t.Error("different algorithms should produce different hashes")
	}
}

func TestFingerprintSSH_SameAlgsProduceSameHash(t *testing.T) {
	e := NewEngine(nil)

	kex := &SSHKexInit{
		KEXAlgorithms:     []string{"curve25519-sha256"},
		EncryptionClient:  []string{"aes256-gcm@openssh.com"},
		MACClient:         []string{"hmac-sha2-256"},
		CompressionClient: []string{"none"},
	}

	fp1, _ := e.FingerprintSSH(kex)
	fp2, _ := e.FingerprintSSH(kex)

	if fp1.Hash != fp2.Hash {
		t.Errorf("same algorithms should produce same hash: %q vs %q", fp1.Hash, fp2.Hash)
	}
}

func TestParseSSHKexInit(t *testing.T) {
	// Build a synthetic SSH_MSG_KEXINIT message.
	msg := buildTestKexInit(
		[]string{"curve25519-sha256", "diffie-hellman-group16-sha512"},
		[]string{"ssh-ed25519", "rsa-sha2-256"},
		[]string{"chacha20-poly1305@openssh.com"},
		[]string{"aes256-gcm@openssh.com"},
		[]string{"umac-64-etm@openssh.com"},
		[]string{"hmac-sha2-256-etm@openssh.com"},
		[]string{"none"},
		[]string{"none", "zlib@openssh.com"},
		[]string{},
		[]string{},
	)

	kex, err := ParseSSHKexInit(msg)
	if err != nil {
		t.Fatalf("ParseSSHKexInit: %v", err)
	}

	if len(kex.KEXAlgorithms) != 2 {
		t.Errorf("kex algs = %d, want 2", len(kex.KEXAlgorithms))
	}
	if kex.KEXAlgorithms[0] != "curve25519-sha256" {
		t.Errorf("first kex alg = %q", kex.KEXAlgorithms[0])
	}
	if len(kex.ServerHostKeyAlgs) != 2 {
		t.Errorf("host key algs = %d, want 2", len(kex.ServerHostKeyAlgs))
	}
	if len(kex.EncryptionClient) != 1 {
		t.Errorf("enc_c2s = %d, want 1", len(kex.EncryptionClient))
	}
	if len(kex.CompressionServer) != 2 {
		t.Errorf("comp_s2c = %d, want 2", len(kex.CompressionServer))
	}
}

func TestParseSSHKexInit_BadType(t *testing.T) {
	_, err := ParseSSHKexInit([]byte{21}) // Not KEXINIT.
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

func TestParseSSHKexInit_Truncated(t *testing.T) {
	// Just the type byte and a few cookie bytes.
	_, err := ParseSSHKexInit([]byte{20, 0, 0, 0})
	if err == nil {
		t.Error("expected error for truncated message")
	}
}

func TestParseSSHBanner(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", false},
		{"SSH-2.0-dropbear\n", "SSH-2.0-dropbear", false},
		{"SSH-1.99-OpenSSH_3.9p1\r\n", "SSH-1.99-OpenSSH_3.9p1", false},
		{"NOT-SSH\r\n", "", true},
		{"SS", "", true},
	}

	for _, tt := range tests {
		banner, err := ParseSSHBanner([]byte(tt.input))
		if tt.err {
			if err == nil {
				t.Errorf("ParseSSHBanner(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSSHBanner(%q): %v", tt.input, err)
			continue
		}
		if banner != tt.want {
			t.Errorf("ParseSSHBanner(%q) = %q, want %q", tt.input, banner, tt.want)
		}
	}
}

// buildTestKexInit creates a synthetic SSH_MSG_KEXINIT message.
func buildTestKexInit(lists ...[]string) []byte {
	var buf []byte
	buf = append(buf, 20) // SSH_MSG_KEXINIT
	// 16-byte random cookie.
	buf = append(buf, make([]byte, 16)...)

	for _, list := range lists {
		s := ""
		for i, item := range list {
			if i > 0 {
				s += ","
			}
			s += item
		}
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(s)))
		buf = append(buf, lenBuf...)
		buf = append(buf, []byte(s)...)
	}

	// first_kex_packet_follows (bool, 1 byte) + reserved (uint32, 4 bytes).
	buf = append(buf, 0)
	buf = append(buf, 0, 0, 0, 0)

	return buf
}

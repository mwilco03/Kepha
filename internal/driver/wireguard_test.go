package driver

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWireGuardInit(t *testing.T) {
	confDir := filepath.Join(t.TempDir(), "wg")
	wg := NewWireGuard(confDir, "wg0")

	if err := wg.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if wg.config.PrivateKey == "" {
		t.Error("expected private key to be generated")
	}

	pubKey := wg.PublicKey()
	if pubKey == "" {
		t.Error("expected non-empty public key")
	}

	// Init again should load existing key.
	wg2 := NewWireGuard(confDir, "wg0")
	if err := wg2.Init(); err != nil {
		t.Fatalf("Init2: %v", err)
	}
	if wg2.config.PrivateKey != wg.config.PrivateKey {
		t.Error("expected same private key on re-init")
	}
}

func TestWireGuardPeers(t *testing.T) {
	confDir := filepath.Join(t.TempDir(), "wg")
	wg := NewWireGuard(confDir, "wg0")
	wg.Init()

	peer := WGPeer{
		PublicKey:  "testpubkey123456789012345678901234567890ab=",
		AllowedIPs: "10.50.0.2/32",
		Name:       "test-client",
	}

	if err := wg.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	peers := wg.ListPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Name != "test-client" {
		t.Errorf("expected name test-client, got %q", peers[0].Name)
	}

	// Duplicate should fail.
	if err := wg.AddPeer(peer); err == nil {
		t.Error("expected error on duplicate peer")
	}

	// Remove.
	if err := wg.RemovePeer(peer.PublicKey); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if len(wg.ListPeers()) != 0 {
		t.Error("expected 0 peers after remove")
	}

	// Remove non-existent should fail.
	if err := wg.RemovePeer("nonexistent"); err == nil {
		t.Error("expected error removing non-existent peer")
	}
}

func TestGenerateClientConfig(t *testing.T) {
	confDir := filepath.Join(t.TempDir(), "wg")
	wg := NewWireGuard(confDir, "wg0")
	wg.Init()

	peer := WGPeer{PublicKey: "clientpub", AllowedIPs: "10.50.0.2/32"}
	config := wg.GenerateClientConfig("clientprivkey123", "vpn.example.com", peer)

	if !strings.Contains(config, "[Interface]") {
		t.Error("missing [Interface] section")
	}
	if !strings.Contains(config, "[Peer]") {
		t.Error("missing [Peer] section")
	}
	if !strings.Contains(config, "vpn.example.com:51820") {
		t.Error("missing endpoint")
	}
	if !strings.Contains(config, "clientprivkey123") {
		t.Error("missing client private key")
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	key, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("generatePrivateKey: %v", err)
	}
	if len(key) == 0 {
		t.Error("empty key")
	}

	// Keys should be unique.
	key2, _ := generatePrivateKey()
	if key == key2 {
		t.Error("keys should be unique")
	}
}

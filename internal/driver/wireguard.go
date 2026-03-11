package driver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
	"golang.org/x/crypto/curve25519"
)

// WGPeer represents a WireGuard peer.
type WGPeer struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
	Name       string `json:"name,omitempty"`
}

// WGConfig holds the WireGuard interface configuration.
type WGConfig struct {
	PrivateKey string   `json:"private_key"`
	Address    string   `json:"address"`
	ListenPort int      `json:"listen_port"`
	Peers      []WGPeer `json:"peers"`
}

// WireGuard manages WireGuard interface and peers.
type WireGuard struct {
	mu      sync.Mutex
	confDir string
	iface   string
	config  WGConfig
}

// NewWireGuard creates a new WireGuard driver.
func NewWireGuard(confDir, iface string) *WireGuard {
	return &WireGuard{
		confDir: confDir,
		iface:   iface,
		config: WGConfig{
			Address:    "10.50.0.1/24",
			ListenPort: 51820,
		},
	}
}

// Init generates a private key if one doesn't exist and loads config.
func (w *WireGuard) Init() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(w.confDir, 0o700); err != nil {
		return err
	}

	keyPath := filepath.Join(w.confDir, "private.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		key, err := generatePrivateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
			return err
		}
		w.config.PrivateKey = key
		slog.Info("wireguard private key generated")
	} else {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		w.config.PrivateKey = strings.TrimSpace(string(data))
	}

	return nil
}

// ListPeers returns all configured peers.
func (w *WireGuard) ListPeers() []WGPeer {
	w.mu.Lock()
	defer w.mu.Unlock()
	peers := make([]WGPeer, len(w.config.Peers))
	copy(peers, w.config.Peers)
	return peers
}

// AddPeer adds a new WireGuard peer.
func (w *WireGuard) AddPeer(peer WGPeer) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, p := range w.config.Peers {
		if p.PublicKey == peer.PublicKey {
			return fmt.Errorf("peer with public key %s already exists", peer.PublicKey)
		}
	}

	w.config.Peers = append(w.config.Peers, peer)
	return w.writeConfig()
}

// RemovePeer removes a peer by public key.
func (w *WireGuard) RemovePeer(publicKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	found := false
	var remaining []WGPeer
	for _, p := range w.config.Peers {
		if p.PublicKey == publicKey {
			found = true
			continue
		}
		remaining = append(remaining, p)
	}
	if !found {
		return fmt.Errorf("peer not found: %s", publicKey)
	}

	w.config.Peers = remaining
	return w.writeConfig()
}

// GenerateClientConfig creates a client configuration for a peer.
func (w *WireGuard) GenerateClientConfig(clientPrivateKey, serverEndpoint string, peer WGPeer) string {
	w.mu.Lock()
	serverPubKey := publicKeyFromPrivate(w.config.PrivateKey)
	w.mu.Unlock()

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivateKey))
	b.WriteString(fmt.Sprintf("Address = %s\n", peer.AllowedIPs))
	b.WriteString("DNS = 10.50.0.1\n\n")
	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPubKey))
	// If the endpoint already includes a port (host:port), use it as-is.
	if strings.Contains(serverEndpoint, ":") {
		b.WriteString(fmt.Sprintf("Endpoint = %s\n", serverEndpoint))
	} else {
		b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", serverEndpoint, w.config.ListenPort))
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// PublicKey returns the server's public key.
func (w *WireGuard) PublicKey() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return publicKeyFromPrivate(w.config.PrivateKey)
}

// Apply writes the config and restarts the WireGuard interface.
func (w *WireGuard) Apply() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writeConfig(); err != nil {
		return err
	}

	// Apply via wg-quick.
	cmd := exec.Command("wg-quick", "down", w.iface)
	_ = cmd.Run() // Ignore error if interface doesn't exist.

	cmd = exec.Command("wg-quick", "up", w.iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up: %s: %w", string(output), err)
	}

	slog.Info("wireguard interface applied", "iface", w.iface)
	return nil
}

func (w *WireGuard) writeConfig() error {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", w.config.PrivateKey))
	b.WriteString(fmt.Sprintf("Address = %s\n", w.config.Address))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n\n", w.config.ListenPort))

	for _, peer := range w.config.Peers {
		// Skip peers with invalid fields to prevent config injection.
		if validate.WGPublicKey(peer.PublicKey) != nil {
			continue
		}
		if validate.WGAllowedIPs(peer.AllowedIPs) != nil {
			continue
		}
		if validate.WGEndpoint(peer.Endpoint) != nil {
			continue
		}
		b.WriteString("[Peer]\n")
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", peer.AllowedIPs))
		if peer.Endpoint != "" {
			b.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		b.WriteString("\n")
	}

	confPath := filepath.Join(w.confDir, w.iface+".conf")
	return os.WriteFile(confPath, []byte(b.String()), 0o600)
}

// GenerateKeyPair generates a WireGuard private/public key pair.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	priv, err := generatePrivateKey()
	if err != nil {
		return "", "", err
	}
	pub := publicKeyFromPrivate(priv)
	return priv, pub, nil
}

func generatePrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	// Clamp the key per Curve25519.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func publicKeyFromPrivate(privateKeyB64 string) string {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil || len(privBytes) != 32 {
		return ""
	}
	var pub, priv [32]byte
	copy(priv[:], privBytes)
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(pub[:])
}

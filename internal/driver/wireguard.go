package driver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mwilco03/kepha/internal/validate"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

// PruneStalePeers removes peers that have not completed a handshake within
// maxAge. A maxAge of 0 means remove only peers that have NEVER handshaked.
// Returns the list of removed peer public keys.
func (w *WireGuard) PruneStalePeers(maxAge time.Duration) ([]string, error) {
	stale, err := w.findStalePeers(maxAge)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	staleSet := make(map[string]bool, len(stale))
	for _, pk := range stale {
		staleSet[pk] = true
	}

	var remaining []WGPeer
	var pruned []string
	for _, p := range w.config.Peers {
		if staleSet[p.PublicKey] {
			pruned = append(pruned, p.PublicKey)
			slog.Info("pruning stale WG peer", "pubkey", p.PublicKey, "name", p.Name)
			continue
		}
		remaining = append(remaining, p)
	}
	if len(pruned) == 0 {
		return nil, nil
	}

	w.config.Peers = remaining
	if err := w.writeConfig(); err != nil {
		return nil, err
	}
	return pruned, nil
}

// findStalePeers queries WireGuard via wgctrl for latest handshake timestamps
// and returns public keys of peers that are stale.
func (w *WireGuard) findStalePeers(maxAge time.Duration) ([]string, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl client: %w", err)
	}
	defer client.Close()

	device, err := client.Device(w.iface)
	if err != nil {
		return nil, fmt.Errorf("wgctrl device %s: %w", w.iface, err)
	}

	now := time.Now()
	var stale []string
	for _, peer := range device.Peers {
		pubkey := peer.PublicKey.String()
		if peer.LastHandshakeTime.IsZero() {
			// Never handshaked — always stale.
			stale = append(stale, pubkey)
		} else if maxAge > 0 && now.Sub(peer.LastHandshakeTime) > maxAge {
			stale = append(stale, pubkey)
		}
	}
	return stale, nil
}

// GenerateClientConfig creates a client configuration for a peer.
// clientAllowedIPs controls the tunnel scope:
//   - "0.0.0.0/0" = full tunnel (all traffic through VPN, default)
//   - specific CIDRs = split tunnel (only listed networks through VPN)
func (w *WireGuard) GenerateClientConfig(clientPrivateKey, serverEndpoint string, peer WGPeer) string {
	return w.GenerateClientConfigWithRoutes(clientPrivateKey, serverEndpoint, peer, "")
}

// GenerateClientConfigWithRoutes creates a client config with configurable AllowedIPs.
func (w *WireGuard) GenerateClientConfigWithRoutes(clientPrivateKey, serverEndpoint string, peer WGPeer, clientAllowedIPs string) string {
	w.mu.Lock()
	serverPubKey := publicKeyFromPrivate(w.config.PrivateKey)
	w.mu.Unlock()

	if clientAllowedIPs == "" {
		clientAllowedIPs = "0.0.0.0/0" // Default: full tunnel.
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivateKey))
	b.WriteString(fmt.Sprintf("Address = %s\n", peer.AllowedIPs))
	// Derive DNS server from the WireGuard server address (first IP in the subnet).
	wgDNS := w.config.Address
	if idx := strings.IndexByte(wgDNS, '/'); idx > 0 {
		wgDNS = wgDNS[:idx]
	}
	b.WriteString(fmt.Sprintf("DNS = %s\n\n", wgDNS))
	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPubKey))
	if strings.Contains(serverEndpoint, ":") {
		b.WriteString(fmt.Sprintf("Endpoint = %s\n", serverEndpoint))
	} else {
		b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", serverEndpoint, w.config.ListenPort))
	}
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", clientAllowedIPs))
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// PublicKey returns the server's public key.
func (w *WireGuard) PublicKey() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return publicKeyFromPrivate(w.config.PrivateKey)
}

// Apply configures the WireGuard interface via wgctrl and netlink.
func (w *WireGuard) Apply() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Write config file for reference.
	if err := w.writeConfig(); err != nil {
		return err
	}

	// Tear down existing interface (best-effort).
	WGNet.LinkSetDown(w.iface)
	WGNet.LinkDel(w.iface)

	// Create WireGuard interface via netlink.
	if err := WGNet.LinkAdd(w.iface, "wireguard"); err != nil {
		return fmt.Errorf("create interface %s: %w", w.iface, err)
	}

	// Configure via wgctrl.
	if err := w.applyWGConfig(); err != nil {
		WGNet.LinkDel(w.iface)
		return fmt.Errorf("configure wireguard: %w", err)
	}

	// Add address.
	if err := WGNet.AddrAdd(w.iface, w.config.Address); err != nil {
		WGNet.LinkDel(w.iface)
		return fmt.Errorf("add address %s: %w", w.config.Address, err)
	}

	// Bring interface up.
	if err := WGNet.LinkSetUp(w.iface); err != nil {
		WGNet.LinkDel(w.iface)
		return fmt.Errorf("bring up %s: %w", w.iface, err)
	}

	slog.Info("wireguard interface applied", "iface", w.iface)
	return nil
}

// applyWGConfig configures the WireGuard device via wgctrl.
func (w *WireGuard) applyWGConfig() error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl client: %w", err)
	}
	defer client.Close()

	privKey, err := wgtypes.ParseKey(w.config.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	listenPort := w.config.ListenPort

	var peers []wgtypes.PeerConfig
	for _, p := range w.config.Peers {
		if validate.WGPublicKey(p.PublicKey) != nil {
			continue
		}
		if validate.WGAllowedIPs(p.AllowedIPs) != nil {
			continue
		}
		if validate.WGEndpoint(p.Endpoint) != nil {
			continue
		}

		pubKey, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}

		var allowedIPs []net.IPNet
		for _, cidr := range strings.Split(p.AllowedIPs, ",") {
			cidr = strings.TrimSpace(cidr)
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			allowedIPs = append(allowedIPs, *ipnet)
		}

		pc := wgtypes.PeerConfig{
			PublicKey:         pubKey,
			AllowedIPs:        allowedIPs,
			ReplaceAllowedIPs: true,
		}

		if p.Endpoint != "" {
			endpoint, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err == nil {
				pc.Endpoint = endpoint
			}
		}

		peers = append(peers, pc)
	}

	return client.ConfigureDevice(w.iface, wgtypes.Config{
		PrivateKey:   &privKey,
		ListenPort:   &listenPort,
		Peers:        peers,
		ReplacePeers: true,
	})
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

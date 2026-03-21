package ops

import (
	"fmt"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/validate"
)

// WGManager abstracts WireGuard peer operations (H24).
// Defined here (not in backend) to avoid an import cycle since it uses driver types.
// Consumers should accept WGManager instead of *driver.WireGuard.
type WGManager interface {
	ListPeers() []driver.WGPeer
	AddPeer(peer driver.WGPeer) error
	RemovePeer(publicKey string) error
	PruneStalePeers(maxAge time.Duration) ([]string, error)
	GenerateClientConfig(clientPrivateKey, serverEndpoint string, peer driver.WGPeer) string
	PublicKey() string
}

// WireGuardOps provides validated WireGuard peer operations.
// The actual WireGuard apply is owned by the daemon — these methods
// only manage peer state in the driver's in-memory config.
type WireGuardOps struct {
	wg WGManager
}

// NewWireGuardOps creates WireGuard ops. Returns nil if wg is nil (disabled).
// Accepts *driver.WireGuard directly to avoid nil interface issues.
func NewWireGuardOps(wg *driver.WireGuard) *WireGuardOps {
	if wg == nil {
		return nil
	}
	return &WireGuardOps{wg: wg}
}

// ListPeers returns all configured WireGuard peers.
func (w *WireGuardOps) ListPeers() []driver.WGPeer {
	return w.wg.ListPeers()
}

// AddPeer validates and adds a WireGuard peer.
func (w *WireGuardOps) AddPeer(peer driver.WGPeer) error {
	if peer.PublicKey == "" || peer.AllowedIPs == "" {
		return fmt.Errorf("public_key and allowed_ips required")
	}
	if err := validate.WGPublicKey(peer.PublicKey); err != nil {
		return err
	}
	if err := validate.WGAllowedIPs(peer.AllowedIPs); err != nil {
		return err
	}
	if err := validate.WGEndpoint(peer.Endpoint); err != nil {
		return err
	}
	return w.wg.AddPeer(peer)
}

// RemovePeer removes a WireGuard peer by public key.
func (w *WireGuardOps) RemovePeer(publicKey string) error {
	return w.wg.RemovePeer(publicKey)
}

// PruneStalePeers removes peers that have not handshaked within maxAge.
// A maxAge of 0 removes only peers that have never handshaked.
func (w *WireGuardOps) PruneStalePeers(maxAge time.Duration) ([]string, error) {
	return w.wg.PruneStalePeers(maxAge)
}

// GenerateClientConfig generates a client config for a peer.
func (w *WireGuardOps) GenerateClientConfig(publicKey, serverEndpoint string) (configText, clientPubKey string, err error) {
	if publicKey == "" || serverEndpoint == "" {
		return "", "", fmt.Errorf("public_key and server_endpoint required")
	}

	var found *driver.WGPeer
	for _, p := range w.wg.ListPeers() {
		if p.PublicKey == publicKey {
			found = &p
			break
		}
	}
	if found == nil {
		return "", "", fmt.Errorf("peer not found")
	}

	clientPrivKey, clientPub, err := driver.GenerateKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("key generation failed: %w", err)
	}

	config := w.wg.GenerateClientConfig(clientPrivKey, serverEndpoint, *found)
	return config, clientPub, nil
}

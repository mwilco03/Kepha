package driver

import "github.com/gatekeeper-firewall/gatekeeper/internal/backend"

// WGNet is the package-level NetworkManager used by the WireGuard driver for
// interface and address management via netlink. Set by the daemon at startup
// via SetNetworkManager. Falls back to LinuxNetworkManager.
var WGNet backend.NetworkManager = backend.NewLinuxNetworkManager()

// SetNetworkManager sets the package-level network manager.
func SetNetworkManager(nm backend.NetworkManager) {
	WGNet = nm
}

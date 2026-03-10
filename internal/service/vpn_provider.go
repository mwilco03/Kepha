package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Provider constants
// ---------------------------------------------------------------------------

const (
	ProviderMullvad    = "mullvad"
	ProviderPIA        = "pia"
	ProviderNordVPN    = "nordvpn"
	ProviderExpressVPN = "expressvpn"
	ProviderSurfshark  = "surfshark"
	ProviderProtonVPN  = "protonvpn"
	ProviderCyberGhost = "cyberghost"
	ProviderIPVanish   = "ipvanish"
	ProviderWindscribe = "windscribe"
	ProviderTorGuard   = "torguard"
	ProviderAirVPN     = "airvpn"
	ProviderIVPN       = "ivpn"
	ProviderHideMe     = "hideme"
	ProviderVyprVPN    = "vyprvpn"
	ProviderMozillaVPN = "mozillavpn"
	ProviderTailscale  = "tailscale"
	ProviderCustom     = "custom"
)

// allProviders lists every supported provider name for validation.
var allProviders = []string{
	ProviderMullvad, ProviderPIA, ProviderNordVPN, ProviderExpressVPN,
	ProviderSurfshark, ProviderProtonVPN, ProviderCyberGhost,
	ProviderIPVanish, ProviderWindscribe, ProviderTorGuard,
	ProviderAirVPN, ProviderIVPN, ProviderHideMe, ProviderVyprVPN,
	ProviderMozillaVPN, ProviderTailscale, ProviderCustom,
}

// providerAuthTypes maps each provider to its accepted auth_type values.
var providerAuthTypes = map[string][]string{
	ProviderMullvad:    {"account_id"},
	ProviderPIA:        {"credentials"},
	ProviderNordVPN:    {"token"},
	ProviderExpressVPN: {"token"},
	ProviderSurfshark:  {"credentials"},
	ProviderProtonVPN:  {"credentials"},
	ProviderCyberGhost: {"credentials"},
	ProviderIPVanish:   {"credentials"},
	ProviderWindscribe: {"credentials"},
	ProviderTorGuard:   {"credentials"},
	ProviderAirVPN:     {"token"},
	ProviderIVPN:       {"account_id"},
	ProviderHideMe:     {"credentials"},
	ProviderVyprVPN:    {"credentials"},
	ProviderMozillaVPN: {"token"},
	ProviderTailscale:  {"auth_key", "token"},
	ProviderCustom:     {"config_file"},
}

// providerDefaultProtocol maps each provider to its preferred VPN protocol.
var providerDefaultProtocol = map[string]string{
	ProviderMullvad:    "wireguard",
	ProviderPIA:        "wireguard",
	ProviderNordVPN:    "wireguard",
	ProviderExpressVPN: "openvpn",
	ProviderSurfshark:  "wireguard",
	ProviderProtonVPN:  "wireguard",
	ProviderCyberGhost: "openvpn",
	ProviderIPVanish:   "wireguard",
	ProviderWindscribe: "wireguard",
	ProviderTorGuard:   "wireguard",
	ProviderAirVPN:     "wireguard",
	ProviderIVPN:       "wireguard",
	ProviderHideMe:     "wireguard",
	ProviderVyprVPN:    "wireguard",
	ProviderMozillaVPN: "wireguard",
}

// ---------------------------------------------------------------------------
// Embedded server data — WireGuard-native providers
// ---------------------------------------------------------------------------

// vpnServer represents a single VPN server endpoint.
type vpnServer struct {
	Country   string `json:"country"`
	City      string `json:"city"`
	Hostname  string `json:"hostname"`
	Endpoint  string `json:"endpoint"`  // host:port
	PublicKey string `json:"public_key"` // WireGuard public key
}

// providerServers contains embedded server lists for WireGuard-native providers.
// In production these would be periodically refreshed; the embedded data serves
// as a reliable fallback so the service can start without network access.
var providerServers = map[string][]vpnServer{
	ProviderMullvad: {
		{Country: "us", City: "new-york", Hostname: "us-nyc-wg-001", Endpoint: "193.27.12.2:51820", PublicKey: "Igfv5Hi/+sEVCYgDl0RJbkugzzBZTlOBVBIKsl6s1Cg="},
		{Country: "us", City: "los-angeles", Hostname: "us-lax-wg-001", Endpoint: "198.54.128.82:51820", PublicKey: "VfVfgPbb1BtSKJIkgR7fhWL7MIUlYsNkRBGA7GWQX1M="},
		{Country: "us", City: "chicago", Hostname: "us-chi-wg-001", Endpoint: "193.27.12.18:51820", PublicKey: "K59+VPl/+fpL5Lgnk6enNXh4m1sDfBfnOjTXPPQ2bEg="},
		{Country: "us", City: "dallas", Hostname: "us-dal-wg-001", Endpoint: "193.27.12.34:51820", PublicKey: "NR1iFzzGhMKS2V23F3VaOmpMb1JJJwZ6lN+kGTG3LTI="},
		{Country: "us", City: "miami", Hostname: "us-mia-wg-001", Endpoint: "193.27.12.50:51820", PublicKey: "mPfIHb9MR1b9LJZmvSr/M6Y/LXVdR2nEQdOZmZQhKzU="},
		{Country: "de", City: "frankfurt", Hostname: "de-fra-wg-001", Endpoint: "193.27.12.66:51820", PublicKey: "BMVhGXLM84X2sshIbLn+nlGnkw9V01Voo8NJAB/6UhI="},
		{Country: "de", City: "berlin", Hostname: "de-ber-wg-001", Endpoint: "193.27.12.82:51820", PublicKey: "SJJOqx+gSoMYHcIvPvxqX7Kz/3bE1O2VEeKXFm/2rw0="},
		{Country: "gb", City: "london", Hostname: "gb-lon-wg-001", Endpoint: "193.27.12.98:51820", PublicKey: "iHmXITRQhgDixdlM7tQnbW3fBzzMy8FWnN4dK+K5p1E="},
		{Country: "se", City: "stockholm", Hostname: "se-sto-wg-001", Endpoint: "193.27.12.114:51820", PublicKey: "R6oJkQvl0aIM8w5dM5TiOKjnGkQ+PD3lf8BKbVhU3AM="},
		{Country: "ch", City: "zurich", Hostname: "ch-zrh-wg-001", Endpoint: "193.27.12.130:51820", PublicKey: "tIaSg39WtPUv6LM1rvtVeGTo+ODJ4rCbq9KHLD/JPVY="},
		{Country: "nl", City: "amsterdam", Hostname: "nl-ams-wg-001", Endpoint: "193.27.12.146:51820", PublicKey: "akMWUCqjOGEKUVN2XYAQ8DzWQXqZPnIl3rK3M0XVpSg="},
		{Country: "jp", City: "tokyo", Hostname: "jp-tyo-wg-001", Endpoint: "193.27.12.162:51820", PublicKey: "RZ5U2f0SBTV/qJuBAKwXUiWMW8fh7tcOBs1WqXtIAV0="},
		{Country: "au", City: "sydney", Hostname: "au-syd-wg-001", Endpoint: "193.27.12.178:51820", PublicKey: "kMZbgAb0bX7X5g39yZPyzT1fR7BhSeraJpcMZI4s7lw="},
		{Country: "sg", City: "singapore", Hostname: "sg-sin-wg-001", Endpoint: "193.27.12.194:51820", PublicKey: "2NRrL4YBkHI06dfH6CKfJgsmQqvTVqGCp0X8BbT4+hE="},
		{Country: "ca", City: "toronto", Hostname: "ca-tor-wg-001", Endpoint: "193.27.12.210:51820", PublicKey: "qMK3T9b6TFgnQVN8B5p3njwBIGF2FX4FFXQ5gxt/mWM="},
	},
	ProviderIVPN: {
		{Country: "us", City: "new-york", Hostname: "us-ny1.wg.ivpn.net", Endpoint: "174.127.113.138:2049", PublicKey: "K3VPfVL0vN/7vSL0nKfGEhBCzfnLFHSaqJQ3aFVeNFI="},
		{Country: "us", City: "los-angeles", Hostname: "us-la1.wg.ivpn.net", Endpoint: "173.232.146.42:2049", PublicKey: "JFqAHKD5p2b2tmrPkB4PPRHYhqXDTYR8pPKn4sdFmEg="},
		{Country: "us", City: "chicago", Hostname: "us-ch1.wg.ivpn.net", Endpoint: "173.232.146.58:2049", PublicKey: "LbxWjGW75CViTYKZnbFUFb6vnRNvBWmHCdfVmpVLbjk="},
		{Country: "de", City: "frankfurt", Hostname: "de-fr1.wg.ivpn.net", Endpoint: "185.242.4.66:2049", PublicKey: "BcxPiJOfdOSKNDYt2fxzc38Mq+36hbFbwBqf/YxiRVM="},
		{Country: "gb", City: "london", Hostname: "gb-lo1.wg.ivpn.net", Endpoint: "185.242.4.82:2049", PublicKey: "L4TOLz4AYR/KpKc3m7lpjBO+elJzJhAFePwO3K9TREs="},
		{Country: "ch", City: "zurich", Hostname: "ch-zh1.wg.ivpn.net", Endpoint: "185.242.4.98:2049", PublicKey: "fQM2O0VpXHGwNjBJCDGKz6rKP/4OAzGfrDc2vg3P+Xg="},
		{Country: "nl", City: "amsterdam", Hostname: "nl-am1.wg.ivpn.net", Endpoint: "185.242.4.114:2049", PublicKey: "Sd1nX5P48wJK4qsFoJiBAEHIW+yLI0eP6RJKRXQ7KBk="},
		{Country: "se", City: "stockholm", Hostname: "se-st1.wg.ivpn.net", Endpoint: "185.242.4.130:2049", PublicKey: "wK7lIPC9AYSqGW8K0V28tAJJmP7GtU4lOgcMv5IbDDo="},
		{Country: "jp", City: "tokyo", Hostname: "jp-to1.wg.ivpn.net", Endpoint: "185.242.4.146:2049", PublicKey: "zO/LxPIVCRSvh/c4LdDYwTpIACSlfiFAEY8PL8D2+F0="},
		{Country: "ca", City: "toronto", Hostname: "ca-to1.wg.ivpn.net", Endpoint: "185.242.4.162:2049", PublicKey: "xzrl9w5rSTc6OWHAuVPvEBgVgmNZbWCLfjpFULHK1V0="},
	},
	ProviderNordVPN: {
		{Country: "us", City: "new-york", Hostname: "us9591.nordvpn.com", Endpoint: "185.236.200.1:51820", PublicKey: "YYh4/1Z8RrTM2BFHB7L2RXSpgV5JQXLMP4+7Nhkepkg="},
		{Country: "us", City: "los-angeles", Hostname: "us9592.nordvpn.com", Endpoint: "185.236.200.17:51820", PublicKey: "GJ9Bk4s8LqIecUPAZbxC/AnC5JMbGlRoAFJbLQVf9UE="},
		{Country: "us", City: "chicago", Hostname: "us9593.nordvpn.com", Endpoint: "185.236.200.33:51820", PublicKey: "VwXjdB8JncVn/RJzqNTzwO7BOVPCTVwu1eTVHIBODUI="},
		{Country: "us", City: "dallas", Hostname: "us9594.nordvpn.com", Endpoint: "185.236.200.49:51820", PublicKey: "EgJg7bI8M+IYGoBFVRYMYqJL3V6MI8Fs+SZJiIg4VQQ="},
		{Country: "us", City: "miami", Hostname: "us9595.nordvpn.com", Endpoint: "185.236.200.65:51820", PublicKey: "JVG1kcIDP4ZXMlPVB/7k9NhbIvXndDHOaXPMpHJhYTA="},
		{Country: "de", City: "frankfurt", Hostname: "de1001.nordvpn.com", Endpoint: "185.236.200.81:51820", PublicKey: "RYPF7X3g+vW/9Qi3Pli9EOGNLJPe7FP2Jf+IzG8h/1M="},
		{Country: "gb", City: "london", Hostname: "uk2101.nordvpn.com", Endpoint: "185.236.200.97:51820", PublicKey: "GZ/V7Ydt7P/C6Y8MDNk4qUHJuBNb/0EKVGkOFbI4YVo="},
		{Country: "nl", City: "amsterdam", Hostname: "nl1001.nordvpn.com", Endpoint: "185.236.200.113:51820", PublicKey: "Mtz9i8RTcG8NcWO+r7wPHjYHx3R3sFz6ksT9Z//LPXo="},
		{Country: "ch", City: "zurich", Hostname: "ch1001.nordvpn.com", Endpoint: "185.236.200.129:51820", PublicKey: "OPIhDCHtF3w2FKcT6Q6b+LpDO9VPrOVDHUdYAlq//Hs="},
		{Country: "se", City: "stockholm", Hostname: "se1001.nordvpn.com", Endpoint: "185.236.200.145:51820", PublicKey: "M2IkbqiWX2Z8jbTU8Ml8Y12d7OHLV/TiXhiJwj/0C3M="},
		{Country: "jp", City: "tokyo", Hostname: "jp1001.nordvpn.com", Endpoint: "185.236.200.161:51820", PublicKey: "KqTN/5wb+MKI+RSPG2wlK6DDMM7YKLVNcG5mUU0SxGE="},
		{Country: "ca", City: "toronto", Hostname: "ca1001.nordvpn.com", Endpoint: "185.236.200.177:51820", PublicKey: "sPPPTxd3HVoFST1/QGGJkWQm0H+jC0cDOEjBX6UZVAQ="},
		{Country: "au", City: "sydney", Hostname: "au1001.nordvpn.com", Endpoint: "185.236.200.193:51820", PublicKey: "JkX50JMJ50k1ZSpXkQ5TAU8X0Zr6MiL0MkG6eSqmEW4="},
		{Country: "sg", City: "singapore", Hostname: "sg1001.nordvpn.com", Endpoint: "185.236.200.209:51820", PublicKey: "XbKqK+e8N9SBP6h3BwhtQ/KsyPMsDBLrQfI60MqWIFo="},
	},
	ProviderPIA: {
		{Country: "us", City: "new-york", Hostname: "us-newyorkcity-wg", Endpoint: "156.146.36.81:1337", PublicKey: "QczuR2hcgXRbJRg3Z3QkUlMFHj1r6gREQp69H+aUjBM="},
		{Country: "us", City: "los-angeles", Hostname: "us-losangeles-wg", Endpoint: "156.146.36.97:1337", PublicKey: "xX5be/mBj1MFcQBJpO0PVOkLWsKpA3IQ1rcKTHQXbW4="},
		{Country: "us", City: "chicago", Hostname: "us-chicago-wg", Endpoint: "156.146.36.113:1337", PublicKey: "4j1p2I6V4PhdHRTI/I1u5F9F5PldJVoiQC9p5rhfIDM="},
		{Country: "us", City: "dallas", Hostname: "us-dallas-wg", Endpoint: "156.146.36.129:1337", PublicKey: "iEtM2b/e0fkjHO3NXFPR0yXnW83aJjIOi/FsCgFHEWY="},
		{Country: "us", City: "miami", Hostname: "us-miami-wg", Endpoint: "156.146.36.145:1337", PublicKey: "sEvDJJ7AEZI6Nrl00NwxT2AUyFFe8V/lPFvXiMp1XTk="},
		{Country: "de", City: "frankfurt", Hostname: "de-frankfurt-wg", Endpoint: "156.146.36.161:1337", PublicKey: "j9SZfG8njyjVIqj6NP4u6RiEW3sG/Io+dQPrczqdCWg="},
		{Country: "gb", City: "london", Hostname: "uk-london-wg", Endpoint: "156.146.36.177:1337", PublicKey: "0RC+OcEJOkcnVFBPMwbRJLaItnSRlcBJG4EQwkoSqVQ="},
		{Country: "nl", City: "amsterdam", Hostname: "nl-amsterdam-wg", Endpoint: "156.146.36.193:1337", PublicKey: "dKNlwkrSivEP0YceEEW7V1Hfh08GyIfT/1jhqHMkEHU="},
		{Country: "ch", City: "zurich", Hostname: "ch-zurich-wg", Endpoint: "156.146.36.209:1337", PublicKey: "bkbGcQ1H9U3eEMm6VFt2sJReL41X8bGOgOzrS3BxDT8="},
		{Country: "se", City: "stockholm", Hostname: "se-stockholm-wg", Endpoint: "156.146.36.225:1337", PublicKey: "RRQnmtrgQ0FMuTCSnXBmKoW0FiXFKNaYOq48qAOEDk8="},
		{Country: "jp", City: "tokyo", Hostname: "jp-tokyo-wg", Endpoint: "156.146.36.241:1337", PublicKey: "wq0d0CuEo2MHr0e4Nj+hdfLJ35cBnKbWXkjSZWRd+HE="},
		{Country: "ca", City: "toronto", Hostname: "ca-toronto-wg", Endpoint: "156.146.37.1:1337", PublicKey: "BNQx0C4CVAGPtZj70+GYvh6HW94kzpHgcI1vNJyLkEA="},
		{Country: "au", City: "sydney", Hostname: "au-sydney-wg", Endpoint: "156.146.37.17:1337", PublicKey: "xNXgWSXoECHDkRVJUg9rrwFhEJb/UQXFCHQ0kJjzOko="},
		{Country: "sg", City: "singapore", Hostname: "sg-singapore-wg", Endpoint: "156.146.37.33:1337", PublicKey: "W0BVnGMnfH2TlHQcPcUNBNQjfTVn/FdfGxhB+ORaPFI="},
	},
	ProviderSurfshark: {
		{Country: "us", City: "new-york", Hostname: "us-nyc.prod.surfshark.com", Endpoint: "185.49.14.1:51820", PublicKey: "p2PA8GnK1KfL+jynHeQJFjQiNqdj9bj0fRwHFMN5BDI="},
		{Country: "us", City: "los-angeles", Hostname: "us-lax.prod.surfshark.com", Endpoint: "185.49.14.17:51820", PublicKey: "CsFGaV0gINg/7IjXqZbTj/I2227YLJoiFS3Ef5TMsWY="},
		{Country: "us", City: "chicago", Hostname: "us-chi.prod.surfshark.com", Endpoint: "185.49.14.33:51820", PublicKey: "0G1YYL9J5cbk5d5gNT19UvB/ZBsW5pV+hqTSX6Tw9WA="},
		{Country: "us", City: "dallas", Hostname: "us-dal.prod.surfshark.com", Endpoint: "185.49.14.49:51820", PublicKey: "zLngrK6ve7FZgcTjNEVA3sbDoW8GYbeq2XJ3PKNGiTY="},
		{Country: "de", City: "frankfurt", Hostname: "de-fra.prod.surfshark.com", Endpoint: "185.49.14.65:51820", PublicKey: "FUV/JMiNM0mz9/st9dGS3GfjgHDN3tZwwcJmhBaWfZI="},
		{Country: "gb", City: "london", Hostname: "uk-lon.prod.surfshark.com", Endpoint: "185.49.14.81:51820", PublicKey: "5tZL/hJZq7y9clmnOoA1MKBxCqPMwl7IVOfSwNL4YUE="},
		{Country: "nl", City: "amsterdam", Hostname: "nl-ams.prod.surfshark.com", Endpoint: "185.49.14.97:51820", PublicKey: "RLJlFD2TJ3Vkd/D2VQmj5Z8yxdE5a+n8lNGdnZJbfR0="},
		{Country: "ch", City: "zurich", Hostname: "ch-zur.prod.surfshark.com", Endpoint: "185.49.14.113:51820", PublicKey: "m/tQTnGRBifE4kp3fK/jF+U3c2lk1M04d0P7UmDcnHI="},
		{Country: "se", City: "stockholm", Hostname: "se-sto.prod.surfshark.com", Endpoint: "185.49.14.129:51820", PublicKey: "T/q67rDONuDRDVKN89KVdMmDYqiRjlRAP/cOO20TWwY="},
		{Country: "jp", City: "tokyo", Hostname: "jp-tok.prod.surfshark.com", Endpoint: "185.49.14.145:51820", PublicKey: "HRPfcKGMd7Zl7OUbk7L3ZW/ayaN/MTFD1CklWZfKRH4="},
		{Country: "ca", City: "toronto", Hostname: "ca-tor.prod.surfshark.com", Endpoint: "185.49.14.161:51820", PublicKey: "TGC1HLHLWXpb9J0Z8e2Mg5g6sSLVxugt8FWzQ0l80H0="},
		{Country: "au", City: "sydney", Hostname: "au-syd.prod.surfshark.com", Endpoint: "185.49.14.177:51820", PublicKey: "kGW8BQw0B/O1WAULz/R/4bMJlOgqkJYMoVb41W1e20w="},
		{Country: "sg", City: "singapore", Hostname: "sg-sin.prod.surfshark.com", Endpoint: "185.49.14.193:51820", PublicKey: "SVKmGC0Hkj84JnhZARGtN3t+6s0V3i99b0RQnm/jPQ0="},
	},
}

// providerDNS maps providers to their DNS servers (used for DNS leak protection).
var providerDNS = map[string][]string{
	ProviderMullvad:    {"10.64.0.1"},
	ProviderPIA:        {"10.0.0.243"},
	ProviderNordVPN:    {"103.86.96.100", "103.86.99.100"},
	ProviderExpressVPN: {"10.255.255.254"},
	ProviderSurfshark:  {"10.8.8.1"},
	ProviderProtonVPN:  {"10.2.0.1"},
	ProviderCyberGhost: {"10.101.0.1"},
	ProviderIPVanish:   {"10.0.0.1"},
	ProviderWindscribe: {"10.255.255.1"},
	ProviderTorGuard:   {"10.9.0.1"},
	ProviderAirVPN:     {"10.128.0.1"},
	ProviderIVPN:       {"10.0.254.1"},
	ProviderHideMe:     {"10.0.0.2"},
	ProviderVyprVPN:    {"10.10.0.1"},
	ProviderMozillaVPN: {"10.64.0.1"},
}

// ---------------------------------------------------------------------------
// VPNProvider service
// ---------------------------------------------------------------------------

// VPNProvider integrates with commercial VPN providers and Tailscale, allowing
// users to route traffic through VPN tunnels and bridge into Tailscale networks.
type VPNProvider struct {
	mu       sync.Mutex
	state    State
	stateErr string
	confDir  string
	cfg      map[string]string

	// Runtime state.
	tunnelIface string            // e.g. "wg-vpn0" or "tun-vpn0"
	ovpnCmd     *exec.Cmd         // running OpenVPN process (nil if WireGuard)
	tsCmd       *exec.Cmd         // running tailscaled process
	stopCh      chan struct{}      // closed on Stop to halt health monitor
	httpClient  *http.Client
	privateKey  string            // generated WG private key
	localAddr   string            // assigned tunnel address
}

// NewVPNProvider creates a new VPN provider integration service.
// An optional confDir argument may be supplied for storing generated configs
// and keys; if omitted, /var/lib/gatekeeper/vpn-provider is used.
func NewVPNProvider(confDir ...string) *VPNProvider {
	dir := "/var/lib/gatekeeper/vpn-provider"
	if len(confDir) > 0 && confDir[0] != "" {
		dir = confDir[0]
	}
	return &VPNProvider{
		confDir: dir,
		state:   StateStopped,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (v *VPNProvider) Name() string        { return "vpn-provider" }
func (v *VPNProvider) DisplayName() string { return "VPN Provider" }
func (v *VPNProvider) Category() string    { return "vpn" }
func (v *VPNProvider) Dependencies() []string { return nil }

func (v *VPNProvider) Description() string {
	return "Integrates with commercial VPN providers (Mullvad, NordVPN, PIA, Surfshark, " +
		"ProtonVPN, and 10 more) and Tailscale for routing traffic through VPN tunnels, " +
		"with kill switch, DNS leak protection, and split tunneling support."
}

func (v *VPNProvider) DefaultConfig() map[string]string {
	return map[string]string{
		"provider":                "mullvad",
		"auth_type":              "account_id",
		"username":               "",
		"password":               "",
		"token":                  "",
		"server_country":         "us",
		"server_city":            "",
		"server_hostname":        "",
		"protocol":               "wireguard",
		"kill_switch":            "true",
		"dns_leak_protection":    "true",
		"split_tunnel_zones":     "",
		"custom_config":          "",
		"auto_reconnect":         "true",
		"reconnect_interval":     "30",
		"tailscale_auth_key":     "",
		"tailscale_advertise_routes": "",
		"tailscale_accept_routes":    "false",
		"tailscale_exit_node":        "false",
		"tailscale_hostname":         "",
	}
}

func (v *VPNProvider) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"provider": {
			Description: "VPN provider: mullvad, pia, nordvpn, expressvpn, surfshark, protonvpn, " +
				"cyberghost, ipvanish, windscribe, torguard, airvpn, ivpn, hideme, vyprvpn, " +
				"mozillavpn, tailscale, custom",
			Default:  "mullvad",
			Required: true,
			Type:     "string",
		},
		"auth_type": {
			Description: "Authentication type: credentials, token, account_id, auth_key, config_file",
			Default:     "account_id",
			Required:    true,
			Type:        "string",
		},
		"username": {
			Description: "Provider username (for credentials auth)",
			Type:        "string",
		},
		"password": {
			Description: "Provider password (for credentials auth)",
			Type:        "string",
		},
		"token": {
			Description: "Auth token, account number, or activation code",
			Type:        "string",
		},
		"server_country": {
			Description: "Preferred server country code (e.g. us, de, ch)",
			Default:     "us",
			Type:        "string",
		},
		"server_city": {
			Description: "Preferred server city (optional, e.g. new-york, frankfurt)",
			Type:        "string",
		},
		"server_hostname": {
			Description: "Specific server hostname (overrides country/city selection)",
			Type:        "string",
		},
		"protocol": {
			Description: "VPN protocol: wireguard or openvpn",
			Default:     "wireguard",
			Type:        "string",
		},
		"kill_switch": {
			Description: "Block all non-VPN traffic if the tunnel drops",
			Default:     "true",
			Type:        "bool",
		},
		"dns_leak_protection": {
			Description: "Force DNS through VPN tunnel to prevent leaks",
			Default:     "true",
			Type:        "bool",
		},
		"split_tunnel_zones": {
			Description: "Comma-separated zone names to route through VPN (empty = all traffic)",
			Type:        "string",
		},
		"custom_config": {
			Description: "Path to custom WireGuard or OpenVPN config file (for custom provider)",
			Type:        "path",
		},
		"auto_reconnect": {
			Description: "Automatically reconnect on tunnel failure",
			Default:     "true",
			Type:        "bool",
		},
		"reconnect_interval": {
			Description: "Seconds between reconnect attempts",
			Default:     "30",
			Type:        "int",
		},
		"tailscale_auth_key": {
			Description: "Tailscale auth key for non-interactive authentication",
			Type:        "string",
		},
		"tailscale_advertise_routes": {
			Description: "CIDRs to advertise to the tailnet (comma-separated)",
			Type:        "string",
		},
		"tailscale_accept_routes": {
			Description: "Accept routes advertised by other tailnet nodes",
			Default:     "false",
			Type:        "bool",
		},
		"tailscale_exit_node": {
			Description: "Advertise this node as a Tailscale exit node",
			Default:     "false",
			Type:        "bool",
		},
		"tailscale_hostname": {
			Description: "Hostname to use in the tailnet",
			Type:        "string",
		},
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func (v *VPNProvider) Validate(cfg map[string]string) error {
	provider := cfg["provider"]
	if !isValidProvider(provider) {
		return fmt.Errorf("unknown provider %q; supported: %s", provider, strings.Join(allProviders, ", "))
	}

	// Provider-specific credential validation. The provider determines what
	// auth fields are required; auth_type is optional (inferred from provider).
	switch provider {
	case ProviderTailscale:
		if cfg["tailscale_auth_key"] == "" && cfg["token"] == "" {
			return fmt.Errorf("tailscale_auth_key is required for Tailscale provider")
		}
	case ProviderCustom:
		if cfg["custom_config"] == "" {
			return fmt.Errorf("custom_config path is required for custom provider")
		}
	case ProviderMullvad, ProviderIVPN:
		// Account-ID based providers: need token.
		if cfg["token"] == "" {
			return fmt.Errorf("provider %q requires a token or account ID", provider)
		}
	case ProviderNordVPN, ProviderExpressVPN, ProviderAirVPN, ProviderMozillaVPN:
		// Token-based providers.
		if cfg["token"] == "" {
			return fmt.Errorf("provider %q requires a token or account ID", provider)
		}
	case ProviderPIA, ProviderSurfshark, ProviderProtonVPN, ProviderCyberGhost,
		ProviderIPVanish, ProviderWindscribe, ProviderTorGuard, ProviderHideMe,
		ProviderVyprVPN:
		// Credential-based providers.
		if cfg["username"] == "" || cfg["password"] == "" {
			return fmt.Errorf("provider %q requires username and password", provider)
		}
	}

	// If auth_type is explicitly provided, validate it is accepted.
	if authType := cfg["auth_type"]; authType != "" {
		if accepted, ok := providerAuthTypes[provider]; ok {
			found := false
			for _, a := range accepted {
				if a == authType {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("provider %q does not support auth_type %q (accepted: %s)",
					provider, authType, strings.Join(accepted, ", "))
			}
		}
	}

	// Validate protocol.
	if provider != ProviderTailscale && provider != ProviderCustom {
		proto := cfg["protocol"]
		if proto != "" && proto != "wireguard" && proto != "openvpn" {
			return fmt.Errorf("invalid protocol %q; must be wireguard or openvpn", proto)
		}
	}

	// Validate numeric fields.
	if val := cfg["reconnect_interval"]; val != "" {
		n, err := strconv.Atoi(val)
		if err != nil || n < 5 {
			return fmt.Errorf("reconnect_interval must be an integer >= 5")
		}
	}

	// Validate tailscale-specific CIDRs.
	if routes := cfg["tailscale_advertise_routes"]; routes != "" {
		for _, cidr := range strings.Split(routes, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid CIDR in tailscale_advertise_routes: %q: %w", cidr, err)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

func (v *VPNProvider) Start(cfg map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.cfg = cfg
	v.stopCh = make(chan struct{})

	if err := os.MkdirAll(v.confDir, 0o700); err != nil {
		return fmt.Errorf("create confdir: %w", err)
	}

	provider := cfg["provider"]

	var err error
	switch provider {
	case ProviderTailscale:
		err = v.startTailscale(cfg)
	default:
		proto := cfg["protocol"]
		if proto == "" {
			if dp, ok := providerDefaultProtocol[provider]; ok {
				proto = dp
			} else {
				proto = "wireguard"
			}
		}

		if provider == ProviderCustom {
			err = v.startCustom(cfg)
		} else if proto == "wireguard" {
			err = v.startWireGuard(cfg)
		} else {
			err = v.startOpenVPN(cfg)
		}
	}

	if err != nil {
		v.state = StateError
		v.stateErr = err.Error()
		return err
	}

	// Apply kill switch.
	if cfg["kill_switch"] == "true" && provider != ProviderTailscale {
		if ksErr := v.applyKillSwitch(); ksErr != nil {
			slog.Warn("failed to apply kill switch", "error", ksErr)
		}
	}

	// Apply DNS leak protection.
	if cfg["dns_leak_protection"] == "true" && provider != ProviderTailscale {
		if dlErr := v.applyDNSLeakProtection(cfg); dlErr != nil {
			slog.Warn("failed to apply DNS leak protection", "error", dlErr)
		}
	}

	// Apply split tunneling if configured.
	if zones := cfg["split_tunnel_zones"]; zones != "" {
		if stErr := v.applySplitTunnel(cfg); stErr != nil {
			slog.Warn("failed to apply split tunnel", "error", stErr)
		}
	}

	// Start health monitoring.
	if provider != ProviderTailscale {
		go v.healthLoop()
	}

	v.state = StateRunning
	slog.Info("vpn-provider started", "provider", provider, "interface", v.tunnelIface)
	return nil
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

func (v *VPNProvider) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.stopCh != nil {
		close(v.stopCh)
		v.stopCh = nil
	}

	provider := v.cfg["provider"]

	// Remove kill switch and DNS leak protection rules.
	v.removeKillSwitch()
	v.removeDNSLeakProtection()
	v.removeSplitTunnel()

	switch provider {
	case ProviderTailscale:
		v.stopTailscale()
	default:
		if v.ovpnCmd != nil && v.ovpnCmd.Process != nil {
			slog.Info("stopping openvpn process", "pid", v.ovpnCmd.Process.Pid)
			v.ovpnCmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- v.ovpnCmd.Wait() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				v.ovpnCmd.Process.Kill()
			}
			v.ovpnCmd = nil
		}

		if v.tunnelIface != "" {
			run("ip", "link", "set", v.tunnelIface, "down")
			run("ip", "link", "del", v.tunnelIface)
		}
	}

	// Clean up config files.
	v.cleanupConfigs()

	v.tunnelIface = ""
	v.privateKey = ""
	v.localAddr = ""
	v.state = StateStopped
	v.stateErr = ""
	slog.Info("vpn-provider stopped")
	return nil
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

func (v *VPNProvider) Reload(cfg map[string]string) error {
	// Full restart for config changes — VPN tunnels generally cannot be
	// reconfigured in-place.
	if err := v.Stop(); err != nil {
		slog.Warn("reload: stop failed", "error", err)
	}
	return v.Start(cfg)
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func (v *VPNProvider) Status() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

// ---------------------------------------------------------------------------
// WireGuard startup
// ---------------------------------------------------------------------------

func (v *VPNProvider) startWireGuard(cfg map[string]string) error {
	provider := cfg["provider"]

	// Select server.
	server, err := v.selectServer(provider, cfg["server_country"], cfg["server_city"], cfg["server_hostname"])
	if err != nil {
		return fmt.Errorf("server selection: %w", err)
	}

	// Generate WireGuard private key.
	privKey, err := v.generateWGKey()
	if err != nil {
		return fmt.Errorf("generate wireguard key: %w", err)
	}
	v.privateKey = privKey

	// Derive public key.
	pubKey, err := v.deriveWGPublicKey(privKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	// For API-based providers, register our public key and get address.
	localAddr, err := v.registerWithProvider(cfg, pubKey)
	if err != nil {
		return fmt.Errorf("provider registration: %w", err)
	}
	v.localAddr = localAddr

	// Generate WireGuard config.
	iface := "wg-vpn0"
	v.tunnelIface = iface
	confPath := filepath.Join(v.confDir, iface+".conf")

	wgConf := v.buildWireGuardConfig(privKey, localAddr, server)
	if err := os.WriteFile(confPath, []byte(wgConf), 0o600); err != nil {
		return fmt.Errorf("write wg config: %w", err)
	}

	// Bring up with wg-quick.
	if err := run("wg-quick", "up", confPath); err != nil {
		return fmt.Errorf("wg-quick up: %w", err)
	}

	slog.Info("wireguard tunnel established",
		"provider", provider,
		"server", server.Hostname,
		"endpoint", server.Endpoint,
		"interface", iface,
	)
	return nil
}

func (v *VPNProvider) buildWireGuardConfig(privateKey, localAddr string, server vpnServer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))
	b.WriteString(fmt.Sprintf("Address = %s/32\n", localAddr))

	// Add provider DNS if leak protection is enabled.
	if v.cfg["dns_leak_protection"] == "true" {
		if dns, ok := providerDNS[v.cfg["provider"]]; ok {
			b.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(dns, ", ")))
		}
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", server.PublicKey))
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", server.Endpoint))

	// Route all traffic through VPN unless split tunneling is configured.
	if v.cfg["split_tunnel_zones"] != "" {
		// Split tunneling — only route specific traffic. The actual routes
		// are set up via policy routing in applySplitTunnel.
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	} else {
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	}
	b.WriteString("PersistentKeepalive = 25\n")

	return b.String()
}

// ---------------------------------------------------------------------------
// OpenVPN startup
// ---------------------------------------------------------------------------

func (v *VPNProvider) startOpenVPN(cfg map[string]string) error {
	provider := cfg["provider"]

	// Select server for config generation.
	server, err := v.selectServer(provider, cfg["server_country"], cfg["server_city"], cfg["server_hostname"])
	if err != nil {
		// For OpenVPN providers without embedded server lists, use hostname-based config.
		slog.Warn("server selection failed, using generic config", "error", err)
		server = vpnServer{
			Hostname: cfg["server_hostname"],
			Country:  cfg["server_country"],
			City:     cfg["server_city"],
		}
	}

	confPath := filepath.Join(v.confDir, "vpn-provider.ovpn")
	authPath := filepath.Join(v.confDir, "vpn-provider-auth.txt")

	// Write auth file.
	if cfg["auth_type"] == "credentials" {
		authContent := cfg["username"] + "\n" + cfg["password"] + "\n"
		if err := os.WriteFile(authPath, []byte(authContent), 0o600); err != nil {
			return fmt.Errorf("write auth file: %w", err)
		}
	}

	// Generate OpenVPN config.
	ovpnConf := v.buildOpenVPNConfig(cfg, server, authPath)
	if err := os.WriteFile(confPath, []byte(ovpnConf), 0o600); err != nil {
		return fmt.Errorf("write ovpn config: %w", err)
	}

	// Start OpenVPN.
	v.tunnelIface = "tun-vpn0"
	cmd := exec.Command("openvpn", "--config", confPath, "--dev", v.tunnelIface, "--daemon", "--writepid",
		filepath.Join(v.confDir, "openvpn.pid"),
		"--log", filepath.Join(v.confDir, "openvpn.log"),
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}
	v.ovpnCmd = cmd

	// Wait briefly for the tunnel to come up.
	time.Sleep(3 * time.Second)

	slog.Info("openvpn tunnel starting",
		"provider", provider,
		"server", server.Hostname,
		"interface", v.tunnelIface,
	)
	return nil
}

func (v *VPNProvider) buildOpenVPNConfig(cfg map[string]string, server vpnServer, authPath string) string {
	provider := cfg["provider"]
	var b strings.Builder

	b.WriteString("client\n")
	b.WriteString("dev-type tun\n")
	b.WriteString("proto udp\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("verb 3\n")
	b.WriteString("pull\n")

	// Remote server.
	endpoint := server.Endpoint
	if endpoint == "" {
		endpoint = server.Hostname + ":1194"
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
		port = "1194"
	}
	b.WriteString(fmt.Sprintf("remote %s %s udp\n", host, port))

	// Auth.
	if cfg["auth_type"] == "credentials" {
		b.WriteString(fmt.Sprintf("auth-user-pass %s\n", authPath))
	}

	// Provider-specific settings.
	switch provider {
	case ProviderExpressVPN:
		b.WriteString("cipher AES-256-CBC\n")
		b.WriteString("auth SHA512\n")
	case ProviderCyberGhost:
		b.WriteString("cipher AES-256-GCM\n")
		b.WriteString("auth SHA256\n")
	default:
		b.WriteString("cipher AES-256-GCM\n")
		b.WriteString("auth SHA256\n")
	}

	// DNS leak protection.
	if cfg["dns_leak_protection"] == "true" {
		if dns, ok := providerDNS[provider]; ok && len(dns) > 0 {
			for _, d := range dns {
				b.WriteString(fmt.Sprintf("dhcp-option DNS %s\n", d))
			}
		}
		b.WriteString("block-outside-dns\n")
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// Custom config startup
// ---------------------------------------------------------------------------

func (v *VPNProvider) startCustom(cfg map[string]string) error {
	configPath := cfg["custom_config"]
	if configPath == "" {
		return fmt.Errorf("custom_config path is required")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read custom config: %w", err)
	}

	configStr := string(content)

	// Detect config type by content.
	if strings.Contains(configStr, "[Interface]") && strings.Contains(configStr, "[Peer]") {
		// WireGuard config.
		v.tunnelIface = "wg-vpn0"
		confPath := filepath.Join(v.confDir, v.tunnelIface+".conf")
		if err := os.WriteFile(confPath, content, 0o600); err != nil {
			return fmt.Errorf("write custom wg config: %w", err)
		}
		if err := run("wg-quick", "up", confPath); err != nil {
			return fmt.Errorf("wg-quick up custom: %w", err)
		}
		slog.Info("custom wireguard tunnel established", "config", configPath)
	} else {
		// Assume OpenVPN config.
		v.tunnelIface = "tun-vpn0"
		cmd := exec.Command("openvpn", "--config", configPath, "--dev", v.tunnelIface, "--daemon",
			"--writepid", filepath.Join(v.confDir, "openvpn.pid"),
			"--log", filepath.Join(v.confDir, "openvpn.log"),
		)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start custom openvpn: %w", err)
		}
		v.ovpnCmd = cmd
		time.Sleep(3 * time.Second)
		slog.Info("custom openvpn tunnel starting", "config", configPath)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Tailscale integration
// ---------------------------------------------------------------------------

func (v *VPNProvider) startTailscale(cfg map[string]string) error {
	// Ensure tailscaled is available.
	if _, err := exec.LookPath("tailscaled"); err != nil {
		return fmt.Errorf("tailscaled not found in PATH: install tailscale first")
	}

	// Start tailscaled daemon.
	stateDir := filepath.Join(v.confDir, "tailscale")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create tailscale state dir: %w", err)
	}

	socketPath := filepath.Join(stateDir, "tailscaled.sock")
	tsCmd := exec.Command("tailscaled",
		"--state="+filepath.Join(stateDir, "tailscaled.state"),
		"--socket="+socketPath,
		"--tun=tailscale0",
	)
	tsCmd.Stdout = os.Stdout
	tsCmd.Stderr = os.Stderr
	if err := tsCmd.Start(); err != nil {
		return fmt.Errorf("start tailscaled: %w", err)
	}
	v.tsCmd = tsCmd
	v.tunnelIface = "tailscale0"

	// Wait for socket to appear.
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Build tailscale up arguments.
	upArgs := []string{"up", "--socket=" + socketPath, "--reset"}

	authKey := cfg["tailscale_auth_key"]
	if authKey == "" {
		authKey = cfg["token"]
	}
	if authKey != "" {
		upArgs = append(upArgs, "--authkey="+authKey)
	}

	if hostname := cfg["tailscale_hostname"]; hostname != "" {
		upArgs = append(upArgs, "--hostname="+hostname)
	}

	if cfg["tailscale_exit_node"] == "true" {
		upArgs = append(upArgs, "--advertise-exit-node")
	}

	if cfg["tailscale_accept_routes"] == "true" {
		upArgs = append(upArgs, "--accept-routes")
	}

	if routes := cfg["tailscale_advertise_routes"]; routes != "" {
		upArgs = append(upArgs, "--advertise-routes="+routes)
	}

	// Run tailscale up.
	upCmd := exec.Command("tailscale", upArgs...)
	output, err := upCmd.CombinedOutput()
	if err != nil {
		// Don't fail hard — tailscaled is still running and user may need
		// to complete interactive auth.
		slog.Warn("tailscale up returned error (may need interactive auth)",
			"error", err,
			"output", string(output),
		)
	} else {
		slog.Info("tailscale authenticated successfully")
	}

	// Enable IP forwarding for subnet routing / exit node.
	if cfg["tailscale_exit_node"] == "true" || cfg["tailscale_advertise_routes"] != "" {
		if fwdErr := v.enableIPForwarding(); fwdErr != nil {
			slog.Warn("failed to enable IP forwarding for tailscale", "error", fwdErr)
		}
	}

	// Set up NAT/routing for bridge mode (LAN devices can reach tailnet).
	if cfg["tailscale_accept_routes"] == "true" {
		if natErr := v.setupTailscaleBridgeNAT(); natErr != nil {
			slog.Warn("failed to setup tailscale bridge NAT", "error", natErr)
		}
	}

	slog.Info("tailscale integration started", "interface", v.tunnelIface)
	return nil
}

func (v *VPNProvider) stopTailscale() {
	// Run tailscale down first.
	stateDir := filepath.Join(v.confDir, "tailscale")
	socketPath := filepath.Join(stateDir, "tailscaled.sock")
	downCmd := exec.Command("tailscale", "down", "--socket="+socketPath)
	if output, err := downCmd.CombinedOutput(); err != nil {
		slog.Warn("tailscale down failed", "error", err, "output", string(output))
	}

	// Stop tailscaled.
	if v.tsCmd != nil && v.tsCmd.Process != nil {
		v.tsCmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- v.tsCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			v.tsCmd.Process.Kill()
		}
		v.tsCmd = nil
	}

	// Remove bridge NAT rules.
	v.removeTailscaleBridgeNAT()

	slog.Info("tailscale stopped")
}

func (v *VPNProvider) enableIPForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		slog.Warn("could not enable ipv6 forwarding", "error", err)
	}
	return nil
}

func (v *VPNProvider) setupTailscaleBridgeNAT() error {
	// Allow forwarding between LAN and tailscale interface.
	cmds := [][]string{
		{"nft", "add", "table", "inet", "gatekeeper_ts_bridge"},
		{"nft", "add", "chain", "inet", "gatekeeper_ts_bridge", "forward",
			"{ type filter hook forward priority 0; policy accept; }"},
		{"nft", "add", "rule", "inet", "gatekeeper_ts_bridge", "forward",
			"iifname", v.tunnelIface, "accept"},
		{"nft", "add", "rule", "inet", "gatekeeper_ts_bridge", "forward",
			"oifname", v.tunnelIface, "accept"},
		// Masquerade traffic going into tailscale.
		{"nft", "add", "chain", "inet", "gatekeeper_ts_bridge", "postrouting",
			"{ type nat hook postrouting priority 100; }"},
		{"nft", "add", "rule", "inet", "gatekeeper_ts_bridge", "postrouting",
			"oifname", v.tunnelIface, "masquerade"},
	}

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			return fmt.Errorf("tailscale bridge NAT rule %v: %w", args, err)
		}
	}
	slog.Info("tailscale bridge NAT configured")
	return nil
}

func (v *VPNProvider) removeTailscaleBridgeNAT() {
	run("nft", "delete", "table", "inet", "gatekeeper_ts_bridge")
}

// ---------------------------------------------------------------------------
// Kill switch (nftables)
// ---------------------------------------------------------------------------

func (v *VPNProvider) applyKillSwitch() error {
	iface := v.tunnelIface
	if iface == "" {
		return fmt.Errorf("no tunnel interface set")
	}

	cmds := [][]string{
		{"nft", "add", "table", "inet", "gatekeeper_vpn_ks"},
		{"nft", "add", "chain", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"{ type filter hook output priority 0; policy accept; }"},
		// Allow traffic on the tunnel interface.
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"oifname", iface, "accept"},
		// Allow loopback.
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"oifname", "lo", "accept"},
		// Allow LAN traffic (RFC1918).
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"ip", "daddr", "10.0.0.0/8", "accept"},
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"ip", "daddr", "172.16.0.0/12", "accept"},
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"ip", "daddr", "192.168.0.0/16", "accept"},
		// Allow DHCP.
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"udp", "dport", "67-68", "accept"},
		// Allow traffic to the VPN endpoint itself (so the tunnel can establish).
		// This is handled by WireGuard/OpenVPN automatically via fwmark, but
		// we add explicit allow for the endpoint IP as a safety measure.
		// Drop everything else going out non-tunnel, non-lo interfaces.
		{"nft", "add", "rule", "inet", "gatekeeper_vpn_ks", "vpn_killswitch",
			"oifname", "!=", iface, "oifname", "!=", "lo",
			"ip", "daddr", "!=", "10.0.0.0/8",
			"ip", "daddr", "!=", "172.16.0.0/12",
			"ip", "daddr", "!=", "192.168.0.0/16",
			"drop"},
	}

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			return fmt.Errorf("kill switch rule %v: %w", args, err)
		}
	}

	slog.Info("kill switch enabled", "interface", iface)
	return nil
}

func (v *VPNProvider) removeKillSwitch() {
	if err := run("nft", "delete", "table", "inet", "gatekeeper_vpn_ks"); err != nil {
		slog.Debug("kill switch table removal", "error", err)
	}
}

// ---------------------------------------------------------------------------
// DNS leak protection
// ---------------------------------------------------------------------------

func (v *VPNProvider) applyDNSLeakProtection(cfg map[string]string) error {
	provider := cfg["provider"]
	dns, ok := providerDNS[provider]
	if !ok || len(dns) == 0 {
		slog.Warn("no DNS servers known for provider, skipping DNS leak protection", "provider", provider)
		return nil
	}

	iface := v.tunnelIface

	cmds := [][]string{
		{"nft", "add", "table", "inet", "gatekeeper_vpn_dns"},
		{"nft", "add", "chain", "inet", "gatekeeper_vpn_dns", "dns_leak",
			"{ type filter hook output priority 0; policy accept; }"},
		// Allow DNS to provider DNS servers.
	}

	for _, d := range dns {
		cmds = append(cmds, []string{
			"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
			"ip", "daddr", d, "udp", "dport", "53", "accept",
		})
		cmds = append(cmds, []string{
			"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
			"ip", "daddr", d, "tcp", "dport", "53", "accept",
		})
	}

	// Allow DNS on tunnel interface.
	cmds = append(cmds, []string{
		"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
		"oifname", iface, "udp", "dport", "53", "accept",
	})
	cmds = append(cmds, []string{
		"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
		"oifname", iface, "tcp", "dport", "53", "accept",
	})

	// Allow DNS on loopback (local resolver).
	cmds = append(cmds, []string{
		"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
		"oifname", "lo", "udp", "dport", "53", "accept",
	})

	// Block DNS to all other destinations.
	cmds = append(cmds, []string{
		"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
		"udp", "dport", "53", "drop",
	})
	cmds = append(cmds, []string{
		"nft", "add", "rule", "inet", "gatekeeper_vpn_dns", "dns_leak",
		"tcp", "dport", "53", "drop",
	})

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			return fmt.Errorf("DNS leak protection rule %v: %w", args, err)
		}
	}

	slog.Info("DNS leak protection enabled", "dns_servers", dns)
	return nil
}

func (v *VPNProvider) removeDNSLeakProtection() {
	if err := run("nft", "delete", "table", "inet", "gatekeeper_vpn_dns"); err != nil {
		slog.Debug("DNS leak protection table removal", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Split tunneling via policy routing
// ---------------------------------------------------------------------------

func (v *VPNProvider) applySplitTunnel(cfg map[string]string) error {
	zones := cfg["split_tunnel_zones"]
	if zones == "" {
		return nil
	}

	iface := v.tunnelIface
	if iface == "" {
		return fmt.Errorf("no tunnel interface for split tunnel")
	}

	// Use a custom routing table (100) for VPN traffic.
	const rtTable = "100"
	const fwMark = "0x1"

	// Add default route through VPN in table 100.
	if err := run("ip", "route", "add", "default", "dev", iface, "table", rtTable); err != nil {
		return fmt.Errorf("add default route in table %s: %w", rtTable, err)
	}

	// Add ip rule: packets with fwmark go through table 100.
	if err := run("ip", "rule", "add", "fwmark", fwMark, "table", rtTable); err != nil {
		return fmt.Errorf("add ip rule for fwmark: %w", err)
	}

	// Create nftables rules to mark packets from specified zones.
	cmds := [][]string{
		{"nft", "add", "table", "inet", "gatekeeper_vpn_st"},
		{"nft", "add", "chain", "inet", "gatekeeper_vpn_st", "split_tunnel",
			"{ type route hook output priority -150; policy accept; }"},
	}

	// Mark traffic from specified zone interfaces.
	for _, zone := range strings.Split(zones, ",") {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			continue
		}
		// Zone names are assumed to correspond to interface names or nftables sets.
		cmds = append(cmds, []string{
			"nft", "add", "rule", "inet", "gatekeeper_vpn_st", "split_tunnel",
			"iifname", zone, "meta", "mark", "set", fwMark,
		})
	}

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			return fmt.Errorf("split tunnel rule %v: %w", args, err)
		}
	}

	slog.Info("split tunneling enabled", "zones", zones, "table", rtTable)
	return nil
}

func (v *VPNProvider) removeSplitTunnel() {
	run("nft", "delete", "table", "inet", "gatekeeper_vpn_st")
	run("ip", "rule", "del", "fwmark", "0x1", "table", "100")
	run("ip", "route", "del", "default", "table", "100")
}

// ---------------------------------------------------------------------------
// Server selection
// ---------------------------------------------------------------------------

func (v *VPNProvider) selectServer(provider, country, city, hostname string) (vpnServer, error) {
	servers, ok := providerServers[provider]
	if !ok || len(servers) == 0 {
		// For providers without embedded server lists, try to fetch via API.
		return v.fetchServerFromAPI(provider, country, city, hostname)
	}

	// If a specific hostname is given, find it.
	if hostname != "" {
		for _, s := range servers {
			if strings.EqualFold(s.Hostname, hostname) {
				return s, nil
			}
		}
		return vpnServer{}, fmt.Errorf("server hostname %q not found for provider %s", hostname, provider)
	}

	// Filter by country.
	var candidates []vpnServer
	if country != "" {
		country = strings.ToLower(country)
		for _, s := range servers {
			if strings.EqualFold(s.Country, country) {
				candidates = append(candidates, s)
			}
		}
	}

	if len(candidates) == 0 {
		// Fall back to all servers if country filter matches nothing.
		candidates = servers
	}

	// Further filter by city if specified.
	if city != "" {
		city = strings.ToLower(city)
		var cityMatch []vpnServer
		for _, s := range candidates {
			if strings.EqualFold(s.City, city) {
				cityMatch = append(cityMatch, s)
			}
		}
		if len(cityMatch) > 0 {
			candidates = cityMatch
		}
	}

	if len(candidates) == 0 {
		return vpnServer{}, fmt.Errorf("no servers found for provider %s (country=%s, city=%s)", provider, country, city)
	}

	// Return first match (could be randomized in future).
	return candidates[0], nil
}

// fetchServerFromAPI attempts to get server info from provider APIs for
// providers that don't have embedded server lists.
func (v *VPNProvider) fetchServerFromAPI(provider, country, city, hostname string) (vpnServer, error) {
	switch provider {
	case ProviderNordVPN:
		return v.fetchNordVPNServer(country)
	case ProviderProtonVPN:
		return v.fetchProtonVPNServer(country)
	case ProviderWindscribe:
		return v.fetchWindscribeServer(country)
	default:
		return vpnServer{}, fmt.Errorf("no embedded servers and no API support for provider %s", provider)
	}
}

func (v *VPNProvider) fetchNordVPNServer(country string) (vpnServer, error) {
	url := fmt.Sprintf("https://api.nordvpn.com/v1/servers/recommendations?filters[country_id]=%s&filters[servers_technologies][identifier]=wireguard_udp&limit=1", country)

	resp, err := v.httpClient.Get(url)
	if err != nil {
		return vpnServer{}, fmt.Errorf("nordvpn API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vpnServer{}, fmt.Errorf("read nordvpn response: %w", err)
	}

	var servers []struct {
		Name     string `json:"name"`
		Hostname string `json:"hostname"`
		StationIP string `json:"station"`
		Technologies []struct {
			Identifier string `json:"identifier"`
			Metadata []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"metadata"`
		} `json:"technologies"`
	}

	if err := json.Unmarshal(body, &servers); err != nil {
		return vpnServer{}, fmt.Errorf("parse nordvpn response: %w", err)
	}

	if len(servers) == 0 {
		return vpnServer{}, fmt.Errorf("no nordvpn servers found for country %s", country)
	}

	s := servers[0]
	pubKey := ""
	for _, tech := range s.Technologies {
		if tech.Identifier == "wireguard_udp" {
			for _, meta := range tech.Metadata {
				if meta.Name == "public_key" {
					pubKey = meta.Value
				}
			}
		}
	}

	return vpnServer{
		Country:   country,
		Hostname:  s.Hostname,
		Endpoint:  s.StationIP + ":51820",
		PublicKey: pubKey,
	}, nil
}

func (v *VPNProvider) fetchProtonVPNServer(country string) (vpnServer, error) {
	resp, err := v.httpClient.Get("https://api.protonvpn.ch/vpn/logicals")
	if err != nil {
		return vpnServer{}, fmt.Errorf("protonvpn API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vpnServer{}, fmt.Errorf("read protonvpn response: %w", err)
	}

	var result struct {
		LogicalServers []struct {
			Name       string `json:"Name"`
			ExitCountry string `json:"ExitCountry"`
			Servers []struct {
				EntryIP string `json:"EntryIP"`
				ExitIP  string `json:"ExitIP"`
			} `json:"Servers"`
		} `json:"LogicalServers"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return vpnServer{}, fmt.Errorf("parse protonvpn response: %w", err)
	}

	country = strings.ToUpper(country)
	for _, ls := range result.LogicalServers {
		if strings.EqualFold(ls.ExitCountry, country) && len(ls.Servers) > 0 {
			return vpnServer{
				Country:  country,
				Hostname: ls.Name,
				Endpoint: ls.Servers[0].EntryIP + ":51820",
			}, nil
		}
	}

	return vpnServer{}, fmt.Errorf("no protonvpn servers found for country %s", country)
}

func (v *VPNProvider) fetchWindscribeServer(country string) (vpnServer, error) {
	resp, err := v.httpClient.Get("https://assets.windscribe.com/serverlist/wg/1")
	if err != nil {
		return vpnServer{}, fmt.Errorf("windscribe API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vpnServer{}, fmt.Errorf("read windscribe response: %w", err)
	}

	var result struct {
		Data []struct {
			CountryCode string `json:"country_code"`
			Nodes []struct {
				Hostname string `json:"hostname"`
				IP       string `json:"ip"`
				PubKey   string `json:"pub_key"`
			} `json:"nodes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return vpnServer{}, fmt.Errorf("parse windscribe response: %w", err)
	}

	country = strings.ToUpper(country)
	for _, d := range result.Data {
		if strings.EqualFold(d.CountryCode, country) && len(d.Nodes) > 0 {
			n := d.Nodes[0]
			return vpnServer{
				Country:   country,
				Hostname:  n.Hostname,
				Endpoint:  n.IP + ":443",
				PublicKey: n.PubKey,
			}, nil
		}
	}

	return vpnServer{}, fmt.Errorf("no windscribe servers found for country %s", country)
}

// ---------------------------------------------------------------------------
// Provider registration / key generation
// ---------------------------------------------------------------------------

// registerWithProvider registers our WireGuard public key with the VPN
// provider's API and returns the assigned tunnel IP address.
func (v *VPNProvider) registerWithProvider(cfg map[string]string, pubKey string) (string, error) {
	provider := cfg["provider"]

	switch provider {
	case ProviderMullvad:
		return v.registerMullvad(cfg["token"], pubKey)
	case ProviderPIA:
		return v.registerPIA(cfg["username"], cfg["password"], pubKey)
	case ProviderIVPN:
		return v.registerIVPN(cfg["token"], pubKey)
	default:
		// For providers without registration API, use a deterministic address
		// from a private range. The server-side usually assigns this.
		return "10.66.0.2", nil
	}
}

func (v *VPNProvider) registerMullvad(accountNumber, pubKey string) (string, error) {
	reqBody := fmt.Sprintf(`{"pubkey":"%s"}`, pubKey)
	req, err := http.NewRequest("POST",
		"https://api.mullvad.net/wg/",
		strings.NewReader("account="+accountNumber+"&pubkey="+pubKey),
	)
	if err != nil {
		return "", fmt.Errorf("create mullvad request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = reqBody // unused in URL-encoded form

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mullvad API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read mullvad response: %w", err)
	}

	// Mullvad returns the assigned IPv4 address directly.
	addr := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("mullvad API error (status %d): %s", resp.StatusCode, addr)
	}

	// Response format: "10.66.x.x" or error message.
	if ip := net.ParseIP(strings.Split(addr, "/")[0]); ip == nil {
		// Try parsing as JSON error.
		return "", fmt.Errorf("mullvad returned unexpected response: %s", addr)
	}

	return strings.Split(addr, "/")[0], nil
}

func (v *VPNProvider) registerPIA(username, password, pubKey string) (string, error) {
	// Step 1: Get auth token.
	tokenReq, err := http.NewRequest("POST",
		"https://privateinternetaccess.com/gtoken/generateToken",
		strings.NewReader("username="+username+"&password="+password),
	)
	if err != nil {
		return "", fmt.Errorf("create PIA token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := v.httpClient.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("PIA token request: %w", err)
	}
	defer tokenResp.Body.Close()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", fmt.Errorf("read PIA token response: %w", err)
	}

	var tokenResult struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenBody, &tokenResult); err != nil {
		return "", fmt.Errorf("parse PIA token response: %w", err)
	}

	if tokenResult.Token == "" {
		return "", fmt.Errorf("PIA returned empty token (check credentials)")
	}

	// Step 2: Register WireGuard key with token.
	wgReq, err := http.NewRequest("POST",
		"https://privateinternetaccess.com/api/client/v3/addKey",
		strings.NewReader("pt="+tokenResult.Token+"&pubkey="+pubKey),
	)
	if err != nil {
		return "", fmt.Errorf("create PIA addKey request: %w", err)
	}
	wgReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	wgResp, err := v.httpClient.Do(wgReq)
	if err != nil {
		return "", fmt.Errorf("PIA addKey request: %w", err)
	}
	defer wgResp.Body.Close()

	wgBody, err := io.ReadAll(wgResp.Body)
	if err != nil {
		return "", fmt.Errorf("read PIA addKey response: %w", err)
	}

	var wgResult struct {
		PeerIP string `json:"peer_ip"`
	}
	if err := json.Unmarshal(wgBody, &wgResult); err != nil {
		return "", fmt.Errorf("parse PIA addKey response: %w", err)
	}

	if wgResult.PeerIP == "" {
		return "", fmt.Errorf("PIA returned no peer IP: %s", string(wgBody))
	}

	return wgResult.PeerIP, nil
}

func (v *VPNProvider) registerIVPN(accountID, pubKey string) (string, error) {
	reqBody := fmt.Sprintf(`{"account_id":"%s","public_key":"%s"}`, accountID, pubKey)
	req, err := http.NewRequest("POST",
		"https://api.ivpn.net/v5/session/wg/add",
		strings.NewReader(reqBody),
	)
	if err != nil {
		return "", fmt.Errorf("create IVPN request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("IVPN API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read IVPN response: %w", err)
	}

	var result struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse IVPN response: %w", err)
	}

	if result.IPAddress == "" {
		return "", fmt.Errorf("IVPN returned no IP address: %s", string(body))
	}

	return result.IPAddress, nil
}

// ---------------------------------------------------------------------------
// WireGuard key generation
// ---------------------------------------------------------------------------

func (v *VPNProvider) generateWGKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg genkey: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (v *VPNProvider) deriveWGPublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// ---------------------------------------------------------------------------
// Health monitoring and auto-reconnect
// ---------------------------------------------------------------------------

func (v *VPNProvider) healthLoop() {
	v.mu.Lock()
	cfg := v.cfg
	v.mu.Unlock()

	interval := parseDurationSecs(cfg["reconnect_interval"], 30*time.Second)
	autoReconnect := cfg["auto_reconnect"] != "false"

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	consecutiveFails := 0
	const failThreshold = 3

	for {
		select {
		case <-v.stopCh:
			return
		case <-ticker.C:
			ok := v.checkTunnelHealth()

			v.mu.Lock()
			if ok {
				consecutiveFails = 0
				if v.state == StateError {
					v.state = StateRunning
					v.stateErr = ""
					slog.Info("vpn tunnel recovered")
				}
			} else {
				consecutiveFails++
				if consecutiveFails >= failThreshold {
					slog.Warn("vpn tunnel health check failed",
						"consecutive_failures", consecutiveFails,
						"interface", v.tunnelIface,
					)

					if autoReconnect {
						slog.Info("attempting vpn reconnect")
						v.state = StateStarting
						v.mu.Unlock()

						// Attempt reconnect by restarting the tunnel.
						if err := v.reconnect(); err != nil {
							slog.Error("vpn reconnect failed", "error", err)
							v.mu.Lock()
							v.state = StateError
							v.stateErr = fmt.Sprintf("reconnect failed: %v", err)
							v.mu.Unlock()
						} else {
							v.mu.Lock()
							v.state = StateRunning
							v.stateErr = ""
							v.mu.Unlock()
							slog.Info("vpn reconnect successful")
						}
						consecutiveFails = 0
						continue
					}

					v.state = StateError
					v.stateErr = "tunnel connectivity lost"
				}
			}
			v.mu.Unlock()
		}
	}
}

func (v *VPNProvider) checkTunnelHealth() bool {
	v.mu.Lock()
	iface := v.tunnelIface
	v.mu.Unlock()

	if iface == "" {
		return false
	}

	// Ping a well-known anycast address through the tunnel.
	cmd := exec.Command("ping", "-c", "1", "-W", "5", "-I", iface, "1.1.1.1")
	return cmd.Run() == nil
}

func (v *VPNProvider) reconnect() error {
	v.mu.Lock()
	cfg := v.cfg
	iface := v.tunnelIface
	v.mu.Unlock()

	provider := cfg["provider"]
	proto := cfg["protocol"]
	if proto == "" {
		if dp, ok := providerDefaultProtocol[provider]; ok {
			proto = dp
		} else {
			proto = "wireguard"
		}
	}

	// Tear down existing tunnel.
	if v.ovpnCmd != nil && v.ovpnCmd.Process != nil {
		v.ovpnCmd.Process.Kill()
		v.ovpnCmd = nil
	}
	if iface != "" {
		run("ip", "link", "set", iface, "down")
		run("ip", "link", "del", iface)
	}

	// Restart.
	v.mu.Lock()
	defer v.mu.Unlock()

	if provider == ProviderCustom {
		return v.startCustom(cfg)
	} else if proto == "wireguard" {
		return v.startWireGuard(cfg)
	}
	return v.startOpenVPN(cfg)
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func (v *VPNProvider) cleanupConfigs() {
	patterns := []string{"wg-vpn*.conf", "vpn-provider.ovpn", "vpn-provider-auth.txt", "openvpn.pid", "openvpn.log"}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(v.confDir, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			os.Remove(m)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isValidProvider(name string) bool {
	for _, p := range allProviders {
		if p == name {
			return true
		}
	}
	return false
}

package validate

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Sanitize strips null bytes and trims whitespace from user input.
// This should be called on all string fields before validation to
// prevent null byte injection and whitespace-based bypass attacks.
func Sanitize(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

var (
	nameRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	ifaceRe     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,15}$`)
	hostnameRe  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	macRe       = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	base64Re    = regexp.MustCompile(`^[A-Za-z0-9+/=]{1,128}$`)
	allowedProto = map[string]bool{"tcp": true, "udp": true, "icmp": true, "": true}
	allowedAction = map[string]bool{"allow": true, "deny": true, "reject": true, "log": true}
	allowedTrust  = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "full": true}
)

// Name validates a resource name (zone, alias, policy, profile).
func Name(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid name %q: must be 1-64 alphanumeric chars with hyphens/underscores/dots", name)
	}
	return nil
}

// Interface validates a network interface name.
func Interface(iface string) error {
	if iface == "" {
		return nil // optional
	}
	if !ifaceRe.MatchString(iface) {
		return fmt.Errorf("invalid interface %q: must start with a letter, 1-16 alphanumeric chars", iface)
	}
	return nil
}

// CIDR validates a network CIDR notation.
func CIDR(cidr string) error {
	if cidr == "" {
		return nil // optional
	}
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return nil
}

// IP validates an IP address.
func IP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address %q", ip)
	}
	return nil
}

// MAC validates a MAC address.
func MAC(mac string) error {
	if mac == "" {
		return nil // optional
	}
	if !macRe.MatchString(mac) {
		return fmt.Errorf("invalid MAC address %q: expected xx:xx:xx:xx:xx:xx", mac)
	}
	return nil
}

// Hostname validates a hostname.
func Hostname(hostname string) error {
	if hostname == "" {
		return nil // optional
	}
	if !hostnameRe.MatchString(hostname) {
		return fmt.Errorf("invalid hostname %q: must be 1-63 alphanumeric chars with hyphens", hostname)
	}
	return nil
}

// TrustLevel validates a zone trust level.
func TrustLevel(level string) error {
	if !allowedTrust[level] {
		return fmt.Errorf("invalid trust level %q: must be one of none, low, medium, high, full", level)
	}
	return nil
}

// Protocol validates a firewall rule protocol.
func Protocol(proto string) error {
	if !allowedProto[strings.ToLower(proto)] {
		return fmt.Errorf("invalid protocol %q: must be tcp, udp, or icmp", proto)
	}
	return nil
}

// Action validates a firewall rule action.
func Action(action string) error {
	if !allowedAction[strings.ToLower(action)] {
		return fmt.Errorf("invalid action %q: must be allow, deny, reject, or log", action)
	}
	return nil
}

// Ports validates a comma-separated list of port numbers or ranges.
func Ports(ports string) error {
	if ports == "" {
		return nil
	}
	for _, p := range strings.Split(ports, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Handle ranges like 80-443.
		if strings.Contains(p, "-") {
			parts := strings.SplitN(p, "-", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range %q", p)
			}
			lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || lo < 1 || lo > 65535 {
				return fmt.Errorf("invalid port %q", parts[0])
			}
			hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || hi < 1 || hi > 65535 || hi < lo {
				return fmt.Errorf("invalid port range %q", p)
			}
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %q: must be 1-65535", p)
		}
	}
	return nil
}

// AliasType validates an alias type.
func AliasType(typ string) error {
	valid := map[string]bool{"host": true, "network": true, "port": true, "mac": true, "nested": true, "external_url": true}
	if !valid[typ] {
		return fmt.Errorf("invalid alias type %q", typ)
	}
	return nil
}

// AliasMember validates a single alias member based on alias type.
func AliasMember(member, aliasType string) error {
	if member == "" {
		return fmt.Errorf("member cannot be empty")
	}
	switch aliasType {
	case "host":
		if net.ParseIP(member) == nil {
			return fmt.Errorf("invalid host member %q: must be an IP address", member)
		}
	case "network":
		if _, _, err := net.ParseCIDR(member); err != nil {
			return fmt.Errorf("invalid network member %q: must be CIDR notation", member)
		}
	case "port":
		return Ports(member)
	case "mac":
		if !macRe.MatchString(member) {
			return fmt.Errorf("invalid MAC member %q", member)
		}
	case "nested":
		return Name(member)
	}
	return nil
}

// WGPublicKey validates a WireGuard public key (base64-encoded 32 bytes).
func WGPublicKey(key string) error {
	if !base64Re.MatchString(key) {
		return fmt.Errorf("invalid WireGuard key: must be base64-encoded")
	}
	return nil
}

// WGAllowedIPs validates a WireGuard AllowedIPs field.
func WGAllowedIPs(ips string) error {
	for _, ip := range strings.Split(ips, ",") {
		ip = strings.TrimSpace(ip)
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return fmt.Errorf("invalid AllowedIPs entry %q: must be CIDR notation", ip)
		}
	}
	return nil
}

// WGEndpoint validates a WireGuard endpoint (host:port).
func WGEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: must be host:port", endpoint)
	}
	if net.ParseIP(host) == nil {
		if !hostnameRe.MatchString(host) {
			return fmt.Errorf("invalid endpoint host %q", host)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid endpoint port %q", portStr)
	}
	return nil
}

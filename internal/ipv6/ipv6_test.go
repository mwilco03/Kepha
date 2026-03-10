package ipv6

import (
	"strings"
	"testing"
)

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"2001:db8::1", true},
		{"fd00::abcd:1234", true},
		{"0000:0000:0000:0000:0000:0000:0000:0001", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"not-an-ip", false},
		{"", false},
		{"192.168.1.1:8080", false},
		{"::ffff:192.168.1.1", false}, // IPv4-mapped IPv6 — To4() != nil
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := IsIPv6(tt.addr); got != tt.want {
				t.Errorf("IsIPv6(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := IsIPv4(tt.addr); got != tt.want {
				t.Errorf("IsIPv4(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		cidr       string
		wantFamily int
		wantErr    bool
	}{
		{"192.168.1.0/24", FamilyIPv4, false},
		{"10.0.0.0/8", FamilyIPv4, false},
		{"172.16.0.0/12", FamilyIPv4, false},
		{"fd00::/64", FamilyIPv6, false},
		{"2001:db8::/32", FamilyIPv6, false},
		{"::1/128", FamilyIPv6, false},
		{"fe80::/10", FamilyIPv6, false},
		{"invalid", 0, true},
		{"not-a-cidr/99", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ip, network, family, err := ParseCIDR(tt.cidr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if family != tt.wantFamily {
				t.Errorf("family = %d, want %d", family, tt.wantFamily)
			}
			if ip == nil {
				t.Error("ip is nil")
			}
			if network == nil {
				t.Error("network is nil")
			}
		})
	}
}

func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"fd00:0000::/64", "fd00::/64"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001/128", "2001:db8::1/128"},
		{"invalid-cidr", "invalid-cidr"}, // returned unchanged on error
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := NormalizeCIDR(tt.input); got != tt.want {
				t.Errorf("NormalizeCIDR(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExpandIPv6(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"::1", "0000:0000:0000:0000:0000:0000:0000:0001"},
		{"fe80::1", "fe80:0000:0000:0000:0000:0000:0000:0001"},
		{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"::", "0000:0000:0000:0000:0000:0000:0000:0000"},
		{"fd00::abcd:ef01", "fd00:0000:0000:0000:0000:0000:abcd:ef01"},
		// IPv4 addresses returned as-is
		{"192.168.1.1", "192.168.1.1"},
		// Invalid addresses returned as-is
		{"not-an-ip", "not-an-ip"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := ExpandIPv6(tt.addr)
			if got != tt.want {
				t.Errorf("ExpandIPv6(%q) = %q, want %q", tt.addr, got, tt.want)
			}
			// Valid IPv6 expansions must be exactly 39 characters
			if tt.want != tt.addr && IsIPv6(tt.addr) {
				if len(got) != 39 {
					t.Errorf("ExpandIPv6(%q) length = %d, want 39", tt.addr, len(got))
				}
			}
		})
	}
}

func TestValidateDualStackZone(t *testing.T) {
	tests := []struct {
		name     string
		ipv4CIDR string
		ipv6CIDR string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid dual-stack",
			ipv4CIDR: "192.168.1.0/24",
			ipv6CIDR: "fd00::/64",
			wantErr:  false,
		},
		{
			name:     "empty IPv4 CIDR",
			ipv4CIDR: "",
			ipv6CIDR: "fd00::/64",
			wantErr:  true,
			errMsg:   "IPv4 CIDR must not be empty",
		},
		{
			name:     "empty IPv6 CIDR",
			ipv4CIDR: "192.168.1.0/24",
			ipv6CIDR: "",
			wantErr:  true,
			errMsg:   "IPv6 CIDR must not be empty",
		},
		{
			name:     "invalid IPv4 CIDR syntax",
			ipv4CIDR: "not-a-cidr",
			ipv6CIDR: "fd00::/64",
			wantErr:  true,
			errMsg:   "invalid IPv4 CIDR",
		},
		{
			name:     "invalid IPv6 CIDR syntax",
			ipv4CIDR: "192.168.1.0/24",
			ipv6CIDR: "bogus",
			wantErr:  true,
			errMsg:   "invalid IPv6 CIDR",
		},
		{
			name:     "swapped families: IPv6 in IPv4 slot",
			ipv4CIDR: "fd00::/64",
			ipv6CIDR: "192.168.1.0/24",
			wantErr:  true,
			errMsg:   "expected IPv4 CIDR but got IPv6",
		},
		{
			name:     "swapped families: IPv4 in IPv6 slot",
			ipv4CIDR: "10.0.0.0/8",
			ipv6CIDR: "172.16.0.0/12",
			wantErr:  true,
			errMsg:   "expected IPv6 CIDR but got IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDualStackZone(tt.ipv4CIDR, tt.ipv6CIDR)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateIPv6Address(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
		errMsg  string
	}{
		{"::1", false, ""},
		{"fe80::1", false, ""},
		{"2001:db8::1", false, ""},
		{"", true, "must not be empty"},
		{"not-an-ip", true, "invalid IP address"},
		{"192.168.1.1", true, "expected IPv6 address but got IPv4"},
		{"10.0.0.1", true, "expected IPv6 address but got IPv4"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := ValidateIPv6Address(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGenerateICMPv6Rules(t *testing.T) {
	rules := GenerateICMPv6Rules()

	if rules == "" {
		t.Fatal("GenerateICMPv6Rules() returned empty string")
	}

	expectedFragments := []string{
		"nd-neighbor-solicit",
		"nd-neighbor-advert",
		"nd-router-solicit",
		"nd-router-advert",
		"nd-redirect",
		"mld-listener-query",
		"mld-listener-report",
		"mld-listener-done",
		"mld2-listener-report",
		"echo-request",
		"echo-reply",
		"destination-unreachable",
		"packet-too-big",
		"time-exceeded",
		"parameter-problem",
	}

	for _, frag := range expectedFragments {
		if !strings.Contains(rules, frag) {
			t.Errorf("GenerateICMPv6Rules() missing expected fragment %q", frag)
		}
	}

	// Every non-comment, non-empty line should end with "accept"
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, "accept") {
			t.Errorf("expected line to end with 'accept': %q", line)
		}
	}
}

func TestGenerateIPv6ForwardRules(t *testing.T) {
	tests := []struct {
		src, dst, action string
	}{
		{"eth0", "eth1", "accept"},
		{"lan", "wan", "drop"},
		{"br0", "wlan0", "accept"},
	}

	for _, tt := range tests {
		t.Run(tt.src+"->"+tt.dst, func(t *testing.T) {
			rules := GenerateIPv6ForwardRules(tt.src, tt.dst, tt.action)
			if rules == "" {
				t.Fatal("GenerateIPv6ForwardRules() returned empty string")
			}
			if !strings.Contains(rules, tt.src) {
				t.Errorf("rules should contain src zone %q", tt.src)
			}
			if !strings.Contains(rules, tt.dst) {
				t.Errorf("rules should contain dst zone %q", tt.dst)
			}
			if !strings.Contains(rules, tt.action) {
				t.Errorf("rules should contain action %q", tt.action)
			}
			if !strings.Contains(rules, "ip6") {
				t.Error("rules should contain 'ip6' for IPv6 matching")
			}
		})
	}
}

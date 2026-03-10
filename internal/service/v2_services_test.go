package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// VPNLegs tests
// ---------------------------------------------------------------------------

func TestVPNLegs_Metadata(t *testing.T) {
	svc := NewVPNLegs("/tmp/test-vpnlegs")
	if svc == nil {
		t.Fatal("NewVPNLegs returned nil")
	}
	if got := svc.Name(); got != "vpn-legs" {
		t.Errorf("Name() = %q, want %q", got, "vpn-legs")
	}
	if got := svc.DisplayName(); got != "VPN Legs & Route Management" {
		t.Errorf("DisplayName() = %q, want %q", got, "VPN Legs & Route Management")
	}
	if got := svc.Category(); got != "network" {
		t.Errorf("Category() = %q, want %q", got, "network")
	}
	if got := svc.Description(); got == "" {
		t.Error("Description() is empty")
	}
	if got := svc.Dependencies(); got != nil {
		t.Errorf("Dependencies() = %v, want nil", got)
	}
}

func TestVPNLegs_Status_InitiallyStopped(t *testing.T) {
	svc := NewVPNLegs("/tmp/test-vpnlegs")
	if got := svc.Status(); got != StateStopped {
		t.Errorf("Status() = %q, want %q", got, StateStopped)
	}
}

func TestVPNLegs_DefaultConfig(t *testing.T) {
	svc := NewVPNLegs("/tmp/test-vpnlegs")
	dc := svc.DefaultConfig()

	expectedKeys := []string{
		"legs", "local_private_key", "local_listen_port",
		"health_interval", "health_timeout", "fail_threshold", "recovery_threshold",
	}
	for _, key := range expectedKeys {
		if _, ok := dc[key]; !ok {
			t.Errorf("DefaultConfig() missing key %q", key)
		}
	}
	if dc["local_listen_port"] != "51820" {
		t.Errorf("DefaultConfig()[local_listen_port] = %q, want %q", dc["local_listen_port"], "51820")
	}
	if dc["legs"] != "[]" {
		t.Errorf("DefaultConfig()[legs] = %q, want %q", dc["legs"], "[]")
	}
}

func TestVPNLegs_ConfigSchema(t *testing.T) {
	svc := NewVPNLegs("/tmp/test-vpnlegs")
	schema := svc.ConfigSchema()

	expectedFields := []string{
		"legs", "local_private_key", "local_listen_port",
		"health_interval", "health_timeout", "fail_threshold", "recovery_threshold",
	}
	for _, key := range expectedFields {
		f, ok := schema[key]
		if !ok {
			t.Errorf("ConfigSchema() missing field %q", key)
			continue
		}
		if f.Description == "" {
			t.Errorf("ConfigSchema()[%s].Description is empty", key)
		}
		if f.Type == "" {
			t.Errorf("ConfigSchema()[%s].Type is empty", key)
		}
	}

	// legs and local_private_key should be required.
	if !schema["legs"].Required {
		t.Error("ConfigSchema()[legs].Required should be true")
	}
	if !schema["local_private_key"].Required {
		t.Error("ConfigSchema()[local_private_key].Required should be true")
	}

	// Numeric fields should have type "int".
	for _, key := range []string{"local_listen_port", "health_interval", "health_timeout", "fail_threshold", "recovery_threshold"} {
		if schema[key].Type != "int" {
			t.Errorf("ConfigSchema()[%s].Type = %q, want %q", key, schema[key].Type, "int")
		}
	}
}

func TestVPNLegs_Validate(t *testing.T) {
	svc := NewVPNLegs("/tmp/test-vpnlegs")

	validLeg := VPNLeg{
		Name:           "site-a",
		RemoteEndpoint: "1.2.3.4:51820",
		RemotePublicKey: "aGVsbG8gd29ybGQ=",
		RemoteSubnets:  []string{"10.0.0.0/24"},
		Priority:       100,
		HealthTarget:   "10.0.0.1",
	}
	validLegsJSON, _ := json.Marshal([]VPNLeg{validLeg})

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr string // empty means no error expected
	}{
		{
			name: "valid minimal config",
			cfg: map[string]string{
				"local_private_key": "someprivatekey",
				"legs":              "[]",
			},
		},
		{
			name: "valid with leg",
			cfg: map[string]string{
				"local_private_key": "someprivatekey",
				"legs":              string(validLegsJSON),
			},
		},
		{
			name: "missing private key",
			cfg: map[string]string{
				"legs": "[]",
			},
			wantErr: "local_private_key is required",
		},
		{
			name: "invalid listen port - too high",
			cfg: map[string]string{
				"local_private_key":  "key",
				"local_listen_port": "70000",
			},
			wantErr: "local_listen_port must be 1-65535",
		},
		{
			name: "invalid listen port - zero",
			cfg: map[string]string{
				"local_private_key":  "key",
				"local_listen_port": "0",
			},
			wantErr: "local_listen_port must be 1-65535",
		},
		{
			name: "invalid listen port - not a number",
			cfg: map[string]string{
				"local_private_key":  "key",
				"local_listen_port": "abc",
			},
			wantErr: "local_listen_port must be 1-65535",
		},
		{
			name: "invalid legs JSON",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              "{bad json",
			},
			wantErr: "invalid legs JSON",
		},
		{
			name: "leg missing name",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"]}]`,
			},
			wantErr: "name is required",
		},
		{
			name: "leg name with spaces",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"bad name","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"]}]`,
			},
			wantErr: "invalid name",
		},
		{
			name: "duplicate leg names",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"dup","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"]},{"name":"dup","remote_endpoint":"5.6.7.8:51820","remote_public_key":"def","remote_subnets":["10.1.0.0/24"]}]`,
			},
			wantErr: "duplicate name",
		},
		{
			name: "leg missing remote_endpoint",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"]}]`,
			},
			wantErr: "remote_endpoint is required",
		},
		{
			name: "leg missing remote_public_key",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_endpoint":"1.2.3.4:51820","remote_subnets":["10.0.0.0/24"]}]`,
			},
			wantErr: "remote_public_key is required",
		},
		{
			name: "leg missing remote_subnets",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":[]}]`,
			},
			wantErr: "at least one remote_subnet is required",
		},
		{
			name: "leg invalid CIDR",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["not-a-cidr"]}]`,
			},
			wantErr: "invalid CIDR",
		},
		{
			name: "leg negative priority",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"],"priority":-1}]`,
			},
			wantErr: "priority must be >= 0",
		},
		{
			name: "leg invalid health_target",
			cfg: map[string]string{
				"local_private_key": "key",
				"legs":              `[{"name":"ok","remote_endpoint":"1.2.3.4:51820","remote_public_key":"abc","remote_subnets":["10.0.0.0/24"],"health_target":"not-an-ip"}]`,
			},
			wantErr: "invalid health_target IP",
		},
		{
			name: "invalid health_interval",
			cfg: map[string]string{
				"local_private_key": "key",
				"health_interval":   "0",
			},
			wantErr: "must be a positive integer",
		},
		{
			name: "invalid fail_threshold",
			cfg: map[string]string{
				"local_private_key": "key",
				"fail_threshold":    "-5",
			},
			wantErr: "must be a positive integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VPNProvider tests
// ---------------------------------------------------------------------------

func TestVPNProvider_Metadata(t *testing.T) {
	svc := NewVPNProvider()
	if svc == nil {
		t.Fatal("NewVPNProvider returned nil")
	}
	if got := svc.Name(); got != "vpn-provider" {
		t.Errorf("Name() = %q, want %q", got, "vpn-provider")
	}
	if got := svc.DisplayName(); got != "VPN Provider" {
		t.Errorf("DisplayName() = %q, want %q", got, "VPN Provider")
	}
	if got := svc.Category(); got != "vpn" {
		t.Errorf("Category() = %q, want %q", got, "vpn")
	}
	if got := svc.Description(); got == "" {
		t.Error("Description() is empty")
	}
	if got := svc.Dependencies(); got != nil {
		t.Errorf("Dependencies() = %v, want nil", got)
	}
}

func TestVPNProvider_Status_InitiallyStopped(t *testing.T) {
	svc := NewVPNProvider()
	if got := svc.Status(); got != StateStopped {
		t.Errorf("Status() = %q, want %q", got, StateStopped)
	}
}

func TestVPNProvider_DefaultConfig(t *testing.T) {
	svc := NewVPNProvider()
	dc := svc.DefaultConfig()

	expectedKeys := []string{
		"provider", "auth_type", "username", "password", "token",
		"server_country", "server_city", "server_hostname",
		"protocol", "kill_switch", "dns_leak_protection",
		"split_tunnel_zones", "custom_config", "auto_reconnect",
		"reconnect_interval", "tailscale_auth_key",
		"tailscale_advertise_routes", "tailscale_accept_routes",
		"tailscale_exit_node", "tailscale_hostname",
	}
	for _, key := range expectedKeys {
		if _, ok := dc[key]; !ok {
			t.Errorf("DefaultConfig() missing key %q", key)
		}
	}
	if dc["provider"] != "mullvad" {
		t.Errorf("DefaultConfig()[provider] = %q, want %q", dc["provider"], "mullvad")
	}
	if dc["protocol"] != "wireguard" {
		t.Errorf("DefaultConfig()[protocol] = %q, want %q", dc["protocol"], "wireguard")
	}
	if dc["kill_switch"] != "true" {
		t.Errorf("DefaultConfig()[kill_switch] = %q, want %q", dc["kill_switch"], "true")
	}
}

func TestVPNProvider_ConfigSchema(t *testing.T) {
	svc := NewVPNProvider()
	schema := svc.ConfigSchema()

	expectedFields := []string{
		"provider", "auth_type", "username", "password", "token",
		"server_country", "server_city", "server_hostname",
		"protocol", "kill_switch", "dns_leak_protection",
		"split_tunnel_zones", "custom_config", "auto_reconnect",
		"reconnect_interval", "tailscale_auth_key",
		"tailscale_advertise_routes", "tailscale_accept_routes",
		"tailscale_exit_node", "tailscale_hostname",
	}
	for _, key := range expectedFields {
		f, ok := schema[key]
		if !ok {
			t.Errorf("ConfigSchema() missing field %q", key)
			continue
		}
		if f.Description == "" {
			t.Errorf("ConfigSchema()[%s].Description is empty", key)
		}
		if f.Type == "" {
			t.Errorf("ConfigSchema()[%s].Type is empty", key)
		}
	}

	if !schema["provider"].Required {
		t.Error("ConfigSchema()[provider].Required should be true")
	}
	if schema["reconnect_interval"].Type != "int" {
		t.Errorf("ConfigSchema()[reconnect_interval].Type = %q, want %q", schema["reconnect_interval"].Type, "int")
	}
	if schema["kill_switch"].Type != "bool" {
		t.Errorf("ConfigSchema()[kill_switch].Type = %q, want %q", schema["kill_switch"].Type, "bool")
	}
	if schema["custom_config"].Type != "path" {
		t.Errorf("ConfigSchema()[custom_config].Type = %q, want %q", schema["custom_config"].Type, "path")
	}
}

func TestVPNProvider_Validate(t *testing.T) {
	svc := NewVPNProvider()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr string
	}{
		{
			name: "valid mullvad with token",
			cfg: map[string]string{
				"provider": "mullvad",
				"token":    "1234567890",
				"protocol": "wireguard",
			},
		},
		{
			name: "valid tailscale",
			cfg: map[string]string{
				"provider":           "tailscale",
				"tailscale_auth_key": "tskey-auth-abc123",
			},
		},
		{
			name: "valid custom with config path",
			cfg: map[string]string{
				"provider":      "custom",
				"custom_config": "/etc/wireguard/wg0.conf",
			},
		},
		{
			name: "valid PIA with credentials",
			cfg: map[string]string{
				"provider": "pia",
				"username": "user",
				"password": "pass",
				"protocol": "openvpn",
			},
		},
		{
			name: "unknown provider",
			cfg: map[string]string{
				"provider": "nonexistent",
			},
			wantErr: "unknown provider",
		},
		{
			name: "invalid protocol",
			cfg: map[string]string{
				"provider": "mullvad",
				"token":    "123",
				"protocol": "ipsec",
			},
			wantErr: "invalid protocol",
		},
		{
			name: "tailscale missing auth key",
			cfg: map[string]string{
				"provider": "tailscale",
			},
			wantErr: "tailscale_auth_key is required",
		},
		{
			name: "custom missing config path",
			cfg: map[string]string{
				"provider": "custom",
			},
			wantErr: "custom_config path is required",
		},
		{
			name: "mullvad missing token",
			cfg: map[string]string{
				"provider": "mullvad",
			},
			wantErr: "requires a token or account ID",
		},
		{
			name: "PIA missing credentials",
			cfg: map[string]string{
				"provider": "pia",
			},
			wantErr: "requires username and password",
		},
		{
			name: "PIA missing password",
			cfg: map[string]string{
				"provider": "pia",
				"username": "user",
			},
			wantErr: "requires username and password",
		},
		{
			name: "nordvpn missing token",
			cfg: map[string]string{
				"provider": "nordvpn",
			},
			wantErr: "requires a token or account ID",
		},
		{
			name: "surfshark missing credentials",
			cfg: map[string]string{
				"provider": "surfshark",
			},
			wantErr: "requires username and password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FRRouting tests
// ---------------------------------------------------------------------------

func TestFRRouting_Metadata(t *testing.T) {
	svc := NewFRRouting("/tmp/test-frr")
	if svc == nil {
		t.Fatal("NewFRRouting returned nil")
	}
	if got := svc.Name(); got != "frrouting" {
		t.Errorf("Name() = %q, want %q", got, "frrouting")
	}
	if got := svc.DisplayName(); got != "FRRouting (Dynamic Routing)" {
		t.Errorf("DisplayName() = %q, want %q", got, "FRRouting (Dynamic Routing)")
	}
	if got := svc.Category(); got != "network" {
		t.Errorf("Category() = %q, want %q", got, "network")
	}
	if got := svc.Description(); got == "" {
		t.Error("Description() is empty")
	}
	if got := svc.Dependencies(); got != nil {
		t.Errorf("Dependencies() = %v, want nil", got)
	}
}

func TestFRRouting_Status_InitiallyStopped(t *testing.T) {
	svc := NewFRRouting("/tmp/test-frr")
	if got := svc.Status(); got != StateStopped {
		t.Errorf("Status() = %q, want %q", got, StateStopped)
	}
}

func TestFRRouting_DefaultConfig(t *testing.T) {
	svc := NewFRRouting("/tmp/test-frr")
	dc := svc.DefaultConfig()

	expectedKeys := []string{
		"mode", "router_id", "bgp_asn", "bgp_neighbors",
		"bgp_networks", "bgp_redistribute", "ospf_areas",
		"ospf_redistribute", "log_level", "graceful_restart",
	}
	for _, key := range expectedKeys {
		if _, ok := dc[key]; !ok {
			t.Errorf("DefaultConfig() missing key %q", key)
		}
	}
	if dc["mode"] != "bgp" {
		t.Errorf("DefaultConfig()[mode] = %q, want %q", dc["mode"], "bgp")
	}
	if dc["bgp_asn"] != "65000" {
		t.Errorf("DefaultConfig()[bgp_asn] = %q, want %q", dc["bgp_asn"], "65000")
	}
	if dc["graceful_restart"] != "true" {
		t.Errorf("DefaultConfig()[graceful_restart] = %q, want %q", dc["graceful_restart"], "true")
	}
}

func TestFRRouting_ConfigSchema(t *testing.T) {
	svc := NewFRRouting("/tmp/test-frr")
	schema := svc.ConfigSchema()

	expectedFields := []string{
		"mode", "router_id", "bgp_asn", "bgp_neighbors",
		"bgp_networks", "bgp_redistribute", "ospf_areas",
		"ospf_redistribute", "log_level", "graceful_restart",
	}
	for _, key := range expectedFields {
		f, ok := schema[key]
		if !ok {
			t.Errorf("ConfigSchema() missing field %q", key)
			continue
		}
		if f.Description == "" {
			t.Errorf("ConfigSchema()[%s].Description is empty", key)
		}
		if f.Type == "" {
			t.Errorf("ConfigSchema()[%s].Type is empty", key)
		}
	}

	if !schema["mode"].Required {
		t.Error("ConfigSchema()[mode].Required should be true")
	}
	if !schema["router_id"].Required {
		t.Error("ConfigSchema()[router_id].Required should be true")
	}
	if schema["graceful_restart"].Type != "bool" {
		t.Errorf("ConfigSchema()[graceful_restart].Type = %q, want %q", schema["graceful_restart"].Type, "bool")
	}
}

func TestFRRouting_Validate(t *testing.T) {
	svc := NewFRRouting("/tmp/test-frr")

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr string
	}{
		{
			name: "valid BGP minimal",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "10.0.0.1",
				"bgp_asn":   "65000",
			},
		},
		{
			name: "valid OSPF minimal",
			cfg: map[string]string{
				"mode":      "ospf",
				"router_id": "10.0.0.1",
			},
		},
		{
			name: "valid both mode",
			cfg: map[string]string{
				"mode":      "both",
				"router_id": "10.0.0.1",
				"bgp_asn":   "65001",
			},
		},
		{
			name: "valid BGP with neighbors",
			cfg: map[string]string{
				"mode":           "bgp",
				"router_id":     "10.0.0.1",
				"bgp_asn":       "65000",
				"bgp_neighbors": `[{"address":"192.168.1.1","remote_asn":"65001","description":"peer1"}]`,
				"bgp_networks":  `["10.0.0.0/24","172.16.0.0/16"]`,
			},
		},
		{
			name: "valid OSPF with areas",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": `[{"area_id":"0","networks":["10.0.0.0/24"]}]`,
			},
		},
		{
			name: "valid redistribute",
			cfg: map[string]string{
				"mode":             "bgp",
				"router_id":       "10.0.0.1",
				"bgp_asn":         "65000",
				"bgp_redistribute": "connected,static",
			},
		},
		{
			name: "invalid mode",
			cfg: map[string]string{
				"mode":      "rip",
				"router_id": "10.0.0.1",
			},
			wantErr: "invalid mode",
		},
		{
			name: "missing router_id",
			cfg: map[string]string{
				"mode": "bgp",
			},
			wantErr: "router_id is required",
		},
		{
			name: "invalid router_id",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "not-an-ip",
			},
			wantErr: "invalid router_id",
		},
		{
			name: "invalid log_level",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "10.0.0.1",
				"bgp_asn":   "65000",
				"log_level": "verbose",
			},
			wantErr: "invalid log_level",
		},
		{
			name: "invalid graceful_restart",
			cfg: map[string]string{
				"mode":             "bgp",
				"router_id":       "10.0.0.1",
				"bgp_asn":         "65000",
				"graceful_restart": "maybe",
			},
			wantErr: "invalid graceful_restart",
		},
		{
			name: "BGP missing ASN",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "10.0.0.1",
				"bgp_asn":   "",
			},
			wantErr: "bgp_asn is required",
		},
		{
			name: "BGP invalid ASN",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "10.0.0.1",
				"bgp_asn":   "0",
			},
			wantErr: "invalid bgp_asn",
		},
		{
			name: "BGP invalid ASN non-numeric",
			cfg: map[string]string{
				"mode":      "bgp",
				"router_id": "10.0.0.1",
				"bgp_asn":   "abc",
			},
			wantErr: "invalid bgp_asn",
		},
		{
			name: "BGP invalid neighbors JSON",
			cfg: map[string]string{
				"mode":           "bgp",
				"router_id":     "10.0.0.1",
				"bgp_asn":       "65000",
				"bgp_neighbors": "{bad",
			},
			wantErr: "invalid bgp_neighbors JSON",
		},
		{
			name: "BGP neighbor invalid address",
			cfg: map[string]string{
				"mode":           "bgp",
				"router_id":     "10.0.0.1",
				"bgp_asn":       "65000",
				"bgp_neighbors": `[{"address":"not-ip","remote_asn":"65001"}]`,
			},
			wantErr: "invalid address",
		},
		{
			name: "BGP neighbor invalid remote_asn",
			cfg: map[string]string{
				"mode":           "bgp",
				"router_id":     "10.0.0.1",
				"bgp_asn":       "65000",
				"bgp_neighbors": `[{"address":"192.168.1.1","remote_asn":"abc"}]`,
			},
			wantErr: "invalid remote_asn",
		},
		{
			name: "BGP invalid networks JSON",
			cfg: map[string]string{
				"mode":         "bgp",
				"router_id":   "10.0.0.1",
				"bgp_asn":     "65000",
				"bgp_networks": "{bad",
			},
			wantErr: "invalid bgp_networks JSON",
		},
		{
			name: "BGP invalid network CIDR",
			cfg: map[string]string{
				"mode":         "bgp",
				"router_id":   "10.0.0.1",
				"bgp_asn":     "65000",
				"bgp_networks": `["not-a-cidr"]`,
			},
			wantErr: "invalid CIDR",
		},
		{
			name: "OSPF invalid areas JSON",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": "{bad",
			},
			wantErr: "invalid ospf_areas JSON",
		},
		{
			name: "OSPF invalid area_id",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": `[{"area_id":"xyz","networks":["10.0.0.0/24"]}]`,
			},
			wantErr: "invalid area_id",
		},
		{
			name: "OSPF area with no networks",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": `[{"area_id":"0","networks":[]}]`,
			},
			wantErr: "at least one network is required",
		},
		{
			name: "OSPF area invalid network CIDR",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": `[{"area_id":"0","networks":["bad"]}]`,
			},
			wantErr: "invalid CIDR",
		},
		{
			name: "OSPF area_id as IP is valid",
			cfg: map[string]string{
				"mode":       "ospf",
				"router_id":  "10.0.0.1",
				"ospf_areas": `[{"area_id":"0.0.0.0","networks":["10.0.0.0/24"]}]`,
			},
		},
		{
			name: "invalid bgp_redistribute value",
			cfg: map[string]string{
				"mode":             "bgp",
				"router_id":       "10.0.0.1",
				"bgp_asn":         "65000",
				"bgp_redistribute": "connected,rip",
			},
			wantErr: "invalid bgp_redistribute value",
		},
		{
			name: "invalid ospf_redistribute value",
			cfg: map[string]string{
				"mode":              "ospf",
				"router_id":        "10.0.0.1",
				"ospf_redistribute": "kernel",
			},
			wantErr: "invalid ospf_redistribute value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CertStore tests
// ---------------------------------------------------------------------------

func TestCertStore_Metadata(t *testing.T) {
	svc := NewCertStore()
	if svc == nil {
		t.Fatal("NewCertStore returned nil")
	}
	if got := svc.Name(); got != "certstore" {
		t.Errorf("Name() = %q, want %q", got, "certstore")
	}
	if got := svc.DisplayName(); got != "Certificate Store" {
		t.Errorf("DisplayName() = %q, want %q", got, "Certificate Store")
	}
	if got := svc.Category(); got != "security" {
		t.Errorf("Category() = %q, want %q", got, "security")
	}
	if got := svc.Description(); got == "" {
		t.Error("Description() is empty")
	}
	if got := svc.Dependencies(); got != nil {
		t.Errorf("Dependencies() = %v, want nil", got)
	}
}

func TestCertStore_Status_InitiallyStopped(t *testing.T) {
	svc := NewCertStore()
	if got := svc.Status(); got != StateStopped {
		t.Errorf("Status() = %q, want %q", got, StateStopped)
	}
}

func TestCertStore_DefaultConfig(t *testing.T) {
	svc := NewCertStore()
	dc := svc.DefaultConfig()

	expectedKeys := []string{
		"ca_dir", "cert_dir", "ca_cn", "ca_org",
		"ca_validity_years", "cert_validity_days",
		"acme_email", "acme_directory", "auto_renew", "renew_before_days",
	}
	for _, key := range expectedKeys {
		if _, ok := dc[key]; !ok {
			t.Errorf("DefaultConfig() missing key %q", key)
		}
	}
	if dc["ca_dir"] != "/var/lib/gatekeeper/ca" {
		t.Errorf("DefaultConfig()[ca_dir] = %q, want %q", dc["ca_dir"], "/var/lib/gatekeeper/ca")
	}
	if dc["cert_dir"] != "/var/lib/gatekeeper/certs" {
		t.Errorf("DefaultConfig()[cert_dir] = %q, want %q", dc["cert_dir"], "/var/lib/gatekeeper/certs")
	}
	if dc["auto_renew"] != "true" {
		t.Errorf("DefaultConfig()[auto_renew] = %q, want %q", dc["auto_renew"], "true")
	}
	if dc["ca_validity_years"] != "10" {
		t.Errorf("DefaultConfig()[ca_validity_years] = %q, want %q", dc["ca_validity_years"], "10")
	}
}

func TestCertStore_ConfigSchema(t *testing.T) {
	svc := NewCertStore()
	schema := svc.ConfigSchema()

	expectedFields := []string{
		"ca_dir", "cert_dir", "ca_cn", "ca_org",
		"ca_validity_years", "cert_validity_days",
		"acme_email", "acme_directory", "auto_renew", "renew_before_days",
	}
	for _, key := range expectedFields {
		f, ok := schema[key]
		if !ok {
			t.Errorf("ConfigSchema() missing field %q", key)
			continue
		}
		if f.Description == "" {
			t.Errorf("ConfigSchema()[%s].Description is empty", key)
		}
		if f.Type == "" {
			t.Errorf("ConfigSchema()[%s].Type is empty", key)
		}
	}

	if !schema["ca_dir"].Required {
		t.Error("ConfigSchema()[ca_dir].Required should be true")
	}
	if !schema["cert_dir"].Required {
		t.Error("ConfigSchema()[cert_dir].Required should be true")
	}
	if schema["ca_dir"].Type != "path" {
		t.Errorf("ConfigSchema()[ca_dir].Type = %q, want %q", schema["ca_dir"].Type, "path")
	}
	if schema["cert_dir"].Type != "path" {
		t.Errorf("ConfigSchema()[cert_dir].Type = %q, want %q", schema["cert_dir"].Type, "path")
	}
	if schema["ca_validity_years"].Type != "int" {
		t.Errorf("ConfigSchema()[ca_validity_years].Type = %q, want %q", schema["ca_validity_years"].Type, "int")
	}
	if schema["auto_renew"].Type != "bool" {
		t.Errorf("ConfigSchema()[auto_renew].Type = %q, want %q", schema["auto_renew"].Type, "bool")
	}
}

func TestCertStore_Validate(t *testing.T) {
	svc := NewCertStore()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr string
	}{
		{
			name: "valid minimal config",
			cfg: map[string]string{
				"ca_dir":   "/var/lib/gatekeeper/ca",
				"cert_dir": "/var/lib/gatekeeper/certs",
			},
		},
		{
			name: "valid full config",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_cn":             "My CA",
				"ca_org":            "My Org",
				"ca_validity_years": "5",
				"cert_validity_days": "90",
				"auto_renew":        "true",
				"renew_before_days": "14",
			},
		},
		{
			name: "missing ca_dir",
			cfg: map[string]string{
				"cert_dir": "/var/lib/gatekeeper/certs",
			},
			wantErr: "ca_dir is required",
		},
		{
			name: "empty ca_dir",
			cfg: map[string]string{
				"ca_dir":   "",
				"cert_dir": "/var/lib/gatekeeper/certs",
			},
			wantErr: "ca_dir is required",
		},
		{
			name: "missing cert_dir",
			cfg: map[string]string{
				"ca_dir": "/var/lib/gatekeeper/ca",
			},
			wantErr: "cert_dir is required",
		},
		{
			name: "ca_validity_years too low",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_validity_years": "0",
			},
			wantErr: "ca_validity_years must be between 1 and 100",
		},
		{
			name: "ca_validity_years too high",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_validity_years": "101",
			},
			wantErr: "ca_validity_years must be between 1 and 100",
		},
		{
			name: "ca_validity_years not a number",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_validity_years": "abc",
			},
			wantErr: "ca_validity_years must be between 1 and 100",
		},
		{
			name: "cert_validity_days too low",
			cfg: map[string]string{
				"ca_dir":              "/var/lib/gatekeeper/ca",
				"cert_dir":           "/var/lib/gatekeeper/certs",
				"cert_validity_days": "0",
			},
			wantErr: "cert_validity_days must be between 1 and 3650",
		},
		{
			name: "cert_validity_days too high",
			cfg: map[string]string{
				"ca_dir":              "/var/lib/gatekeeper/ca",
				"cert_dir":           "/var/lib/gatekeeper/certs",
				"cert_validity_days": "3651",
			},
			wantErr: "cert_validity_days must be between 1 and 3650",
		},
		{
			name: "renew_before_days too low",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"renew_before_days": "0",
			},
			wantErr: "renew_before_days must be between 1 and 365",
		},
		{
			name: "renew_before_days too high",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"renew_before_days": "366",
			},
			wantErr: "renew_before_days must be between 1 and 365",
		},
		{
			name: "invalid auto_renew",
			cfg: map[string]string{
				"ca_dir":      "/var/lib/gatekeeper/ca",
				"cert_dir":   "/var/lib/gatekeeper/certs",
				"auto_renew": "yes",
			},
			wantErr: "auto_renew must be 'true' or 'false'",
		},
		{
			name: "auto_renew false is valid",
			cfg: map[string]string{
				"ca_dir":      "/var/lib/gatekeeper/ca",
				"cert_dir":   "/var/lib/gatekeeper/certs",
				"auto_renew": "false",
			},
		},
		{
			name: "boundary: ca_validity_years = 1",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_validity_years": "1",
			},
		},
		{
			name: "boundary: ca_validity_years = 100",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"ca_validity_years": "100",
			},
		},
		{
			name: "boundary: cert_validity_days = 3650",
			cfg: map[string]string{
				"ca_dir":              "/var/lib/gatekeeper/ca",
				"cert_dir":           "/var/lib/gatekeeper/certs",
				"cert_validity_days": "3650",
			},
		},
		{
			name: "boundary: renew_before_days = 365",
			cfg: map[string]string{
				"ca_dir":             "/var/lib/gatekeeper/ca",
				"cert_dir":          "/var/lib/gatekeeper/certs",
				"renew_before_days": "365",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Validate(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-service: DefaultConfig keys match ConfigSchema keys
// ---------------------------------------------------------------------------

func TestDefaultConfigKeysMatchConfigSchema(t *testing.T) {
	services := []struct {
		name   string
		dc     map[string]string
		schema map[string]ConfigField
	}{
		{"VPNLegs", NewVPNLegs("/tmp").DefaultConfig(), NewVPNLegs("/tmp").ConfigSchema()},
		{"VPNProvider", NewVPNProvider().DefaultConfig(), NewVPNProvider().ConfigSchema()},
		{"FRRouting", NewFRRouting("/tmp").DefaultConfig(), NewFRRouting("/tmp").ConfigSchema()},
		{"CertStore", NewCertStore().DefaultConfig(), NewCertStore().ConfigSchema()},
	}

	for _, svc := range services {
		t.Run(svc.name, func(t *testing.T) {
			// Every key in DefaultConfig should exist in ConfigSchema.
			for key := range svc.dc {
				if _, ok := svc.schema[key]; !ok {
					t.Errorf("DefaultConfig key %q not found in ConfigSchema", key)
				}
			}
			// Every key in ConfigSchema should exist in DefaultConfig.
			for key := range svc.schema {
				if _, ok := svc.dc[key]; !ok {
					t.Errorf("ConfigSchema key %q not found in DefaultConfig", key)
				}
			}
		})
	}
}

package ha

import (
	"errors"
	"testing"
)

func TestNewHAManager(t *testing.T) {
	m := NewHAManager()
	if m == nil {
		t.Fatal("NewHAManager() returned nil")
	}
}

func TestServiceMetadata(t *testing.T) {
	m := NewHAManager()

	tests := []struct {
		method string
		got    string
		want   string
	}{
		{"Name", m.Name(), "ha"},
		{"DisplayName", m.DisplayName(), "High Availability"},
		{"Category", m.Category(), "cluster"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.method, tt.got, tt.want)
			}
		})
	}

	if desc := m.Description(); desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestDefaultConfig(t *testing.T) {
	m := NewHAManager()
	cfg := m.DefaultConfig()

	requiredKeys := []string{
		"mode", "node_id", "cluster_name", "virtual_ip",
		"vrrp_interface", "vrrp_priority", "vrrp_auth_pass",
		"peer_nodes", "heartbeat_interval", "keepalived_conf_dir",
	}

	for _, key := range requiredKeys {
		if _, ok := cfg[key]; !ok {
			t.Errorf("DefaultConfig() missing key %q", key)
		}
	}

	expectedDefaults := map[string]string{
		"mode":               "standalone",
		"cluster_name":       "gatekeeper",
		"vrrp_priority":      "100",
		"heartbeat_interval": "1",
		"keepalived_conf_dir": "/etc/keepalived",
	}

	for key, want := range expectedDefaults {
		if got := cfg[key]; got != want {
			t.Errorf("DefaultConfig()[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestConfigSchema(t *testing.T) {
	m := NewHAManager()
	schema := m.ConfigSchema()

	expectedTypes := map[string]string{
		"mode":               "string",
		"vrrp_priority":      "int",
		"heartbeat_interval": "int",
		"keepalived_conf_dir": "path",
	}

	for field, wantType := range expectedTypes {
		cf, ok := schema[field]
		if !ok {
			t.Errorf("ConfigSchema() missing field %q", field)
			continue
		}
		if cf.Type != wantType {
			t.Errorf("ConfigSchema()[%q].Type = %q, want %q", field, cf.Type, wantType)
		}
	}

	// "mode" should be required
	if modeField, ok := schema["mode"]; ok && !modeField.Required {
		t.Error("ConfigSchema()[\"mode\"].Required should be true")
	}
}

func TestValidate(t *testing.T) {
	m := NewHAManager()

	tests := []struct {
		name    string
		cfg     map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "standalone mode requires no extra fields",
			cfg:     map[string]string{"mode": "standalone"},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			cfg:     map[string]string{"mode": "bogus"},
			wantErr: true,
			errMsg:  "invalid mode",
		},
		{
			name: "active-passive missing node_id",
			cfg: map[string]string{
				"mode":       "active-passive",
				"virtual_ip": "10.0.0.1",
			},
			wantErr: true,
			errMsg:  "node_id is required",
		},
		{
			name: "active-passive missing virtual_ip",
			cfg: map[string]string{
				"mode":    "active-passive",
				"node_id": "node1",
			},
			wantErr: true,
			errMsg:  "virtual_ip is required",
		},
		{
			name: "active-passive invalid virtual_ip",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "not-an-ip",
				"vrrp_interface": "eth0",
			},
			wantErr: true,
			errMsg:  "invalid virtual_ip",
		},
		{
			name: "active-passive missing vrrp_interface",
			cfg: map[string]string{
				"mode":       "active-passive",
				"node_id":    "node1",
				"virtual_ip": "10.0.0.1",
			},
			wantErr: true,
			errMsg:  "vrrp_interface is required",
		},
		{
			name: "vrrp_priority out of range low",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "10.0.0.1",
				"vrrp_interface": "eth0",
				"vrrp_priority":  "0",
			},
			wantErr: true,
			errMsg:  "vrrp_priority must be between 1 and 254",
		},
		{
			name: "vrrp_priority out of range high",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "10.0.0.1",
				"vrrp_interface": "eth0",
				"vrrp_priority":  "255",
			},
			wantErr: true,
			errMsg:  "vrrp_priority must be between 1 and 254",
		},
		{
			name: "vrrp_auth_pass too long",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "10.0.0.1",
				"vrrp_interface": "eth0",
				"vrrp_auth_pass": "123456789",
			},
			wantErr: true,
			errMsg:  "vrrp_auth_pass must be at most 8 characters",
		},
		{
			name: "heartbeat_interval out of range",
			cfg: map[string]string{
				"mode":               "active-passive",
				"node_id":            "node1",
				"virtual_ip":         "10.0.0.1",
				"vrrp_interface":     "eth0",
				"heartbeat_interval": "99",
			},
			wantErr: true,
			errMsg:  "heartbeat_interval must be between 1 and 60",
		},
		{
			name: "invalid peer_nodes JSON",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "10.0.0.1",
				"vrrp_interface": "eth0",
				"peer_nodes":     "not-json",
			},
			wantErr: true,
			errMsg:  "peer_nodes must be a valid JSON array",
		},
		{
			name: "valid active-passive config",
			cfg: map[string]string{
				"mode":               "active-passive",
				"node_id":            "node1",
				"virtual_ip":         "10.0.0.1",
				"vrrp_interface":     "eth0",
				"vrrp_priority":      "150",
				"vrrp_auth_pass":     "secret",
				"peer_nodes":         `["10.0.0.2"]`,
				"heartbeat_interval": "5",
			},
			wantErr: false,
		},
		{
			name: "valid active-active config",
			cfg: map[string]string{
				"mode":           "active-active",
				"node_id":        "node2",
				"virtual_ip":     "192.168.1.100",
				"vrrp_interface": "eth1",
			},
			wantErr: false,
		},
		{
			name: "valid config with IPv6 virtual_ip",
			cfg: map[string]string{
				"mode":           "active-passive",
				"node_id":        "node1",
				"virtual_ip":     "fd00::1",
				"vrrp_interface": "eth0",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.Validate(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
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

func TestStatusStartsStopped(t *testing.T) {
	m := NewHAManager()
	if got := m.Status(); got != StateStopped {
		t.Errorf("Status() = %q, want %q", got, StateStopped)
	}
}

func TestRoleStartsStandalone(t *testing.T) {
	m := NewHAManager()
	if got := m.Role(); got != RoleStandalone {
		t.Errorf("Role() = %q, want %q", got, RoleStandalone)
	}
}

func TestRegisterHealthCheck(t *testing.T) {
	m := NewHAManager()

	called := false
	check := HealthCheck{
		Name:     "test-check",
		Endpoint: "/test",
		CheckFn: func() error {
			called = true
			return nil
		},
	}

	m.RegisterHealthCheck(check)

	// Run health checks manually
	m.runHealthChecks()

	if !called {
		t.Error("health check function was not called")
	}

	statuses := m.HealthStatuses()
	status, ok := statuses["test-check"]
	if !ok {
		t.Fatal("expected status for 'test-check'")
	}
	if !status.Healthy {
		t.Error("expected health check to be healthy")
	}
	if status.Error != "" {
		t.Errorf("expected no error, got %q", status.Error)
	}
}

func TestHealthCheckFailure(t *testing.T) {
	m := NewHAManager()

	check := HealthCheck{
		Name:     "failing-check",
		Endpoint: "/failing",
		CheckFn: func() error {
			return errors.New("service down")
		},
	}

	m.RegisterHealthCheck(check)
	m.runHealthChecks()

	statuses := m.HealthStatuses()
	status, ok := statuses["failing-check"]
	if !ok {
		t.Fatal("expected status for 'failing-check'")
	}
	if status.Healthy {
		t.Error("expected health check to be unhealthy")
	}
	if !contains(status.Error, "service down") {
		t.Errorf("error %q should contain 'service down'", status.Error)
	}
}

func TestMultipleHealthChecks(t *testing.T) {
	m := NewHAManager()

	m.RegisterHealthCheck(HealthCheck{
		Name:    "check-ok",
		CheckFn: func() error { return nil },
	})
	m.RegisterHealthCheck(HealthCheck{
		Name:    "check-fail",
		CheckFn: func() error { return errors.New("broken") },
	})

	m.runHealthChecks()

	statuses := m.HealthStatuses()
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}
	if !statuses["check-ok"].Healthy {
		t.Error("check-ok should be healthy")
	}
	if statuses["check-fail"].Healthy {
		t.Error("check-fail should be unhealthy")
	}
}

func TestHealthCheckNilFn(t *testing.T) {
	m := NewHAManager()

	m.RegisterHealthCheck(HealthCheck{
		Name:    "nil-fn",
		CheckFn: nil,
	})

	m.runHealthChecks()

	statuses := m.HealthStatuses()
	status, ok := statuses["nil-fn"]
	if !ok {
		t.Fatal("expected status for 'nil-fn'")
	}
	if !status.Healthy {
		t.Error("nil CheckFn should result in healthy status")
	}
}

func TestDependenciesReturnsNil(t *testing.T) {
	m := NewHAManager()
	if deps := m.Dependencies(); deps != nil {
		t.Errorf("Dependencies() = %v, want nil", deps)
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

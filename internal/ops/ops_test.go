package ops_test

import (
	"path/filepath"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
)

// newTestOps creates an Ops backed by a temporary in-memory-like SQLite DB.
func newTestOps(t *testing.T) *ops.Ops {
	t.Helper()
	dir := t.TempDir()
	store, err := config.NewStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return ops.New(store)
}

var cliActor = ops.Actor{Source: "cli", User: "root"}
var apiActor = ops.Actor{Source: "api", User: "api-key"}

// --- Zone Tests ---

func TestCreateZone_Valid(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "lan", Interface: "eth1", NetworkCIDR: "192.168.1.0/24", TrustLevel: "high"}
	if err := o.CreateZone(cliActor, z); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	got, err := o.GetZone("lan")
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}
	if got == nil || got.Name != "lan" {
		t.Fatalf("expected zone 'lan', got %v", got)
	}
}

func TestCreateZone_InvalidName(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "invalid name!", Interface: "eth0"}
	if err := o.CreateZone(cliActor, z); err == nil {
		t.Fatal("expected error for invalid zone name")
	}
}

func TestCreateZone_EmptyName(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: ""}
	if err := o.CreateZone(cliActor, z); err == nil {
		t.Fatal("expected error for empty zone name")
	}
}

func TestCreateZone_InvalidCIDR(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "test", NetworkCIDR: "not-a-cidr"}
	if err := o.CreateZone(cliActor, z); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestCreateZone_InvalidTrust(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "test", TrustLevel: "bogus"}
	if err := o.CreateZone(cliActor, z); err == nil {
		t.Fatal("expected error for invalid trust level")
	}
}

func TestDeleteZone(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "todelete", Interface: "eth0"}
	_ = o.CreateZone(cliActor, z)
	if err := o.DeleteZone(cliActor, "todelete"); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
}

// --- Alias Tests ---

func TestCreateAlias_Valid(t *testing.T) {
	o := newTestOps(t)
	a := &model.Alias{Name: "servers", Type: model.AliasTypeHost, Members: []string{"10.0.0.1"}}
	if err := o.CreateAlias(cliActor, a); err != nil {
		t.Fatalf("CreateAlias: %v", err)
	}
}

func TestCreateAlias_InvalidType(t *testing.T) {
	o := newTestOps(t)
	a := &model.Alias{Name: "bad", Type: "invalid_type"}
	if err := o.CreateAlias(cliActor, a); err == nil {
		t.Fatal("expected error for invalid alias type")
	}
}

func TestCreateAlias_InvalidMember(t *testing.T) {
	o := newTestOps(t)
	a := &model.Alias{Name: "bad-member", Type: model.AliasTypeHost, Members: []string{"not-an-ip"}}
	if err := o.CreateAlias(cliActor, a); err == nil {
		t.Fatal("expected error for invalid host alias member")
	}
}

func TestAddAliasMember_ValidatesType(t *testing.T) {
	o := newTestOps(t)
	a := &model.Alias{Name: "hosts", Type: model.AliasTypeHost}
	_ = o.CreateAlias(cliActor, a)

	// Valid member.
	if err := o.AddAliasMember(cliActor, "hosts", "10.0.0.1"); err != nil {
		t.Fatalf("AddAliasMember valid: %v", err)
	}
	// Invalid member for host type.
	if err := o.AddAliasMember(cliActor, "hosts", "not-an-ip"); err == nil {
		t.Fatal("expected error adding invalid host member")
	}
}

// --- Policy/Rule Tests ---

func TestCreatePolicy_Valid(t *testing.T) {
	o := newTestOps(t)
	p := &model.Policy{Name: "web-policy", DefaultAction: model.RuleActionDeny}
	if err := o.CreatePolicy(cliActor, p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
}

func TestCreateRule_InvalidProtocol(t *testing.T) {
	o := newTestOps(t)
	p := &model.Policy{Name: "pol1"}
	_ = o.CreatePolicy(cliActor, p)
	rule := &model.Rule{Protocol: "invalid", Action: model.RuleActionAllow}
	if err := o.CreateRule(cliActor, "pol1", rule); err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestCreateRule_InvalidAction(t *testing.T) {
	o := newTestOps(t)
	p := &model.Policy{Name: "pol2"}
	_ = o.CreatePolicy(cliActor, p)
	rule := &model.Rule{Protocol: "tcp", Action: "nuke"}
	if err := o.CreateRule(cliActor, "pol2", rule); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestCreateRule_InvalidPorts(t *testing.T) {
	o := newTestOps(t)
	p := &model.Policy{Name: "pol3"}
	_ = o.CreatePolicy(cliActor, p)
	rule := &model.Rule{Protocol: "tcp", Ports: "99999", Action: model.RuleActionAllow}
	if err := o.CreateRule(cliActor, "pol3", rule); err == nil {
		t.Fatal("expected error for invalid port")
	}
}

// --- Profile Tests ---

func TestCreateProfile_Valid(t *testing.T) {
	o := newTestOps(t)
	p := &model.Profile{Name: "default-profile"}
	if err := o.CreateProfile(cliActor, p); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
}

func TestCreateProfile_InvalidName(t *testing.T) {
	o := newTestOps(t)
	p := &model.Profile{Name: "has spaces"}
	if err := o.CreateProfile(cliActor, p); err == nil {
		t.Fatal("expected error for invalid profile name")
	}
}

// --- Device Tests ---

func TestAssignDevice_Valid(t *testing.T) {
	o := newTestOps(t)
	// Create a profile first.
	prof := &model.Profile{Name: "dev-profile"}
	_ = o.CreateProfile(cliActor, prof)

	d, err := o.AssignDevice(cliActor, "10.0.0.5", "aa:bb:cc:dd:ee:ff", "myhost", "dev-profile", 0)
	if err != nil {
		t.Fatalf("AssignDevice: %v", err)
	}
	if d.IP != "10.0.0.5" {
		t.Fatalf("expected IP 10.0.0.5, got %s", d.IP)
	}
}

func TestAssignDevice_InvalidIP(t *testing.T) {
	o := newTestOps(t)
	_, err := o.AssignDevice(cliActor, "not-an-ip", "", "", "", 1)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestAssignDevice_InvalidMAC(t *testing.T) {
	o := newTestOps(t)
	_, err := o.AssignDevice(cliActor, "10.0.0.1", "bad-mac", "", "", 1)
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
}

func TestAssignDevice_MissingProfile(t *testing.T) {
	o := newTestOps(t)
	_, err := o.AssignDevice(cliActor, "10.0.0.1", "", "", "", 0)
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

// --- Audit Provenance Tests ---

func TestAuditSource_CLI(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "auditzone"}
	_ = o.CreateZone(cliActor, z)

	entries, err := o.ListAuditLog(10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	if entries[0].Source != "cli" {
		t.Errorf("expected source 'cli', got %q", entries[0].Source)
	}
}

func TestAuditSource_API(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "apizone"}
	_ = o.CreateZone(apiActor, z)

	entries, err := o.ListAuditLog(10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	if entries[0].Source != "api" {
		t.Errorf("expected source 'api', got %q", entries[0].Source)
	}
}

// --- Config Operations ---

func TestCommitAndRevisions(t *testing.T) {
	o := newTestOps(t)
	// Seed some data.
	_ = o.CreateZone(cliActor, &model.Zone{Name: "wan", Interface: "eth0", NetworkCIDR: "0.0.0.0/0"})

	rev, err := o.Commit(cliActor, "test commit")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rev != 1 {
		t.Errorf("expected rev 1, got %d", rev)
	}

	revs, err := o.ListRevisions()
	if err != nil {
		t.Fatalf("ListRevisions: %v", err)
	}
	if len(revs) != 1 {
		t.Errorf("expected 1 revision, got %d", len(revs))
	}
}

func TestExportImport(t *testing.T) {
	o := newTestOps(t)
	_ = o.CreateZone(cliActor, &model.Zone{Name: "wan", Interface: "eth0"})
	_ = o.CreateZone(cliActor, &model.Zone{Name: "lan", Interface: "eth1"})

	snap, err := o.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if err := o.Import(cliActor, snap); err != nil {
		t.Fatalf("Import: %v", err)
	}

	zones, _ := o.ListZones()
	if len(zones) != 2 {
		t.Errorf("expected 2 zones after import, got %d", len(zones))
	}
}

// --- PathTest ---

func TestPathTest_RequiresSrcDst(t *testing.T) {
	o := newTestOps(t)
	_, err := o.PathTest(compiler.PathTestRequest{SrcIP: ""})
	if err == nil {
		t.Fatal("expected error for missing src_ip/dst_ip")
	}
}

func TestPathTest_Valid(t *testing.T) {
	o := newTestOps(t)
	_ = o.CreateZone(cliActor, &model.Zone{Name: "wan", Interface: "eth0", NetworkCIDR: "0.0.0.0/0"})
	_ = o.CreateZone(cliActor, &model.Zone{Name: "lan", Interface: "eth1", NetworkCIDR: "192.168.1.0/24"})

	result, err := o.PathTest(compiler.PathTestRequest{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", Protocol: "tcp", DstPort: 80})
	if err != nil {
		t.Fatalf("PathTest: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- Validation Parity Tests ---
// These verify that the same invalid inputs are rejected by the ops layer
// regardless of whether they came from CLI or API context.

func TestValidationParity_ZoneName(t *testing.T) {
	o := newTestOps(t)
	// Note: "x\x00" is NOT in this list because sanitization strips null bytes,
	// leaving "x" which is a valid name. This is correct — sanitize-then-validate.
	badNames := []string{"", "a b", "<script>"}
	for _, name := range badNames {
		z := &model.Zone{Name: name}
		if err := o.CreateZone(cliActor, z); err == nil {
			t.Errorf("CLI: expected error for zone name %q", name)
		}
		if err := o.CreateZone(apiActor, z); err == nil {
			t.Errorf("API: expected error for zone name %q", name)
		}
	}
}

func TestValidationParity_AliasMembers(t *testing.T) {
	o := newTestOps(t)
	// Host alias with non-IP member should fail for both sources.
	a := &model.Alias{Name: "test-host", Type: model.AliasTypeHost, Members: []string{"not-an-ip"}}
	if err := o.CreateAlias(cliActor, a); err == nil {
		t.Error("CLI: expected error for invalid host member")
	}
	if err := o.CreateAlias(apiActor, a); err == nil {
		t.Error("API: expected error for invalid host member")
	}
}

func TestValidationParity_DeviceIP(t *testing.T) {
	o := newTestOps(t)
	badIPs := []string{"", "not-ip", "999.999.999.999"}
	for _, ip := range badIPs {
		if _, err := o.AssignDevice(cliActor, ip, "", "", "", 1); err == nil {
			t.Errorf("CLI: expected error for IP %q", ip)
		}
		if _, err := o.AssignDevice(apiActor, ip, "", "", "", 1); err == nil {
			t.Errorf("API: expected error for IP %q", ip)
		}
	}
}

// --- Sanitization Tests ---
// Verify that null bytes and whitespace are stripped before validation.

func TestSanitization_NullBytesStripped(t *testing.T) {
	o := newTestOps(t)
	// A name with embedded null byte should be sanitized to a valid name.
	z := &model.Zone{Name: "test\x00zone"}
	if err := o.CreateZone(cliActor, z); err != nil {
		t.Fatalf("expected null byte to be stripped, got error: %v", err)
	}
	// The stored name should have the null byte removed.
	got, err := o.GetZone("testzone")
	if err != nil || got == nil {
		t.Fatal("expected to find zone 'testzone' after null byte sanitization")
	}
}

func TestSanitization_WhitespaceStripped(t *testing.T) {
	o := newTestOps(t)
	z := &model.Zone{Name: "  trimmed  "}
	if err := o.CreateZone(cliActor, z); err != nil {
		t.Fatalf("expected whitespace to be trimmed, got error: %v", err)
	}
	got, err := o.GetZone("trimmed")
	if err != nil || got == nil {
		t.Fatal("expected to find zone 'trimmed' after whitespace sanitization")
	}
}

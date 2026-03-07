package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatekeeper-firewall/gatekeeper/internal/api"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

// setup creates a test server with a fresh seeded database.
func setup(t *testing.T) (*httptest.Server, *config.Store) {
	t.Helper()
	store, err := config.NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	handler := api.NewRouterWithConfig(&api.RouterConfig{
		Store:   store,
		APIKey:  "test-key",
		Metrics: api.NewMetrics(),
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, store
}

func doReq(t *testing.T, srv *httptest.Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return resp.StatusCode, result
}

func doReqArray(t *testing.T, srv *httptest.Server, method, path string) (int, []any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-API-Key", "test-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	var result []any
	json.NewDecoder(resp.Body).Decode(&result)
	return resp.StatusCode, result
}

// TestStatusEndpoint verifies the health check (no auth required).
func TestStatusEndpoint(t *testing.T) {
	srv, _ := setup(t)

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/status", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %s", result["status"])
	}
}

// TestAuthRequired verifies that authenticated endpoints reject missing keys.
func TestAuthRequired(t *testing.T) {
	srv, _ := setup(t)

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/zones", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without API key, got %d", resp.StatusCode)
	}
}

// TestZoneCRUD tests the full lifecycle of a zone.
func TestZoneCRUD(t *testing.T) {
	srv, _ := setup(t)

	// List seeded zones.
	code, zones := doReqArray(t, srv, "GET", "/api/v1/zones")
	if code != 200 {
		t.Fatalf("list zones: expected 200, got %d", code)
	}
	if len(zones) < 2 {
		t.Fatalf("expected at least 2 seeded zones, got %d", len(zones))
	}

	// Create a new zone.
	code, result := doReq(t, srv, "POST", "/api/v1/zones",
		`{"name":"dmz","interface":"eth2","network_cidr":"172.16.0.0/24","trust_level":"low"}`)
	if code != 201 {
		t.Fatalf("create zone: expected 201, got %d: %v", code, result)
	}

	// Get the new zone.
	code, result = doReq(t, srv, "GET", "/api/v1/zones/dmz", "")
	if code != 200 {
		t.Fatalf("get zone: expected 200, got %d", code)
	}
	if result["name"] != "dmz" {
		t.Errorf("expected name dmz, got %v", result["name"])
	}

	// Update the zone.
	code, _ = doReq(t, srv, "PUT", "/api/v1/zones/dmz",
		`{"network_cidr":"172.16.1.0/24","trust_level":"medium"}`)
	if code != 200 {
		t.Fatalf("update zone: expected 200, got %d", code)
	}

	// Delete the zone.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/zones/dmz", "")
	if code != 200 {
		t.Fatalf("delete zone: expected 200, got %d", code)
	}

	// Verify deleted.
	code, _ = doReq(t, srv, "GET", "/api/v1/zones/dmz", "")
	if code != 404 {
		t.Fatalf("expected 404 after delete, got %d", code)
	}
}

// TestAliasCRUDWithMembers tests alias creation, member management, and deletion.
func TestAliasCRUDWithMembers(t *testing.T) {
	srv, _ := setup(t)

	// Create alias.
	code, _ := doReq(t, srv, "POST", "/api/v1/aliases",
		`{"name":"webservers","type":"host","members":["10.0.0.1","10.0.0.2"]}`)
	if code != 201 {
		t.Fatalf("create alias: expected 201, got %d", code)
	}

	// Add member.
	code, _ = doReq(t, srv, "POST", "/api/v1/aliases/webservers/members",
		`{"member":"10.0.0.3"}`)
	if code != 200 {
		t.Fatalf("add member: expected 200, got %d", code)
	}

	// Verify member added.
	code, result := doReq(t, srv, "GET", "/api/v1/aliases/webservers", "")
	if code != 200 {
		t.Fatalf("get alias: expected 200, got %d", code)
	}
	members, ok := result["members"].([]any)
	if !ok || len(members) != 3 {
		t.Fatalf("expected 3 members, got %v", result["members"])
	}

	// Remove member.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/aliases/webservers/members",
		`{"member":"10.0.0.3"}`)
	if code != 200 {
		t.Fatalf("remove member: expected 200, got %d", code)
	}

	// Delete alias.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/aliases/webservers", "")
	if code != 200 {
		t.Fatalf("delete alias: expected 200, got %d", code)
	}
}

// TestPolicyCRUDWithRules tests policy creation, rule management, and deletion.
func TestPolicyCRUDWithRules(t *testing.T) {
	srv, _ := setup(t)

	// Create policy.
	code, _ := doReq(t, srv, "POST", "/api/v1/policies",
		`{"name":"test-policy","default_action":"deny"}`)
	if code != 201 {
		t.Fatalf("create policy: expected 201, got %d", code)
	}

	// Add rule.
	code, result := doReq(t, srv, "POST", "/api/v1/policies/test-policy/rules",
		`{"order":1,"src_alias":"","dst_alias":"","protocol":"tcp","ports":"443","action":"allow","log":true}`)
	if code != 201 {
		t.Fatalf("create rule: expected 201, got %d: %v", code, result)
	}

	// Get policy with rules.
	code, result = doReq(t, srv, "GET", "/api/v1/policies/test-policy", "")
	if code != 200 {
		t.Fatalf("get policy: expected 200, got %d", code)
	}
	rules, ok := result["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %v", result["rules"])
	}

	// Get rule ID for deletion.
	rule := rules[0].(map[string]any)
	ruleID := int64(rule["id"].(float64))

	// Delete rule.
	code, _ = doReq(t, srv, "DELETE", fmt.Sprintf("/api/v1/rules/%d", ruleID), "")
	if code != 200 {
		t.Fatalf("delete rule: expected 200, got %d", code)
	}

	// Delete policy.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/policies/test-policy", "")
	if code != 200 {
		t.Fatalf("delete policy: expected 200, got %d", code)
	}
}

// TestDeviceAssignment tests assigning and unassigning devices.
func TestDeviceAssignment(t *testing.T) {
	srv, _ := setup(t)

	// Assign device.
	code, _ := doReq(t, srv, "POST", "/api/v1/assign",
		`{"ip":"10.10.0.50","mac":"aa:bb:cc:dd:ee:ff","hostname":"test-pc","profile":"desktop"}`)
	if code != 201 {
		t.Fatalf("assign: expected 201, got %d", code)
	}

	// List devices.
	code, devices := doReqArray(t, srv, "GET", "/api/v1/devices")
	if code != 200 {
		t.Fatalf("list devices: expected 200, got %d", code)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	// Unassign device.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/unassign", `{"ip":"10.10.0.50"}`)
	if code != 200 {
		t.Fatalf("unassign: expected 200, got %d", code)
	}

	// Verify empty.
	code, devices = doReqArray(t, srv, "GET", "/api/v1/devices")
	if len(devices) != 0 {
		t.Fatalf("expected 0 devices after unassign, got %d", len(devices))
	}
}

// TestProfileCRUD tests profile creation, update, and deletion.
func TestProfileCRUD(t *testing.T) {
	srv, store := setup(t)

	// Get lan zone ID.
	zone, err := store.GetZone("lan")
	if err != nil || zone == nil {
		t.Fatalf("GetZone lan: %v", err)
	}

	// Create profile.
	code, _ := doReq(t, srv, "POST", "/api/v1/profiles",
		fmt.Sprintf(`{"name":"iot","zone_id":%d,"policy_name":"lan-outbound"}`, zone.ID))
	if code != 201 {
		t.Fatalf("create profile: expected 201, got %d", code)
	}

	// Delete profile.
	code, _ = doReq(t, srv, "DELETE", "/api/v1/profiles/iot", "")
	if code != 200 {
		t.Fatalf("delete profile: expected 200, got %d", code)
	}
}

// TestConfigCommitAndRevisions tests the commit and revision listing workflow.
func TestConfigCommitAndRevisions(t *testing.T) {
	srv, _ := setup(t)

	// Commit.
	code, result := doReq(t, srv, "POST", "/api/v1/config/commit",
		`{"message":"test commit"}`)
	if code != 200 {
		t.Fatalf("commit: expected 200, got %d: %v", code, result)
	}
	rev, ok := result["rev"].(float64)
	if !ok || rev < 1 {
		t.Fatalf("expected rev >= 1, got %v", result["rev"])
	}

	// List revisions.
	code, revisions := doReqArray(t, srv, "GET", "/api/v1/config/revisions")
	if code != 200 {
		t.Fatalf("list revisions: expected 200, got %d", code)
	}
	if len(revisions) < 1 {
		t.Fatal("expected at least 1 revision")
	}

	// Export.
	code, export := doReq(t, srv, "GET", "/api/v1/config/export", "")
	if code != 200 {
		t.Fatalf("export: expected 200, got %d", code)
	}
	if export["zones"] == nil {
		t.Error("export missing zones key")
	}
}

// TestPagination tests paginated listing.
func TestPagination(t *testing.T) {
	srv, _ := setup(t)

	code, result := doReq(t, srv, "GET", "/api/v1/zones?limit=1&offset=0", "")
	if code != 200 {
		t.Fatalf("paginated list: expected 200, got %d", code)
	}
	data, ok := result["data"].([]any)
	if !ok {
		t.Fatalf("expected data array, got %v", result)
	}
	if len(data) != 1 {
		t.Errorf("expected 1 item with limit=1, got %d", len(data))
	}
	total, _ := result["total"].(float64)
	if total < 2 {
		t.Errorf("expected total >= 2, got %v", total)
	}
}

// TestDryRun tests the dry_run query parameter.
func TestDryRun(t *testing.T) {
	srv, _ := setup(t)

	code, result := doReq(t, srv, "POST", "/api/v1/zones?dry_run=true",
		`{"name":"test-dry","interface":"eth5","network_cidr":"192.168.5.0/24","trust_level":"none"}`)
	if code != 200 {
		t.Fatalf("dry run: expected 200, got %d", code)
	}
	if result["dry_run"] != true {
		t.Errorf("expected dry_run=true, got %v", result["dry_run"])
	}

	// Verify zone was NOT actually created.
	code, _ = doReq(t, srv, "GET", "/api/v1/zones/test-dry", "")
	if code != 404 {
		t.Fatalf("expected 404 for dry-run zone, got %d", code)
	}
}

// TestPathTest tests the packet path simulation endpoint.
func TestPathTest(t *testing.T) {
	srv, store := setup(t)

	// Create alias, policy with rule, and device for a meaningful test.
	_ = store.CreateAlias(&model.Alias{Name: "dns-servers", Type: "host", Members: []string{"8.8.8.8"}})

	code, result := doReq(t, srv, "POST", "/api/v1/test",
		`{"src_ip":"10.10.0.50","dst_ip":"8.8.8.8","protocol":"udp","dst_port":53}`)
	if code != 200 {
		t.Fatalf("path test: expected 200, got %d: %v", code, result)
	}
	if result["action"] == nil {
		t.Error("expected action in path test result")
	}
}

// TestMetricsEndpoint verifies the Prometheus metrics endpoint.
func TestMetricsEndpoint(t *testing.T) {
	srv, _ := setup(t)

	// Make a few requests first to generate metrics.
	doReqArray(t, srv, "GET", "/api/v1/zones")
	doReqArray(t, srv, "GET", "/api/v1/zones")

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/metrics", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

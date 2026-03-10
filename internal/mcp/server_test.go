package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── New() defaults ──────────────────────────────────────────────────────────

func TestNew_DefaultRateLimits(t *testing.T) {
	tests := []struct {
		name   string
		cfg    MCPConfig
		wantRO int
		wantDi int
		wantMu int
		wantDa int
	}{
		{
			name:   "all zeros get defaults",
			cfg:    MCPConfig{},
			wantRO: 120,
			wantDi: 30,
			wantMu: 10,
			wantDa: 5,
		},
		{
			name: "negative values get defaults",
			cfg: MCPConfig{
				ReadOnlyRateLimit:  -1,
				DiagRateLimit:      -5,
				MutationRateLimit:  -10,
				DangerousRateLimit: -20,
			},
			wantRO: 120,
			wantDi: 30,
			wantMu: 10,
			wantDa: 5,
		},
		{
			name: "custom values preserved",
			cfg: MCPConfig{
				ReadOnlyRateLimit:  200,
				DiagRateLimit:      50,
				MutationRateLimit:  20,
				DangerousRateLimit: 2,
			},
			wantRO: 200,
			wantDi: 50,
			wantMu: 20,
			wantDa: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.cfg)
			if s.cfg.ReadOnlyRateLimit != tc.wantRO {
				t.Errorf("ReadOnlyRateLimit = %d, want %d", s.cfg.ReadOnlyRateLimit, tc.wantRO)
			}
			if s.cfg.DiagRateLimit != tc.wantDi {
				t.Errorf("DiagRateLimit = %d, want %d", s.cfg.DiagRateLimit, tc.wantDi)
			}
			if s.cfg.MutationRateLimit != tc.wantMu {
				t.Errorf("MutationRateLimit = %d, want %d", s.cfg.MutationRateLimit, tc.wantMu)
			}
			if s.cfg.DangerousRateLimit != tc.wantDa {
				t.Errorf("DangerousRateLimit = %d, want %d", s.cfg.DangerousRateLimit, tc.wantDa)
			}
		})
	}
}

func TestNew_RegistersTools(t *testing.T) {
	s := New(MCPConfig{})
	if len(s.tools) == 0 {
		t.Fatal("expected tools to be registered, got 0")
	}
	// Spot-check a few expected tool names.
	for _, name := range []string{"list_zones", "get_zone", "status", "ping", "dry_run"} {
		if _, ok := s.tools[name]; !ok {
			t.Errorf("expected tool %q to be registered", name)
		}
	}
}

func TestNew_LimiterInitialized(t *testing.T) {
	s := New(MCPConfig{})
	if s.limiter == nil {
		t.Fatal("expected limiter to be initialized")
	}
}

// ─── isToolAllowed ───────────────────────────────────────────────────────────

func TestIsToolAllowed(t *testing.T) {
	tests := []struct {
		name        string
		permissions map[string][]string
		principal   string
		tool        string
		want        bool
	}{
		{
			name:        "nil permissions allows everything",
			permissions: nil,
			principal:   "alice",
			tool:        "list_zones",
			want:        true,
		},
		{
			name:        "principal not in map and no wildcard denies",
			permissions: map[string][]string{"bob": {"list_zones"}},
			principal:   "alice",
			tool:        "list_zones",
			want:        false,
		},
		{
			name:        "principal with exact tool match",
			permissions: map[string][]string{"alice": {"list_zones", "get_zone"}},
			principal:   "alice",
			tool:        "get_zone",
			want:        true,
		},
		{
			name:        "principal with tool not in list",
			permissions: map[string][]string{"alice": {"list_zones"}},
			principal:   "alice",
			tool:        "create_zone",
			want:        false,
		},
		{
			name:        "principal with wildcard tool",
			permissions: map[string][]string{"alice": {"*"}},
			principal:   "alice",
			tool:        "anything",
			want:        true,
		},
		{
			name:        "wildcard principal allows tool",
			permissions: map[string][]string{"*": {"list_zones", "status"}},
			principal:   "unknown_user",
			tool:        "status",
			want:        true,
		},
		{
			name:        "wildcard principal denies unlisted tool",
			permissions: map[string][]string{"*": {"list_zones"}},
			principal:   "unknown_user",
			tool:        "create_zone",
			want:        false,
		},
		{
			name:        "specific principal overrides wildcard",
			permissions: map[string][]string{"alice": {"create_zone"}, "*": {"list_zones"}},
			principal:   "alice",
			tool:        "create_zone",
			want:        true,
		},
		{
			name:        "empty allow list denies everything",
			permissions: map[string][]string{"alice": {}},
			principal:   "alice",
			tool:        "list_zones",
			want:        false,
		},
		{
			name:        "empty map denies unknown principal",
			permissions: map[string][]string{},
			principal:   "alice",
			tool:        "list_zones",
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: MCPConfig{Permissions: tc.permissions}}
			got := s.isToolAllowed(tc.principal, tc.tool)
			if got != tc.want {
				t.Errorf("isToolAllowed(%q, %q) = %v, want %v", tc.principal, tc.tool, got, tc.want)
			}
		})
	}
}

// ─── inZoneScope ─────────────────────────────────────────────────────────────

func TestInZoneScope(t *testing.T) {
	tests := []struct {
		name      string
		zoneScope map[string][]string
		principal string
		zone      string
		want      bool
	}{
		{
			name:      "nil scope allows all",
			zoneScope: nil,
			principal: "alice",
			zone:      "lan",
			want:      true,
		},
		{
			name:      "principal not in scope allows all",
			zoneScope: map[string][]string{"bob": {"lan"}},
			principal: "alice",
			zone:      "dmz",
			want:      true,
		},
		{
			name:      "zone in scope",
			zoneScope: map[string][]string{"alice": {"lan", "dmz"}},
			principal: "alice",
			zone:      "dmz",
			want:      true,
		},
		{
			name:      "zone not in scope",
			zoneScope: map[string][]string{"alice": {"lan"}},
			principal: "alice",
			zone:      "dmz",
			want:      false,
		},
		{
			name:      "wildcard zone allows all",
			zoneScope: map[string][]string{"alice": {"*"}},
			principal: "alice",
			zone:      "anything",
			want:      true,
		},
		{
			name:      "empty scope list denies all",
			zoneScope: map[string][]string{"alice": {}},
			principal: "alice",
			zone:      "lan",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: MCPConfig{ZoneScope: tc.zoneScope}}
			got := s.inZoneScope(tc.principal, tc.zone)
			if got != tc.want {
				t.Errorf("inZoneScope(%q, %q) = %v, want %v", tc.principal, tc.zone, got, tc.want)
			}
		})
	}
}

// ─── inProfileScope ──────────────────────────────────────────────────────────

func TestInProfileScope(t *testing.T) {
	tests := []struct {
		name         string
		profileScope map[string][]string
		principal    string
		profile      string
		want         bool
	}{
		{
			name:         "nil scope allows all",
			profileScope: nil,
			principal:    "alice",
			profile:      "default",
			want:         true,
		},
		{
			name:         "principal not in scope allows all",
			profileScope: map[string][]string{"bob": {"default"}},
			principal:    "alice",
			profile:      "restricted",
			want:         true,
		},
		{
			name:         "profile in scope",
			profileScope: map[string][]string{"alice": {"default", "iot"}},
			principal:    "alice",
			profile:      "iot",
			want:         true,
		},
		{
			name:         "profile not in scope",
			profileScope: map[string][]string{"alice": {"default"}},
			principal:    "alice",
			profile:      "iot",
			want:         false,
		},
		{
			name:         "wildcard profile",
			profileScope: map[string][]string{"alice": {"*"}},
			principal:    "alice",
			profile:      "anything",
			want:         true,
		},
		{
			name:         "empty scope list denies all",
			profileScope: map[string][]string{"alice": {}},
			principal:    "alice",
			profile:      "default",
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: MCPConfig{ProfileScope: tc.profileScope}}
			got := s.inProfileScope(tc.principal, tc.profile)
			if got != tc.want {
				t.Errorf("inProfileScope(%q, %q) = %v, want %v", tc.principal, tc.profile, got, tc.want)
			}
		})
	}
}

// ─── Rate Limiter ────────────────────────────────────────────────────────────

func TestRateLimiter_AllowAndDeny(t *testing.T) {
	rl := newRateLimiter()
	key := "alice:list_zones"

	// Should allow up to the limit.
	for i := 0; i < 3; i++ {
		if !rl.allow(key, 3) {
			t.Fatalf("allow() returned false on call %d, expected true (limit=3)", i+1)
		}
	}

	// The 4th call should be denied.
	if rl.allow(key, 3) {
		t.Fatal("allow() returned true on call 4, expected false (limit=3)")
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	rl := newRateLimiter()

	// Fill up key A.
	for i := 0; i < 2; i++ {
		rl.allow("a:tool", 2)
	}
	if rl.allow("a:tool", 2) {
		t.Fatal("expected key a:tool to be rate-limited")
	}

	// Key B should still be allowed.
	if !rl.allow("b:tool", 2) {
		t.Fatal("expected key b:tool to be allowed (independent)")
	}
}

func TestRateLimiter_LimitOfOne(t *testing.T) {
	rl := newRateLimiter()
	if !rl.allow("k", 1) {
		t.Fatal("first call should be allowed with limit=1")
	}
	if rl.allow("k", 1) {
		t.Fatal("second call should be denied with limit=1")
	}
}

func TestRateLimiter_PrunesOldEntries(t *testing.T) {
	rl := newRateLimiter()
	key := "test:prune"

	// Manually inject entries older than 1 minute.
	rl.mu.Lock()
	old := time.Now().Add(-2 * time.Minute)
	rl.counts[key] = []time.Time{old, old, old}
	rl.mu.Unlock()

	// Despite 3 old entries, a new call should succeed since they're expired.
	if !rl.allow(key, 3) {
		t.Fatal("expected allow after old entries are pruned")
	}
}

// ─── checkRateLimit ──────────────────────────────────────────────────────────

func TestCheckRateLimit_CategoryDefault(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			ReadOnlyRateLimit:  2,
			DiagRateLimit:      1,
			MutationRateLimit:  1,
			DangerousRateLimit: 1,
		},
		limiter: newRateLimiter(),
	}

	tool := &Tool{Name: "test_read", Category: CategoryReadOnly}

	if !s.checkRateLimit("alice", tool) {
		t.Fatal("first call should be within limit")
	}
	if !s.checkRateLimit("alice", tool) {
		t.Fatal("second call should be within limit (limit=2)")
	}
	if s.checkRateLimit("alice", tool) {
		t.Fatal("third call should exceed limit (limit=2)")
	}
}

func TestCheckRateLimit_ToolConfigOverride(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			ReadOnlyRateLimit: 100, // high category default
			ToolRateLimits:    map[string]int{"restricted_tool": 1},
		},
		limiter: newRateLimiter(),
	}

	tool := &Tool{Name: "restricted_tool", Category: CategoryReadOnly}

	if !s.checkRateLimit("alice", tool) {
		t.Fatal("first call should be allowed")
	}
	if s.checkRateLimit("alice", tool) {
		t.Fatal("second call should be denied (tool override limit=1)")
	}
}

func TestCheckRateLimit_ToolFieldOverride(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			ReadOnlyRateLimit: 100,
			ToolRateLimits:    map[string]int{"my_tool": 100},
		},
		limiter: newRateLimiter(),
	}

	// Per-tool rateLimit field should take priority over both category and config.
	tool := &Tool{Name: "my_tool", Category: CategoryReadOnly, rateLimit: 1}

	if !s.checkRateLimit("alice", tool) {
		t.Fatal("first call should be allowed")
	}
	if s.checkRateLimit("alice", tool) {
		t.Fatal("second call should be denied (tool.rateLimit=1 overrides)")
	}
}

// ─── categoryRateLimit ───────────────────────────────────────────────────────

func TestCategoryRateLimit(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			ReadOnlyRateLimit:  120,
			DiagRateLimit:      30,
			MutationRateLimit:  10,
			DangerousRateLimit: 5,
		},
	}

	tests := []struct {
		category ToolCategory
		want     int
	}{
		{CategoryReadOnly, 120},
		{CategorySuggest, 120}, // shares with read-only
		{CategoryDiag, 30},
		{CategoryMutation, 10},
		{CategoryDangerous, 5},
		{ToolCategory("unknown"), 120}, // default falls back to read-only
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			tool := &Tool{Category: tc.category}
			got := s.categoryRateLimit(tool)
			if got != tc.want {
				t.Errorf("categoryRateLimit(%q) = %d, want %d", tc.category, got, tc.want)
			}
		})
	}
}

// ─── promptContextHash ───────────────────────────────────────────────────────

func TestPromptContextHash(t *testing.T) {
	tests := []struct {
		name  string
		input json.RawMessage
		want  string
	}{
		{
			name:  "empty input returns empty",
			input: nil,
			want:  "",
		},
		{
			name:  "empty bytes returns empty",
			input: json.RawMessage{},
			want:  "",
		},
		{
			name:  "produces truncated SHA-256",
			input: json.RawMessage(`{"zone":"lan"}`),
			want: func() string {
				h := sha256.Sum256([]byte(`{"zone":"lan"}`))
				return fmt.Sprintf("%x", h[:16])
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := promptContextHash(tc.input)
			if got != tc.want {
				t.Errorf("promptContextHash() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPromptContextHash_DeterministicAndLength(t *testing.T) {
	input := json.RawMessage(`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`)

	h1 := promptContextHash(input)
	h2 := promptContextHash(input)

	if h1 != h2 {
		t.Errorf("expected deterministic output, got %q != %q", h1, h2)
	}

	// 16 bytes in hex = 32 characters.
	if len(h1) != 32 {
		t.Errorf("expected 32-char hex string, got %d chars: %q", len(h1), h1)
	}
}

func TestPromptContextHash_DifferentInputsDiffer(t *testing.T) {
	a := promptContextHash(json.RawMessage(`{"a":1}`))
	b := promptContextHash(json.RawMessage(`{"b":2}`))

	if a == b {
		t.Error("expected different hashes for different inputs")
	}
}

// ─── jsonSchema ──────────────────────────────────────────────────────────────

func TestJsonSchema_NilProperties(t *testing.T) {
	got := jsonSchema(nil, nil)
	want := `{"type":"object","properties":{}}`
	if string(got) != want {
		t.Errorf("jsonSchema(nil, nil) = %s, want %s", got, want)
	}
}

func TestJsonSchema_WithProperties(t *testing.T) {
	raw := jsonSchema(
		map[string]schemaField{
			"name": {Type: "string", Desc: "The name"},
		},
		[]string{"name"},
	)

	var schema map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("failed to unmarshal schema: %v", err)
	}

	// Check top-level type.
	var typ string
	json.Unmarshal(schema["type"], &typ)
	if typ != "object" {
		t.Errorf("type = %q, want %q", typ, "object")
	}

	// Check properties.
	var props map[string]map[string]string
	if err := json.Unmarshal(schema["properties"], &props); err != nil {
		t.Fatalf("failed to unmarshal properties: %v", err)
	}
	nameProp, ok := props["name"]
	if !ok {
		t.Fatal("expected 'name' property in schema")
	}
	if nameProp["type"] != "string" {
		t.Errorf("name.type = %q, want %q", nameProp["type"], "string")
	}
	if nameProp["description"] != "The name" {
		t.Errorf("name.description = %q, want %q", nameProp["description"], "The name")
	}

	// Check required.
	var required []string
	if err := json.Unmarshal(schema["required"], &required); err != nil {
		t.Fatalf("failed to unmarshal required: %v", err)
	}
	if len(required) != 1 || required[0] != "name" {
		t.Errorf("required = %v, want [name]", required)
	}
}

func TestJsonSchema_NoRequired(t *testing.T) {
	raw := jsonSchema(
		map[string]schemaField{
			"limit": {Type: "integer", Desc: "Max results"},
		},
		nil,
	)

	var schema map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("failed to unmarshal schema: %v", err)
	}

	if _, ok := schema["required"]; ok {
		t.Error("expected no 'required' key when required is nil")
	}
}

func TestJsonSchema_FieldWithoutDescription(t *testing.T) {
	raw := jsonSchema(
		map[string]schemaField{
			"count": {Type: "integer"},
		},
		nil,
	)

	var schema struct {
		Properties map[string]map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	countProp := schema.Properties["count"]
	if countProp["type"] != "integer" {
		t.Errorf("count.type = %q, want %q", countProp["type"], "integer")
	}
	if _, ok := countProp["description"]; ok {
		t.Error("expected no 'description' when Desc is empty")
	}
}

func TestJsonSchema_MultipleProperties(t *testing.T) {
	raw := jsonSchema(
		map[string]schemaField{
			"name":    {Type: "string", Desc: "Name"},
			"enabled": {Type: "boolean", Desc: "On/off"},
			"count":   {Type: "integer", Desc: "Number"},
		},
		[]string{"name", "count"},
	)

	var schema struct {
		Type       string                       `json:"type"`
		Properties map[string]map[string]string `json:"properties"`
		Required   []string                     `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(schema.Properties) != 3 {
		t.Errorf("expected 3 properties, got %d", len(schema.Properties))
	}
	if len(schema.Required) != 2 {
		t.Errorf("expected 2 required fields, got %d", len(schema.Required))
	}
}

// ─── dispatch ────────────────────────────────────────────────────────────────

func TestDispatch_Ping(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ping",
	}

	resp := s.dispatch(context.Background(), "alice", req)

	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.ID != 1 {
		t.Errorf("ID = %v, want 1", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]string)
	if !ok {
		t.Fatalf("result type = %T, want map[string]string", resp.Result)
	}
	if result["status"] != "pong" {
		t.Errorf("status = %q, want %q", result["status"], "pong")
	}
}

func TestDispatch_Initialize(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      "init-1",
		Method:  "initialize",
	}

	resp := s.dispatch(context.Background(), "alice", req)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T, want map[string]any", resp.Result)
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %v, want %q", result["protocolVersion"], "2024-11-05")
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo type = %T", result["serverInfo"])
	}
	if serverInfo["name"] != "gatekeeper-mcp" {
		t.Errorf("server name = %v, want %q", serverInfo["name"], "gatekeeper-mcp")
	}
}

func TestDispatch_UnknownMethod(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      42,
		Method:  "nonexistent/method",
	}

	resp := s.dispatch(context.Background(), "alice", req)

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != codeMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, codeMethodNotFound)
	}
	if !strings.Contains(resp.Error.Message, "nonexistent/method") {
		t.Errorf("error message = %q, expected it to contain method name", resp.Error.Message)
	}
}

// Note: handleToolsCall tests that trigger auditToolCall (permission denied,
// rate limited, success, error) are not tested via dispatch because auditToolCall
// requires a non-nil Ops with a real config.Store (sqlite). Instead, the
// individual methods (isToolAllowed, checkRateLimit, etc.) are tested above,
// and handleToolsCall is tested only for paths that don't call audit (unknown tool,
// invalid params).

func TestDispatch_ToolsCall_UnknownTool(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}

	params, _ := json.Marshal(ToolCallParams{Name: "no_such_tool", Arguments: json.RawMessage(`{}`)})
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	}

	resp := s.dispatch(context.Background(), "alice", req)

	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if resp.Error.Code != codeMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, codeMethodNotFound)
	}
}

func TestDispatch_ToolsCall_InvalidParams(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`not-valid-json`),
	}

	resp := s.dispatch(context.Background(), "alice", req)

	if resp.Error == nil {
		t.Fatal("expected parse error")
	}
	if resp.Error.Code != codeInvalidParams {
		t.Errorf("error code = %d, want %d", resp.Error.Code, codeInvalidParams)
	}
}

// Dispatch tests for rate limiting, approval, success, and error are omitted
// because handleToolsCall always calls auditToolCall, which requires a non-nil
// Ops backed by sqlite. The underlying logic is covered by direct unit tests
// for checkRateLimit, isToolAllowed, categoryRateLimit, etc.

// ─── handleToolsList ─────────────────────────────────────────────────────────

func TestDispatch_ToolsList_FiltersPermissions(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			Permissions: map[string][]string{
				"alice": {"tool_a", "tool_b"},
			},
		},
		tools:   make(map[string]*Tool),
		limiter: newRateLimiter(),
	}
	s.tools["tool_a"] = &Tool{Name: "tool_a", Description: "A", InputSchema: jsonSchema(nil, nil)}
	s.tools["tool_b"] = &Tool{Name: "tool_b", Description: "B", InputSchema: jsonSchema(nil, nil)}
	s.tools["tool_c"] = &Tool{Name: "tool_c", Description: "C", InputSchema: jsonSchema(nil, nil)}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	resp := s.dispatch(context.Background(), "alice", req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", resp.Result)
	}
	tools, ok := result["tools"].([]map[string]any)
	if !ok {
		t.Fatalf("tools type = %T", result["tools"])
	}

	// Alice should only see tool_a and tool_b.
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool["name"].(string)] = true
	}
	if !names["tool_a"] || !names["tool_b"] {
		t.Errorf("expected tool_a and tool_b, got %v", names)
	}
	if names["tool_c"] {
		t.Error("tool_c should not be visible to alice")
	}
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

func TestHandleMessage_MissingSession(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}

	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", body)
	w := httptest.NewRecorder()

	s.handleMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp JSONRPCResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != codeInvalidRequest {
		t.Errorf("expected invalid request error, got %+v", resp.Error)
	}
}

func TestHandleMessage_UnknownSession(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}

	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp/message?session=bogus", body)
	w := httptest.NewRecorder()

	s.handleMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleMessage_InvalidJSON(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}

	// Register a client so the session lookup succeeds.
	s.clients["sess-1"] = &sseClient{
		id:      "sess-1",
		flusher: &noopFlusher{},
		writer:  httptest.NewRecorder(),
		done:    make(chan struct{}),
	}

	body := strings.NewReader(`{this is not valid json}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp/message?session=sess-1", body)
	w := httptest.NewRecorder()

	s.handleMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp JSONRPCResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != codeParseError {
		t.Errorf("expected parse error, got %+v", resp.Error)
	}
}

func TestHandleMessage_DefaultPrincipal(t *testing.T) {
	s := &Server{
		cfg: MCPConfig{
			ReadOnlyRateLimit: 100,
		},
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}

	rec := httptest.NewRecorder()
	s.clients["sess-1"] = &sseClient{
		id:      "sess-1",
		flusher: &noopFlusher{},
		writer:  rec,
		done:    make(chan struct{}),
	}

	// Use the ping RPC method, which doesn't require a tool handler.
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp/message?session=sess-1", body)
	// Do NOT set X-MCP-Principal header; default should be "anonymous".
	w := httptest.NewRecorder()

	s.handleMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp JSONRPCResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Errorf("unexpected error: %+v", resp.Error)
	}
}

// ─── writeJSON ───────────────────────────────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]string{"status": "ok"},
	}

	writeJSON(w, http.StatusOK, resp)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var decoded JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if decoded.JSONRPC != "2.0" {
		t.Errorf("decoded JSONRPC = %q, want %q", decoded.JSONRPC, "2.0")
	}
}

// ─── mcpActorFor ─────────────────────────────────────────────────────────────

func TestMCPActorFor(t *testing.T) {
	actor := mcpActorFor("alice")
	if actor.Source != "mcp" {
		t.Errorf("Source = %q, want %q", actor.Source, "mcp")
	}
	if actor.User != "alice" {
		t.Errorf("User = %q, want %q", actor.User, "alice")
	}
}

// ─── Handler routing ─────────────────────────────────────────────────────────

func TestHandler_RoutesExist(t *testing.T) {
	s := &Server{
		cfg:     MCPConfig{},
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}

	handler := s.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// noopFlusher satisfies http.Flusher for testing.
type noopFlusher struct{}

func (f *noopFlusher) Flush() {}

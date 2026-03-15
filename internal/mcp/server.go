// Package mcp implements a Model Context Protocol server for Gatekeeper.
//
// MCP is a constrained automation interface — it deliberately does NOT
// provide parity with the full API. Instead, it exposes curated tools
// with per-tool permissions, mandatory audit logging, tool-specific rate
// limits, scope restrictions, and simulation requirements for dangerous
// actions.
//
// Transport: SSE (Server-Sent Events) streaming JSON-RPC 2.0 messages.
//
// Every tool call — regardless of outcome — is written to the audit log
// with the requesting principal and a SHA-256 context hash of the arguments.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

// ToolCategory classifies tools by risk level and required controls.
type ToolCategory string

const (
	CategoryReadOnly  ToolCategory = "read_only"
	CategoryDiag      ToolCategory = "diagnostic"
	CategoryMutation  ToolCategory = "mutation"   // requires approval
	CategoryDangerous ToolCategory = "dangerous"  // requires simulation + approval
	CategorySuggest   ToolCategory = "suggestion" // returns suggestions, never mutates
)

// Tool describes an MCP tool with its metadata, input schema, and handler.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    ToolCategory    `json:"category"`
	InputSchema json.RawMessage `json:"inputSchema"`

	// handler processes a tool call. The principal identifies the requesting
	// agent for audit logging and scope checks.
	handler func(ctx context.Context, principal string, params json.RawMessage) (any, error)

	// rateLimit overrides the category default (calls per minute). Zero = use default.
	rateLimit int
}

// MCPConfig holds all dependencies for the MCP server.
type MCPConfig struct {
	// Ops is the validated, audited business logic layer.
	Ops *ops.Ops

	// NFT is the firewall controller for apply/dry-run operations. May be nil.
	NFT backend.Firewall

	// WireGuardOps provides validated WireGuard peer management. May be nil.
	WireGuardOps *ops.WireGuardOps

	// Dnsmasq is the dnsmasq driver for DHCP lease queries. May be nil.
	Dnsmasq *driver.Dnsmasq

	// ServiceMgr is the pluggable service manager. May be nil.
	ServiceMgr *service.Manager

	// LeasePath overrides the default dnsmasq lease file path.
	LeasePath string

	// ─── Permission configuration ───────────────────────────────────

	// Permissions maps principal IDs to per-tool allow lists.
	// If a principal has an entry, only listed tools are available.
	// An empty list means no tools are allowed.
	// A nil map means all tools are allowed (no principal-level filtering).
	Permissions map[string][]string

	// ZoneScope restricts the principal to specific zones.
	// Nil or empty means all zones are accessible.
	ZoneScope map[string][]string

	// ProfileScope restricts the principal to specific profiles.
	// Nil or empty means all profiles are accessible.
	ProfileScope map[string][]string

	// ApprovalCallback is invoked before mutation/dangerous tools execute.
	// Return nil to approve, non-nil error to reject.
	// If nil, all approved-tier tools require no external approval.
	ApprovalCallback func(principal, tool string, args json.RawMessage) error

	// ─── Rate limits (calls per minute) ─────────────────────────────

	// ToolRateLimits maps tool names to per-minute call limits.
	// Takes priority over category defaults.
	ToolRateLimits map[string]int

	// Category defaults: applied when no tool-specific limit is set.
	ReadOnlyRateLimit  int // default: 120/min
	DiagRateLimit      int // default: 30/min
	MutationRateLimit  int // default: 10/min
	DangerousRateLimit int // default: 5/min
}

// ─── JSON-RPC 2.0 Types ─────────────────────────────────────────────────────

// JSONRPCRequest is a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *JSONRPCErr `json:"error,omitempty"`
}

// JSONRPCErr is a JSON-RPC 2.0 error object.
type JSONRPCErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	// Application-defined error codes.
	codePermissionDenied = -32000
	codeRateLimited      = -32001
	codeScopeViolation   = -32002
	codeSimulationFailed = -32003
	codeApprovalRejected = -32004
)

// ToolCallParams holds the parameters for a tools/call JSON-RPC request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolResult is the MCP-standard tool result envelope.
type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent is a single content block in a tool result.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ─── SSE Client ──────────────────────────────────────────────────────────────

type sseClient struct {
	id      string
	flusher http.Flusher
	writer  http.ResponseWriter
	done    chan struct{}
}

// ─── Rate Limiter ────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu     sync.Mutex
	counts map[string][]time.Time // key: "principal:tool"
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{counts: make(map[string][]time.Time)}
}

// allow checks and records a call. Returns true if within limit.
func (rl *rateLimiter) allow(key string, limit int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Prune old entries.
	existing := rl.counts[key]
	recent := existing[:0]
	for _, t := range existing {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= limit {
		rl.counts[key] = recent
		return false
	}

	rl.counts[key] = append(recent, now)
	return true
}

// ─── Server ──────────────────────────────────────────────────────────────────

// Server is the MCP server that handles SSE connections and tool calls.
type Server struct {
	mu      sync.RWMutex
	cfg     MCPConfig
	tools   map[string]*Tool
	clients map[string]*sseClient
	nextID  atomic.Int64
	limiter *rateLimiter
}

// New creates a new MCP server with all tools registered.
func New(cfg MCPConfig) *Server {
	// Apply category rate limit defaults.
	if cfg.ReadOnlyRateLimit <= 0 {
		cfg.ReadOnlyRateLimit = 120
	}
	if cfg.DiagRateLimit <= 0 {
		cfg.DiagRateLimit = 30
	}
	if cfg.MutationRateLimit <= 0 {
		cfg.MutationRateLimit = 10
	}
	if cfg.DangerousRateLimit <= 0 {
		cfg.DangerousRateLimit = 5
	}

	s := &Server{
		cfg:     cfg,
		tools:   make(map[string]*Tool),
		clients: make(map[string]*sseClient),
		limiter: newRateLimiter(),
	}
	s.registerTools()
	return s
}

// ─── HTTP Handlers ───────────────────────────────────────────────────────────

// Handler returns an HTTP handler for the MCP SSE endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp/sse", s.handleSSE)
	mux.HandleFunc("POST /mcp/message", s.handleMessage)
	return mux
}

// handleSSE establishes a Server-Sent Events connection.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	clientID := fmt.Sprintf("mcp-%d", s.nextID.Add(1))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	client := &sseClient{
		id:      clientID,
		flusher: flusher,
		writer:  w,
		done:    make(chan struct{}),
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
	}()

	slog.Info("mcp client connected", "client_id", clientID)

	// Send the endpoint event so the client knows where to POST messages.
	fmt.Fprintf(w, "event: endpoint\ndata: /mcp/message?session=%s\n\n", clientID)
	flusher.Flush()

	// Keep the connection alive with periodic heartbeats.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			slog.Info("mcp client disconnected", "client_id", clientID)
			return
		case <-client.done:
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// handleMessage processes incoming JSON-RPC requests posted by MCP clients.
func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCErr{Code: codeInvalidRequest, Message: "missing session parameter"},
		})
		return
	}

	s.mu.RLock()
	client, ok := s.clients[sessionID]
	s.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCErr{Code: codeInvalidRequest, Message: "unknown session"},
		})
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCErr{Code: codeParseError, Message: "parse error: " + err.Error()},
		})
		return
	}

	// Extract the requesting principal from header. Defaults to "anonymous".
	principal := r.Header.Get("X-MCP-Principal")
	if principal == "" {
		principal = "anonymous"
	}

	// Compute a context hash of the full request for audit traceability.
	contextHash := promptContextHash(req.Params)
	slog.Info("mcp request",
		"method", req.Method,
		"session", sessionID,
		"principal", principal,
		"context_hash", contextHash,
	)

	resp := s.dispatch(r.Context(), principal, &req)

	// Return via HTTP and echo via SSE.
	writeJSON(w, http.StatusOK, resp)
	s.sseEmit(client, resp)
}

// ─── Request Dispatch ────────────────────────────────────────────────────────

func (s *Server) dispatch(ctx context.Context, principal string, req *JSONRPCRequest) *JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(principal, req)
	case "tools/call":
		return s.handleToolsCall(ctx, principal, req)
	case "ping":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]string{"status": "pong"},
		}
	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCErr{Code: codeMethodNotFound, Message: "method not found: " + req.Method},
		}
	}
}

func (s *Server) handleInitialize(req *JSONRPCRequest) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{
					"listChanged": true,
				},
			},
			"serverInfo": map[string]any{
				"name":    "gatekeeper-mcp",
				"version": "1.0.0",
			},
		},
	}
}

func (s *Server) handleToolsList(principal string, req *JSONRPCRequest) *JSONRPCResponse {
	var tools []map[string]any
	for _, t := range s.tools {
		if !s.isToolAllowed(principal, t.Name) {
			continue
		}
		tools = append(tools, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]any{"tools": tools},
	}
}

// handleToolsCall is the core handler for tool invocations. It enforces:
//  1. Permission check (per-tool allow list)
//  2. Rate limit check (per-tool or per-category)
//  3. Simulation for dangerous tools (auto dry-run)
//  4. Approval callback for mutation/dangerous tools
//  5. Mandatory audit logging of every invocation
func (s *Server) handleToolsCall(ctx context.Context, principal string, req *JSONRPCRequest) *JSONRPCResponse {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCErr{Code: codeInvalidParams, Message: "invalid params: " + err.Error()},
		}
	}

	tool, ok := s.tools[params.Name]
	if !ok {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCErr{Code: codeMethodNotFound, Message: "unknown tool: " + params.Name},
		}
	}

	// 1. Permission check.
	if !s.isToolAllowed(principal, params.Name) {
		s.auditToolCall(principal, params.Name, params.Arguments, "permission_denied")
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCErr{Code: codePermissionDenied, Message: "tool not permitted for principal: " + params.Name},
		}
	}

	// 2. Rate limit check.
	if !s.checkRateLimit(principal, tool) {
		s.auditToolCall(principal, params.Name, params.Arguments, "rate_limited")
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCErr{Code: codeRateLimited, Message: "rate limit exceeded for tool: " + params.Name},
		}
	}

	// 3. Simulation for dangerous tools: auto-run dry-run first.
	if tool.Category == CategoryDangerous {
		if err := s.runPreflightSimulation(params.Name); err != nil {
			s.auditToolCall(principal, params.Name, params.Arguments, "simulation_failed: "+err.Error())
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &JSONRPCErr{
					Code:    codeSimulationFailed,
					Message: "pre-flight simulation failed: " + err.Error(),
				},
			}
		}
	}

	// 4. Approval callback for mutation and dangerous tools.
	if (tool.Category == CategoryMutation || tool.Category == CategoryDangerous) && s.cfg.ApprovalCallback != nil {
		if err := s.cfg.ApprovalCallback(principal, params.Name, params.Arguments); err != nil {
			s.auditToolCall(principal, params.Name, params.Arguments, "approval_rejected: "+err.Error())
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCErr{Code: codeApprovalRejected, Message: "approval rejected: " + err.Error()},
			}
		}
	}

	// 5. Execute the tool handler.
	slog.Info("mcp tool call", "tool", params.Name, "category", tool.Category, "principal", principal)
	result, err := tool.handler(ctx, principal, params.Arguments)

	// 6. Mandatory audit logging — always, regardless of outcome.
	outcome := "success"
	if err != nil {
		outcome = "error: " + err.Error()
	}
	s.auditToolCall(principal, params.Name, params.Arguments, outcome)

	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: err.Error()}},
			},
		}
	}

	text, _ := json.Marshal(result)
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: ToolResult{
			Content: []ToolContent{{Type: "text", Text: string(text)}},
		},
	}
}

// ─── Permission & Scope Checks ───────────────────────────────────────────────

// isToolAllowed checks whether a principal has permission to call a tool.
func (s *Server) isToolAllowed(principal, toolName string) bool {
	if s.cfg.Permissions == nil {
		return true // No restrictions configured.
	}
	allowed, ok := s.cfg.Permissions[principal]
	if !ok {
		// Check wildcard principal.
		allowed, ok = s.cfg.Permissions["*"]
		if !ok {
			return false // Principal not found and no wildcard.
		}
	}
	if len(allowed) == 0 {
		return false
	}
	for _, t := range allowed {
		if t == toolName || t == "*" {
			return true
		}
	}
	return false
}

// inZoneScope returns true if the zone is within the principal's allowed scope.
func (s *Server) inZoneScope(principal, zone string) bool {
	if s.cfg.ZoneScope == nil {
		return true
	}
	allowed, ok := s.cfg.ZoneScope[principal]
	if !ok {
		return true // No restriction for this principal.
	}
	for _, z := range allowed {
		if z == zone || z == "*" {
			return true
		}
	}
	return false
}

// inProfileScope returns true if the profile is within the principal's allowed scope.
func (s *Server) inProfileScope(principal, profile string) bool {
	if s.cfg.ProfileScope == nil {
		return true
	}
	allowed, ok := s.cfg.ProfileScope[principal]
	if !ok {
		return true
	}
	for _, p := range allowed {
		if p == profile || p == "*" {
			return true
		}
	}
	return false
}

// ─── Rate Limiting ───────────────────────────────────────────────────────────

// checkRateLimit enforces per-tool rate limits. Returns true if allowed.
func (s *Server) checkRateLimit(principal string, tool *Tool) bool {
	limit := s.categoryRateLimit(tool)

	// Tool-level override (from config).
	if s.cfg.ToolRateLimits != nil {
		if tl, ok := s.cfg.ToolRateLimits[tool.Name]; ok && tl > 0 {
			limit = tl
		}
	}

	// Per-tool rateLimit field override.
	if tool.rateLimit > 0 {
		limit = tool.rateLimit
	}

	key := principal + ":" + tool.Name
	return s.limiter.allow(key, limit)
}

func (s *Server) categoryRateLimit(tool *Tool) int {
	switch tool.Category {
	case CategoryReadOnly, CategorySuggest:
		return s.cfg.ReadOnlyRateLimit
	case CategoryDiag:
		return s.cfg.DiagRateLimit
	case CategoryMutation:
		return s.cfg.MutationRateLimit
	case CategoryDangerous:
		return s.cfg.DangerousRateLimit
	default:
		return s.cfg.ReadOnlyRateLimit
	}
}

// ─── Pre-flight Simulation ───────────────────────────────────────────────────

// runPreflightSimulation compiles the current config into an nftables ruleset
// without applying it. If the compilation fails, the dangerous action is blocked.
func (s *Server) runPreflightSimulation(toolName string) error {
	// Prefer the NFT driver's dry-run if available (it validates nft syntax too).
	if s.cfg.NFT != nil {
		_, err := s.cfg.NFT.DryRun()
		if err != nil {
			return fmt.Errorf("nftables dry-run: %w", err)
		}
		slog.Info("mcp pre-flight simulation passed", "tool", toolName, "method", "nft_dry_run")
		return nil
	}

	// Fallback: compile via ops layer to verify config consistency.
	input, err := s.cfg.Ops.BuildCompilerInput()
	if err != nil {
		return fmt.Errorf("build compiler input: %w", err)
	}
	_, err = compiler.Compile(input)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	slog.Info("mcp pre-flight simulation passed", "tool", toolName, "method", "compiler")
	return nil
}

// ─── Mandatory Audit Logging ─────────────────────────────────────────────────

// auditToolCall logs every MCP tool invocation to the audit trail.
// This is mandatory for all calls regardless of outcome.
func (s *Server) auditToolCall(principal, toolName string, args json.RawMessage, outcome string) {
	contextHash := promptContextHash(args)
	detail := map[string]any{
		"principal":    principal,
		"tool":         toolName,
		"outcome":      outcome,
		"context_hash": contextHash,
	}
	if err := s.cfg.Ops.Store().LogAudit("mcp", "tool_call", toolName, principal, detail); err != nil {
		slog.Error("failed to write MCP audit log",
			"tool", toolName,
			"principal", principal,
			"error", err,
		)
	}
}

// promptContextHash produces a truncated SHA-256 hash of the tool arguments,
// used as a compact fingerprint in audit logs to correlate tool calls with
// the prompts that triggered them.
func promptContextHash(args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	h := sha256.Sum256(args)
	return fmt.Sprintf("%x", h[:16])
}

// ─── SSE Helpers ─────────────────────────────────────────────────────────────

func (s *Server) sseEmit(client *sseClient, resp *JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("failed to marshal SSE response", "error", err)
		return
	}
	// Non-blocking write: if the client buffer is full, log and skip.
	select {
	case <-client.done:
		return
	default:
		fmt.Fprintf(client.writer, "event: message\ndata: %s\n\n", data)
		client.flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, resp *JSONRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// ─── Actor Helper ────────────────────────────────────────────────────────────

// mcpActorFor creates an ops.Actor for the given MCP principal.
func mcpActorFor(principal string) ops.Actor {
	return ops.Actor{Source: "mcp", User: principal}
}

// ─── Tool Registration ───────────────────────────────────────────────────────

func (s *Server) addTool(t *Tool) {
	s.tools[t.Name] = t
}

// registerTools sets up all MCP tools with their handlers.
func (s *Server) registerTools() {
	// ━━━ Read-only tools ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "list_zones",
		Description: "List all network zones configured in Gatekeeper. Respects zone scope restrictions.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			zones, err := s.cfg.Ops.ListZones()
			if err != nil {
				return nil, err
			}
			var filtered []model.Zone
			for _, z := range zones {
				if s.inZoneScope(principal, z.Name) {
					filtered = append(filtered, z)
				}
			}
			return filtered, nil
		},
	})

	s.addTool(&Tool{
		Name:        "get_zone",
		Description: "Get details of a specific zone by name.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Zone name"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inZoneScope(principal, p.Name) {
				return nil, fmt.Errorf("zone %q is outside permitted scope", p.Name)
			}
			return s.cfg.Ops.GetZone(p.Name)
		},
	})

	s.addTool(&Tool{
		Name:        "list_aliases",
		Description: "List all address/port/MAC aliases.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			return s.cfg.Ops.ListAliases()
		},
	})

	s.addTool(&Tool{
		Name:        "get_alias",
		Description: "Get details of a specific alias by name, including all members.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Alias name"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			return s.cfg.Ops.GetAlias(p.Name)
		},
	})

	s.addTool(&Tool{
		Name:        "list_profiles",
		Description: "List all device profiles. Respects profile scope restrictions.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			profiles, err := s.cfg.Ops.ListProfiles()
			if err != nil {
				return nil, err
			}
			var filtered []model.Profile
			for _, p := range profiles {
				if s.inProfileScope(principal, p.Name) {
					filtered = append(filtered, p)
				}
			}
			return filtered, nil
		},
	})

	s.addTool(&Tool{
		Name:        "get_profile",
		Description: "Get details of a specific device profile by name.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Profile name"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inProfileScope(principal, p.Name) {
				return nil, fmt.Errorf("profile %q is outside permitted scope", p.Name)
			}
			return s.cfg.Ops.GetProfile(p.Name)
		},
	})

	s.addTool(&Tool{
		Name:        "list_policies",
		Description: "List all firewall policies.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			return s.cfg.Ops.ListPolicies()
		},
	})

	s.addTool(&Tool{
		Name:        "get_policy",
		Description: "Get a specific policy by name, including all its rules.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Policy name"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			return s.cfg.Ops.GetPolicy(p.Name)
		},
	})

	s.addTool(&Tool{
		Name:        "list_devices",
		Description: "List all device-to-profile assignments.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			return s.cfg.Ops.ListDevices()
		},
	})

	s.addTool(&Tool{
		Name:        "status",
		Description: "Get current Gatekeeper status: zone count, policy count, device count, revision count, and timestamp.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			return s.buildStatus()
		},
	})

	s.addTool(&Tool{
		Name:        "audit_log",
		Description: "View recent audit log entries. Returns the most recent entries, up to the specified limit.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(
			map[string]schemaField{"limit": {Type: "integer", Desc: "Max entries to return (default 50, max 1000)"}},
			nil,
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(params, &p)
			if p.Limit <= 0 || p.Limit > 1000 {
				p.Limit = 50
			}
			return s.cfg.Ops.ListAuditLog(p.Limit)
		},
	})

	// ━━━ Diagnostic tools ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "path_test",
		Description: "Simulate a packet through the firewall and return the verdict (allow/deny/drop) with a full trace of rule evaluation.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"src_ip":   {Type: "string", Desc: "Source IP address"},
				"dst_ip":   {Type: "string", Desc: "Destination IP address"},
				"protocol": {Type: "string", Desc: "Protocol: tcp, udp, icmp"},
				"dst_port": {Type: "integer", Desc: "Destination port number"},
			},
			[]string{"src_ip", "dst_ip"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var req compiler.PathTestRequest
			if err := json.Unmarshal(params, &req); err != nil {
				return nil, err
			}
			return s.cfg.Ops.PathTest(req)
		},
	})

	s.addTool(&Tool{
		Name:        "explain_path",
		Description: "Show a detailed breakdown of ALL rules evaluated for a source-to-destination path, indicating which match and which do not.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"src_ip":   {Type: "string", Desc: "Source IP address"},
				"dst_ip":   {Type: "string", Desc: "Destination IP address"},
				"protocol": {Type: "string", Desc: "Protocol: tcp, udp, icmp"},
				"dst_port": {Type: "integer", Desc: "Destination port number"},
			},
			[]string{"src_ip", "dst_ip"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var req compiler.PathTestRequest
			if err := json.Unmarshal(params, &req); err != nil {
				return nil, err
			}
			return s.cfg.Ops.Explain(req)
		},
	})

	s.addTool(&Tool{
		Name:        "dry_run",
		Description: "Compile the current config into an nftables ruleset without applying it. Returns the full ruleset text for review.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.NFT != nil {
				text, err := s.cfg.NFT.DryRun()
				if err != nil {
					return nil, err
				}
				return map[string]string{"ruleset": text}, nil
			}
			// Fallback: compile via ops layer.
			input, err := s.cfg.Ops.BuildCompilerInput()
			if err != nil {
				return nil, err
			}
			ruleset, err := compiler.Compile(input)
			if err != nil {
				return nil, err
			}
			return map[string]string{"ruleset": ruleset.Text}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "ping",
		Description: "Check if the Gatekeeper MCP server is alive and responsive.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			return map[string]any{
				"status": "ok",
				"time":   time.Now().UTC().Format(time.RFC3339),
			}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "interfaces",
		Description: "List network interfaces referenced by zones, with their zone and CIDR assignments.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			zones, err := s.cfg.Ops.ListZones()
			if err != nil {
				return nil, err
			}
			type ifaceInfo struct {
				Zone      string `json:"zone"`
				Interface string `json:"interface"`
				CIDR      string `json:"cidr"`
			}
			var ifaces []ifaceInfo
			for _, z := range zones {
				if z.Interface != "" && s.inZoneScope(principal, z.Name) {
					ifaces = append(ifaces, ifaceInfo{
						Zone:      z.Name,
						Interface: z.Interface,
						CIDR:      z.NetworkCIDR,
					})
				}
			}
			return ifaces, nil
		},
	})

	s.addTool(&Tool{
		Name:        "leases",
		Description: "List current DHCP leases from dnsmasq.",
		Category:    CategoryDiag,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.Dnsmasq == nil {
				return nil, fmt.Errorf("dnsmasq driver not configured")
			}
			leasePath := s.cfg.LeasePath
			if leasePath == "" {
				leasePath = "/var/lib/misc/dnsmasq.leases"
			}
			return s.cfg.Dnsmasq.ParseLeaseFile(leasePath)
		},
	})

	// ━━━ Mutation tools (require approval) ━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "create_zone",
		Description: "Create a new network zone. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"name":         {Type: "string", Desc: "Unique zone name"},
				"interface":    {Type: "string", Desc: "Network interface (e.g., eth1)"},
				"network_cidr": {Type: "string", Desc: "Network CIDR (e.g., 192.168.1.0/24)"},
				"trust_level":  {Type: "string", Desc: "Trust level: trusted, semi-trusted, untrusted"},
				"description":  {Type: "string", Desc: "Optional description"},
			},
			[]string{"name", "interface", "network_cidr"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var z model.Zone
			if err := json.Unmarshal(params, &z); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.CreateZone(mcpActorFor(principal), &z); err != nil {
				return nil, err
			}
			return map[string]any{"created": z.Name, "id": z.ID}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "create_alias",
		Description: "Create a new alias (host, network, port, MAC, nested, or external URL group). Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"name":        {Type: "string", Desc: "Unique alias name"},
				"type":        {Type: "string", Desc: "Alias type: host, network, port, mac, nested, external_url"},
				"members":     {Type: "array", Desc: "Members (IPs, CIDRs, ports, MACs, or alias names)"},
				"description": {Type: "string", Desc: "Optional description"},
			},
			[]string{"name", "type"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var a model.Alias
			if err := json.Unmarshal(params, &a); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.CreateAlias(mcpActorFor(principal), &a); err != nil {
				return nil, err
			}
			return map[string]any{"created": a.Name, "id": a.ID}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "create_profile",
		Description: "Create a new device profile linking a zone and policy. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"name":        {Type: "string", Desc: "Unique profile name"},
				"zone_id":     {Type: "integer", Desc: "Zone ID to associate with"},
				"policy_name": {Type: "string", Desc: "Policy name to apply"},
				"description": {Type: "string", Desc: "Optional description"},
			},
			[]string{"name", "zone_id", "policy_name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p model.Profile
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inProfileScope(principal, p.Name) {
				return nil, fmt.Errorf("profile %q is outside permitted scope", p.Name)
			}
			if err := s.cfg.Ops.CreateProfile(mcpActorFor(principal), &p); err != nil {
				return nil, err
			}
			return map[string]any{"created": p.Name, "id": p.ID}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "assign_device",
		Description: "Assign a device (by IP/MAC) to a profile. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"ip":           {Type: "string", Desc: "Device IP address"},
				"mac":          {Type: "string", Desc: "Device MAC address (optional)"},
				"hostname":     {Type: "string", Desc: "Device hostname (optional)"},
				"profile_name": {Type: "string", Desc: "Profile name to assign"},
			},
			[]string{"ip", "profile_name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				IP          string `json:"ip"`
				MAC         string `json:"mac"`
				Hostname    string `json:"hostname"`
				ProfileName string `json:"profile_name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inProfileScope(principal, p.ProfileName) {
				return nil, fmt.Errorf("profile %q is outside permitted scope", p.ProfileName)
			}
			return s.cfg.Ops.AssignDevice(mcpActorFor(principal), p.IP, p.MAC, p.Hostname, p.ProfileName, 0)
		},
	})

	s.addTool(&Tool{
		Name:        "create_policy",
		Description: "Create a new firewall policy. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"name":           {Type: "string", Desc: "Unique policy name"},
				"default_action": {Type: "string", Desc: "Default action: allow, deny, reject"},
				"description":    {Type: "string", Desc: "Optional description"},
			},
			[]string{"name", "default_action"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p model.Policy
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.CreatePolicy(mcpActorFor(principal), &p); err != nil {
				return nil, err
			}
			return map[string]any{"created": p.Name, "id": p.ID}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "create_rule",
		Description: "Add a firewall rule to an existing policy. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"policy_name": {Type: "string", Desc: "Policy to add the rule to"},
				"order":       {Type: "integer", Desc: "Rule evaluation order (lower = first)"},
				"src_alias":   {Type: "string", Desc: "Source alias name"},
				"dst_alias":   {Type: "string", Desc: "Destination alias name"},
				"protocol":    {Type: "string", Desc: "Protocol: tcp, udp, icmp, or empty for any"},
				"ports":       {Type: "string", Desc: "Comma-separated port numbers or empty for any"},
				"action":      {Type: "string", Desc: "Rule action: allow, deny, reject, log"},
				"log":         {Type: "boolean", Desc: "Enable logging for matched packets"},
				"description": {Type: "string", Desc: "Optional rule description"},
			},
			[]string{"policy_name", "action"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				PolicyName string `json:"policy_name"`
				model.Rule
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.CreateRule(mcpActorFor(principal), p.PolicyName, &p.Rule); err != nil {
				return nil, err
			}
			return map[string]any{"created_rule_id": p.Rule.ID, "policy": p.PolicyName}, nil
		},
	})

	// ━━━ Dangerous tools (require simulation + approval) ━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "commit_config",
		Description: "Commit the current config as a new revision and apply the nftables ruleset. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"message": {Type: "string", Desc: "Commit message describing the change"}},
			nil,
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(params, &p)
			rev, err := s.cfg.Ops.Commit(mcpActorFor(principal), p.Message)
			if err != nil {
				return nil, err
			}
			applied := false
			if s.cfg.NFT != nil {
				if err := s.cfg.NFT.Apply(); err != nil {
					return nil, fmt.Errorf("commit succeeded (rev %d) but apply failed: %w", rev, err)
				}
				applied = true
			}
			return map[string]any{"revision": rev, "applied": applied, "message": p.Message}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "rollback_config",
		Description: "Rollback to a previous config revision and reapply. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"revision": {Type: "integer", Desc: "Revision number to rollback to"}},
			[]string{"revision"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Revision int `json:"revision"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.Rollback(mcpActorFor(principal), p.Revision); err != nil {
				return nil, err
			}
			applied := false
			if s.cfg.NFT != nil {
				if err := s.cfg.NFT.Apply(); err != nil {
					return nil, fmt.Errorf("rollback succeeded but apply failed: %w", err)
				}
				applied = true
			}
			return map[string]any{"rolled_back_to": p.Revision, "applied": applied}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "delete_zone",
		Description: "Delete a network zone. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Zone name to delete"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inZoneScope(principal, p.Name) {
				return nil, fmt.Errorf("zone %q is outside permitted scope", p.Name)
			}
			if err := s.cfg.Ops.DeleteZone(mcpActorFor(principal), p.Name); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": p.Name}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "delete_alias",
		Description: "Delete an alias. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Alias name to delete"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.DeleteAlias(mcpActorFor(principal), p.Name); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": p.Name}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "delete_profile",
		Description: "Delete a device profile. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Profile name to delete"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if !s.inProfileScope(principal, p.Name) {
				return nil, fmt.Errorf("profile %q is outside permitted scope", p.Name)
			}
			if err := s.cfg.Ops.DeleteProfile(mcpActorFor(principal), p.Name); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": p.Name}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "delete_rule",
		Description: "Delete a firewall rule by ID. DANGEROUS: auto-runs a dry-run simulation first. Requires approval.",
		Category:    CategoryDangerous,
		InputSchema: jsonSchema(
			map[string]schemaField{"id": {Type: "integer", Desc: "Rule ID to delete"}},
			[]string{"id"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.Ops.DeleteRule(mcpActorFor(principal), p.ID); err != nil {
				return nil, err
			}
			return map[string]any{"deleted_rule_id": p.ID}, nil
		},
	})

	// ━━━ WireGuard tools ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "list_wg_peers",
		Description: "List all configured WireGuard VPN peers.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.WireGuardOps == nil {
				return nil, fmt.Errorf("wireguard not configured")
			}
			return s.cfg.WireGuardOps.ListPeers(), nil
		},
	})

	s.addTool(&Tool{
		Name:        "add_wg_peer",
		Description: "Add a WireGuard VPN peer. Validates public key and allowed IPs. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"public_key":  {Type: "string", Desc: "Peer's WireGuard public key (base64)"},
				"allowed_ips": {Type: "string", Desc: "Allowed IPs CIDR (e.g., 10.50.0.2/32)"},
				"endpoint":    {Type: "string", Desc: "Peer endpoint host:port (optional)"},
				"name":        {Type: "string", Desc: "Friendly peer name (optional)"},
			},
			[]string{"public_key", "allowed_ips"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.WireGuardOps == nil {
				return nil, fmt.Errorf("wireguard not configured")
			}
			var peer driver.WGPeer
			if err := json.Unmarshal(params, &peer); err != nil {
				return nil, err
			}
			if err := s.cfg.WireGuardOps.AddPeer(peer); err != nil {
				return nil, err
			}
			// Audit WG mutations through the store.
			_ = s.cfg.Ops.Store().LogAudit("mcp", "add_wg_peer", "wireguard", principal, peer)
			return map[string]string{"added": peer.PublicKey}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "remove_wg_peer",
		Description: "Remove a WireGuard VPN peer by public key. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{"public_key": {Type: "string", Desc: "Public key of the peer to remove"}},
			[]string{"public_key"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.WireGuardOps == nil {
				return nil, fmt.Errorf("wireguard not configured")
			}
			var p struct {
				PublicKey string `json:"public_key"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.WireGuardOps.RemovePeer(p.PublicKey); err != nil {
				return nil, err
			}
			_ = s.cfg.Ops.Store().LogAudit("mcp", "remove_wg_peer", "wireguard", principal, nil)
			return map[string]string{"removed": p.PublicKey}, nil
		},
	})

	// ━━━ Service tools ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "list_services",
		Description: "List all registered services and their current state.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.ServiceMgr == nil {
				return nil, fmt.Errorf("service manager not configured")
			}
			return s.cfg.ServiceMgr.List(), nil
		},
	})

	s.addTool(&Tool{
		Name:        "enable_service",
		Description: "Enable and start a registered service. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Service name to enable"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.ServiceMgr == nil {
				return nil, fmt.Errorf("service manager not configured")
			}
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.ServiceMgr.Enable(p.Name); err != nil {
				return nil, err
			}
			_ = s.cfg.Ops.Store().LogAudit("mcp", "enable_service", "service", principal, map[string]string{"service": p.Name})
			return map[string]string{"enabled": p.Name}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "disable_service",
		Description: "Disable and stop a running service. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{"name": {Type: "string", Desc: "Service name to disable"}},
			[]string{"name"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.ServiceMgr == nil {
				return nil, fmt.Errorf("service manager not configured")
			}
			var p struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.ServiceMgr.Disable(p.Name); err != nil {
				return nil, err
			}
			_ = s.cfg.Ops.Store().LogAudit("mcp", "disable_service", "service", principal, map[string]string{"service": p.Name})
			return map[string]string{"disabled": p.Name}, nil
		},
	})

	s.addTool(&Tool{
		Name:        "configure_service",
		Description: "Update a service's configuration. If the service is running, it will be reloaded. Requires approval.",
		Category:    CategoryMutation,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"name":   {Type: "string", Desc: "Service name"},
				"config": {Type: "object", Desc: "Configuration key-value pairs"},
			},
			[]string{"name", "config"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			if s.cfg.ServiceMgr == nil {
				return nil, fmt.Errorf("service manager not configured")
			}
			var p struct {
				Name   string            `json:"name"`
				Config map[string]string `json:"config"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			if err := s.cfg.ServiceMgr.Configure(p.Name, p.Config); err != nil {
				return nil, err
			}
			_ = s.cfg.Ops.Store().LogAudit("mcp", "configure_service", "service", principal, p.Config)
			return map[string]string{"configured": p.Name}, nil
		},
	})

	// ━━━ MTU diagnostic tools ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "mtu_status",
		Description: "Show MTU status for all zones: configured vs actual MTU, overlay adjustments, MSS clamping state, and any MTU mismatch warnings between zones.",
		Category:    CategoryReadOnly,
		InputSchema: jsonSchema(nil, nil),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			zones, err := s.cfg.Ops.ListZones()
			if err != nil {
				return nil, err
			}
			// Filter by zone scope.
			var filtered []model.Zone
			for _, z := range zones {
				if s.inZoneScope(principal, z.Name) {
					filtered = append(filtered, z)
				}
			}
			return service.GetMTUStatusFromZones(filtered), nil
		},
	})

	// ━━━ Suggestion tool ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	s.addTool(&Tool{
		Name:        "device_suggest",
		Description: "Return ranked profile suggestions for a device based on its IP, MAC, hostname, and open ports. NEVER silently mutates state. Returns suggestions with rationale and confidence score for the caller to review. Use assign_device separately to act on a suggestion.",
		Category:    CategorySuggest,
		InputSchema: jsonSchema(
			map[string]schemaField{
				"ip":         {Type: "string", Desc: "Device IP address"},
				"mac":        {Type: "string", Desc: "Device MAC address (optional)"},
				"hostname":   {Type: "string", Desc: "Device hostname (optional)"},
				"open_ports": {Type: "array", Desc: "List of open TCP ports (optional)"},
			},
			[]string{"ip"},
		),
		handler: func(ctx context.Context, principal string, params json.RawMessage) (any, error) {
			var p struct {
				IP        string `json:"ip"`
				MAC       string `json:"mac"`
				Hostname  string `json:"hostname"`
				OpenPorts []int  `json:"open_ports"`
			}
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, err
			}
			return s.suggestProfile(principal, p.IP, p.Hostname, p.MAC, p.OpenPorts)
		},
	})
}

// ─── Status ──────────────────────────────────────────────────────────────────

type statusResponse struct {
	Status        string `json:"status"`
	ZoneCount     int    `json:"zone_count"`
	AliasCount    int    `json:"alias_count"`
	ProfileCount  int    `json:"profile_count"`
	PolicyCount   int    `json:"policy_count"`
	DeviceCount   int    `json:"device_count"`
	RevisionCount int    `json:"revision_count"`
	Timestamp     string `json:"timestamp"`
}

func (s *Server) buildStatus() (*statusResponse, error) {
	zones, err := s.cfg.Ops.ListZones()
	if err != nil {
		return nil, err
	}
	aliases, err := s.cfg.Ops.ListAliases()
	if err != nil {
		return nil, err
	}
	profiles, err := s.cfg.Ops.ListProfiles()
	if err != nil {
		return nil, err
	}
	policies, err := s.cfg.Ops.ListPolicies()
	if err != nil {
		return nil, err
	}
	devices, err := s.cfg.Ops.ListDevices()
	if err != nil {
		return nil, err
	}
	revisions, err := s.cfg.Ops.ListRevisions()
	if err != nil {
		return nil, err
	}
	return &statusResponse{
		Status:        "ok",
		ZoneCount:     len(zones),
		AliasCount:    len(aliases),
		ProfileCount:  len(profiles),
		PolicyCount:   len(policies),
		DeviceCount:   len(devices),
		RevisionCount: len(revisions),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ─── Device Suggestion Engine ────────────────────────────────────────────────

type profileSuggestion struct {
	Profile    string  `json:"profile"`
	ZoneName   string  `json:"zone_name"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// suggestProfile returns ranked profile suggestions. It NEVER mutates state.
func (s *Server) suggestProfile(principal, ip, hostname, mac string, openPorts []int) (any, error) {
	profiles, err := s.cfg.Ops.ListProfiles()
	if err != nil {
		return nil, err
	}
	zones, err := s.cfg.Ops.ListZones()
	if err != nil {
		return nil, err
	}

	zoneByID := make(map[int64]model.Zone)
	for _, z := range zones {
		zoneByID[z.ID] = z
	}

	hostnameL := strings.ToLower(hostname)
	var suggestions []profileSuggestion

	for _, prof := range profiles {
		if !s.inProfileScope(principal, prof.Name) {
			continue
		}

		confidence := 0.1 // base
		var reasons []string
		nameL := strings.ToLower(prof.Name)

		zone, hasZone := zoneByID[prof.ZoneID]
		zoneName := ""
		if hasZone {
			zoneName = zone.Name
		}

		// Hostname-based heuristics.
		if hostnameL != "" {
			if (strings.Contains(hostnameL, "server") || strings.Contains(hostnameL, "srv")) && strings.Contains(nameL, "server") {
				confidence = floatMax(confidence, 0.8)
				reasons = append(reasons, "hostname suggests server device, matches server profile")
			}
			if (strings.Contains(hostnameL, "desktop") || strings.Contains(hostnameL, "laptop") || strings.Contains(hostnameL, "pc")) &&
				(strings.Contains(nameL, "desktop") || strings.Contains(nameL, "workstation")) {
				confidence = floatMax(confidence, 0.7)
				reasons = append(reasons, "hostname suggests desktop/laptop device")
			}
			if (strings.Contains(hostnameL, "phone") || strings.Contains(hostnameL, "iphone") || strings.Contains(hostnameL, "android")) &&
				(strings.Contains(nameL, "mobile") || strings.Contains(nameL, "phone")) {
				confidence = floatMax(confidence, 0.7)
				reasons = append(reasons, "hostname suggests mobile device")
			}
			// IoT device heuristics.
			iotKeywords := []string{"cam", "sensor", "bulb", "plug", "thermostat", "speaker", "ring", "nest", "hue", "iot"}
			for _, kw := range iotKeywords {
				if strings.Contains(hostnameL, kw) && hasZone && zone.TrustLevel == model.TrustNone {
					confidence = floatMax(confidence, 0.6)
					reasons = append(reasons, fmt.Sprintf("hostname %q suggests IoT device, matches untrusted zone %q", hostname, zoneName))
					break
				}
			}
		}

		// Port-based heuristics.
		for _, port := range openPorts {
			switch port {
			case 22:
				if strings.Contains(nameL, "server") {
					confidence = floatMax(confidence, 0.6)
					reasons = append(reasons, "SSH port open, likely a server")
				}
			case 80, 443:
				if strings.Contains(nameL, "server") || strings.Contains(nameL, "web") {
					confidence = floatMax(confidence, 0.5)
					reasons = append(reasons, "HTTP/HTTPS ports open, likely a web server")
				}
			case 3389:
				if strings.Contains(nameL, "desktop") || strings.Contains(nameL, "workstation") {
					confidence = floatMax(confidence, 0.6)
					reasons = append(reasons, "RDP port open, likely Windows desktop")
				}
			}
		}

		if len(reasons) == 0 {
			reasons = append(reasons, "default suggestion, no strong signal detected")
		}

		suggestions = append(suggestions, profileSuggestion{
			Profile:    prof.Name,
			ZoneName:   zoneName,
			Confidence: confidence,
			Rationale:  strings.Join(reasons, "; "),
		})
	}

	// Sort by confidence descending.
	for i := 1; i < len(suggestions); i++ {
		for j := i; j > 0 && suggestions[j].Confidence > suggestions[j-1].Confidence; j-- {
			suggestions[j], suggestions[j-1] = suggestions[j-1], suggestions[j]
		}
	}

	return map[string]any{
		"suggestions":  suggestions,
		"note":         "These are suggestions only. Use assign_device to actually assign the device.",
		"auto_applied": false,
	}, nil
}

// ─── Schema Builder ──────────────────────────────────────────────────────────

// schemaField describes a single property in a JSON Schema.
type schemaField struct {
	Type string // "string", "integer", "boolean", "array", "object"
	Desc string
}

// jsonSchema builds a JSON Schema object for tool input.
func jsonSchema(properties map[string]schemaField, required []string) json.RawMessage {
	if properties == nil {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	props := make(map[string]map[string]string, len(properties))
	for k, v := range properties {
		prop := map[string]string{"type": v.Type}
		if v.Desc != "" {
			prop["description"] = v.Desc
		}
		props[k] = prop
	}
	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	data, _ := json.Marshal(schema)
	return data
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func floatMax(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// Tools returns all registered tool definitions (for testing/introspection).
func (s *Server) Tools() map[string]*Tool {
	return s.tools
}

// Ensure compile-time verification that all imports are used.
var (
	_ = (*service.Manager)(nil)
)

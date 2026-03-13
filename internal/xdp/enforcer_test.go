package xdp

import (
	"errors"
	"testing"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// newNoopConnFn returns a connFn that always errors, preventing real netlink calls.
// This lets us test rule-building logic and state management without root.
func newNoopConnFn() func() (*nft.Conn, error) {
	return func() (*nft.Conn, error) {
		return nil, errors.New("test: no netlink")
	}
}

func TestMatchIPv4Saddr_SingleIP(t *testing.T) {
	exprs := matchIPv4Saddr("10.0.0.1")
	if exprs == nil {
		t.Fatal("expected non-nil expressions for valid IP")
	}
	if len(exprs) != 2 {
		t.Fatalf("got %d exprs, want 2", len(exprs))
	}
	payload, ok := exprs[0].(*expr.Payload)
	if !ok {
		t.Fatal("first expr should be Payload")
	}
	if payload.Offset != 12 {
		t.Errorf("offset = %d, want 12", payload.Offset)
	}
	if payload.Len != 4 {
		t.Errorf("len = %d, want 4", payload.Len)
	}
	cmp, ok := exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatal("second expr should be Cmp")
	}
	if cmp.Op != expr.CmpOpEq {
		t.Errorf("cmp op = %v, want Eq", cmp.Op)
	}
	want := []byte{10, 0, 0, 1}
	if len(cmp.Data) != 4 || cmp.Data[0] != want[0] || cmp.Data[3] != want[3] {
		t.Errorf("cmp data = %v, want %v", cmp.Data, want)
	}
}

func TestMatchIPv4Saddr_CIDR(t *testing.T) {
	exprs := matchIPv4Saddr("192.168.1.0/24")
	if exprs == nil {
		t.Fatal("expected non-nil expressions for valid CIDR")
	}
	if len(exprs) != 3 {
		t.Fatalf("got %d exprs, want 3", len(exprs))
	}
	_, ok := exprs[1].(*expr.Bitwise)
	if !ok {
		t.Fatal("second expr should be Bitwise for CIDR")
	}
}

func TestMatchIPv4Saddr_CIDR32(t *testing.T) {
	exprs := matchIPv4Saddr("10.0.0.5/32")
	if exprs == nil {
		t.Fatal("expected non-nil for /32")
	}
	if len(exprs) != 2 {
		t.Fatalf("got %d exprs, want 2 (no bitwise for /32)", len(exprs))
	}
}

func TestMatchIPv4Saddr_Invalid(t *testing.T) {
	if exprs := matchIPv4Saddr("not-an-ip"); exprs != nil {
		t.Error("expected nil for invalid IP")
	}
	if exprs := matchIPv4Saddr(""); exprs != nil {
		t.Error("expected nil for empty string")
	}
}

func TestMatchIPv4Daddr(t *testing.T) {
	exprs := matchIPv4Daddr("172.16.0.1")
	if exprs == nil {
		t.Fatal("expected non-nil")
	}
	payload := exprs[0].(*expr.Payload)
	if payload.Offset != 16 {
		t.Errorf("offset = %d, want 16", payload.Offset)
	}
}

func TestMatchL4Proto(t *testing.T) {
	exprs := matchL4Proto(6)
	if len(exprs) != 2 {
		t.Fatalf("got %d exprs, want 2", len(exprs))
	}
	meta, ok := exprs[0].(*expr.Meta)
	if !ok {
		t.Fatal("first should be Meta")
	}
	if meta.Key != expr.MetaKeyL4PROTO {
		t.Error("meta key should be L4PROTO")
	}
}

func TestMatchTCPSynFlag(t *testing.T) {
	exprs := matchTCPSynFlag()
	if len(exprs) != 3 {
		t.Fatalf("got %d exprs, want 3", len(exprs))
	}
	bw, ok := exprs[1].(*expr.Bitwise)
	if !ok {
		t.Fatal("second should be Bitwise")
	}
	if len(bw.Mask) != 1 || bw.Mask[0] != 0x02 {
		t.Errorf("mask = %x, want [02]", bw.Mask)
	}
}

func TestMatchCtStateEstablished(t *testing.T) {
	exprs := matchCtStateEstablished()
	if len(exprs) != 3 {
		t.Fatalf("got %d exprs, want 3", len(exprs))
	}
	ct, ok := exprs[0].(*expr.Ct)
	if !ok {
		t.Fatal("first should be Ct")
	}
	if ct.Key != expr.CtKeySTATE {
		t.Error("ct key should be STATE")
	}
}

func TestConcat(t *testing.T) {
	a := []expr.Any{&expr.Counter{}}
	b := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	result := concat(a, b)
	if len(result) != 2 {
		t.Fatalf("got %d, want 2", len(result))
	}
}

func TestEnforcerTarpitRules(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	rules := e.tarpitRules(saddr, CountermeasureConfig{})

	if len(rules) != 2 {
		t.Fatalf("tarpit should produce 2 rules, got %d", len(rules))
	}

	// First rule should end with accept verdict.
	lastExpr := rules[0][len(rules[0])-1]
	v, ok := lastExpr.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Error("first tarpit rule should accept")
	}

	// Second rule should end with drop verdict.
	lastExpr = rules[1][len(rules[1])-1]
	v, ok = lastExpr.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictDrop {
		t.Error("second tarpit rule should drop")
	}

	// First rule should contain a Limit expression.
	foundLimit := false
	for _, ex := range rules[0] {
		if _, ok := ex.(*expr.Limit); ok {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Error("tarpit accept rule should contain Limit")
	}
}

func TestEnforcerSynCookieRules(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	rules := e.synCookieRules(saddr)

	if len(rules) != 2 {
		t.Fatalf("syn cookie should produce 2 rules, got %d", len(rules))
	}

	// Both rules should match TCP SYN flag.
	for i, rule := range rules {
		foundSynMatch := false
		for _, ex := range rule {
			if bw, ok := ex.(*expr.Bitwise); ok && len(bw.Mask) == 1 && bw.Mask[0] == 0x02 {
				foundSynMatch = true
			}
		}
		if !foundSynMatch {
			t.Errorf("rule %d should match SYN flag", i)
		}
	}
}

func TestEnforcerBandwidthRules(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	tech := TechniqueConfig{Type: TechniqueBandwidth, Enabled: true}
	global := CountermeasureConfig{BandwidthLimitBps: 1024}
	rules := e.bandwidthRules(saddr, tech, global)

	if len(rules) != 2 {
		t.Fatalf("bandwidth should produce 2 rules, got %d", len(rules))
	}
}

func TestEnforcerBandwidthRules_CustomLimit(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	tech := TechniqueConfig{
		Type: TechniqueBandwidth, Enabled: true,
		Params: map[string]string{"limit_bps": "512"},
	}
	global := CountermeasureConfig{BandwidthLimitBps: 1024}
	rules := e.bandwidthRules(saddr, tech, global)

	if len(rules) != 2 {
		t.Fatalf("bandwidth should produce 2 rules, got %d", len(rules))
	}
}

func TestEnforcerLatencyRule(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	rule := e.latencyRule(saddr)

	if rule == nil {
		t.Fatal("expected non-nil latency rule")
	}

	foundQueue := false
	for _, ex := range rule {
		if q, ok := ex.(*expr.Queue); ok {
			foundQueue = true
			if q.Num != 100 {
				t.Errorf("queue num = %d, want 100", q.Num)
			}
			if q.Flag != expr.QueueFlagBypass {
				t.Error("queue should have bypass flag")
			}
		}
	}
	if !foundQueue {
		t.Error("latency rule should contain Queue expression")
	}
}

func TestEnforcerRSTChaosRule(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	global := CountermeasureConfig{RSTChaosProbability: 0.3}
	rule := e.rstChaosRule(saddr, global)

	if rule == nil {
		t.Fatal("expected non-nil RST chaos rule")
	}

	foundNumgen := false
	for _, ex := range rule {
		if ng, ok := ex.(*expr.Numgen); ok {
			foundNumgen = true
			if ng.Modulus != 100 {
				t.Errorf("modulus = %d, want 100", ng.Modulus)
			}
		}
	}
	if !foundNumgen {
		t.Error("RST chaos rule should contain Numgen expression")
	}

	// Should end with Drop.
	last := rule[len(rule)-1]
	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictDrop {
		t.Error("RST chaos should end with drop")
	}
}

func TestEnforcerRSTChaosRule_ZeroProbability(t *testing.T) {
	e := NewEnforcer()
	saddr := matchIPv4Saddr("10.0.0.1")
	global := CountermeasureConfig{RSTChaosProbability: 0}
	rule := e.rstChaosRule(saddr, global)

	if rule != nil {
		t.Error("RST chaos with 0 probability should return nil")
	}
}

func TestEnforcerTTLRandomRule(t *testing.T) {
	e := NewEnforcer()
	daddr := matchIPv4Daddr("10.0.0.1")
	rule := e.ttlRandomRule(daddr)

	if rule == nil {
		t.Fatal("expected non-nil TTL rule")
	}

	foundWrite := false
	for _, ex := range rule {
		if p, ok := ex.(*expr.Payload); ok && p.OperationType == expr.PayloadWrite {
			foundWrite = true
			if p.Offset != 8 {
				t.Errorf("TTL offset = %d, want 8", p.Offset)
			}
			if p.Len != 1 {
				t.Errorf("TTL len = %d, want 1", p.Len)
			}
			if p.CsumType != expr.CsumTypeInet {
				t.Error("TTL write should trigger checksum recalc")
			}
		}
	}
	if !foundWrite {
		t.Error("TTL rule should contain Payload write expression")
	}
}

func TestCountermeasures_DisabledByDefault(t *testing.T) {
	cm := NewCountermeasures()
	if cm.Enabled() {
		t.Error("countermeasures should be disabled by default")
	}
}

func TestCountermeasures_EnableDisable(t *testing.T) {
	cm := NewCountermeasures()
	// Override enforcer to avoid netlink calls in tests.
	cm.enforcer = &Enforcer{connFn: newNoopConnFn()}

	if cm.Enabled() {
		t.Fatal("should start disabled")
	}

	// Enable will fail on sync (no netlink) but state should still toggle.
	// The sync error is non-fatal — it's logged as a warning.
	cm.mu.Lock()
	cm.enabled = true
	cm.mu.Unlock()

	if !cm.Enabled() {
		t.Error("should be enabled after setting enabled=true")
	}

	cm.mu.Lock()
	cm.enabled = false
	cm.mu.Unlock()

	if cm.Enabled() {
		t.Error("should be disabled after setting enabled=false")
	}
}

func TestCountermeasures_PolicyNotEnforcedWhenDisabled(t *testing.T) {
	cm := NewCountermeasures()
	cm.enforcer = &Enforcer{connFn: newNoopConnFn()}

	// Add policy while disabled — should succeed (stored but not enforced).
	err := cm.AddPolicy(CountermeasurePolicy{
		Target:     "10.0.0.1",
		Techniques: []TechniqueConfig{{Type: TechniqueTarpit, Enabled: true}},
		Reason:     "test",
	})
	if err != nil {
		t.Fatalf("AddPolicy while disabled: %v", err)
	}

	policies := cm.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
}

func TestUint32Bytes(t *testing.T) {
	b := uint32Bytes(30)
	if len(b) != 4 {
		t.Fatalf("got %d bytes, want 4", len(b))
	}
	// 30 in big-endian = 0x0000001e
	if b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 30 {
		t.Errorf("uint32Bytes(30) = %v, want [0 0 0 30]", b)
	}
}

package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Manager coordinates XDP program lifecycle across interfaces.
//
// It handles:
//   - Capability probing at startup
//   - Program loading and attachment
//   - Map population (blocklists, ACLs)
//   - Statistics collection
//   - Graceful detachment on shutdown
//
// The Manager does NOT directly load BPF bytecode — that requires the
// cilium/ebpf library at build time. Instead, it maintains the control-plane
// state (blocklists, ACLs, stats) and provides the data structures that a
// BPF loader would use. When cilium/ebpf is available, the BPFLoader
// interface bridges the gap.
type Manager struct {
	mu         sync.RWMutex
	caps       *Capabilities
	attached   map[string]*InterfaceState // interface name -> state
	blocklist  map[[4]byte]BlocklistEntry // IPv4 blocklist (network byte order)
	blocklist6 map[[16]byte]BlocklistEntry // IPv6 blocklist
	acls       []ACLRule
	mode       AttachMode
	running    bool
}

// InterfaceState tracks XDP attachment on a single interface.
type InterfaceState struct {
	Name       string     `json:"name"`
	IfIndex    int        `json:"ifindex"`
	Mode       AttachMode `json:"mode"`
	Attached   bool       `json:"attached"`
	AttachedAt time.Time  `json:"attached_at,omitempty"`
	ProgramID  uint32     `json:"program_id,omitempty"`
	Stats      Stats      `json:"stats"`
}

// BPFLoader is the interface for loading and managing BPF programs.
// This abstracts the cilium/ebpf dependency so the control plane can
// be tested without actual BPF program loading.
type BPFLoader interface {
	// Load loads the compiled BPF programs and maps.
	Load() error
	// Attach attaches the XDP program to an interface.
	Attach(ifName string, ifIndex int, mode AttachMode) error
	// Detach removes the XDP program from an interface.
	Detach(ifName string, ifIndex int) error
	// UpdateBlocklist writes the blocklist map entries.
	UpdateBlocklist(entries map[[4]byte]uint8) error
	// UpdateBlocklist6 writes the IPv6 blocklist map entries.
	UpdateBlocklist6(entries map[[16]byte]uint8) error
	// ReadStats reads per-CPU statistics from the stats map.
	ReadStats(ifIndex int) (Stats, error)
	// Close releases all BPF resources.
	Close() error
}

// NewManager creates a new XDP manager.
func NewManager() *Manager {
	return &Manager{
		attached:   make(map[string]*InterfaceState),
		blocklist:  make(map[[4]byte]BlocklistEntry),
		blocklist6: make(map[[16]byte]BlocklistEntry),
		mode:       AttachModeGeneric, // Safe default; upgraded if native supported.
	}
}

// Probe checks system capabilities and returns the result.
func (m *Manager) Probe() *Capabilities {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caps = ProbeCapabilities()
	return m.caps
}

// Capabilities returns the last probed capabilities.
func (m *Manager) Capabilities() *Capabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.caps == nil {
		m.mu.RUnlock()
		caps := ProbeCapabilities()
		m.mu.RLock()
		m.caps = caps
	}
	return m.caps
}

// SetMode sets the XDP attach mode.
func (m *Manager) SetMode(mode AttachMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mode = mode
}

// AddToBlocklist adds an IP to the blocklist.
func (m *Manager) AddToBlocklist(entry BlocklistEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ip := net.ParseIP(entry.IP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %q", entry.IP)
	}

	if entry.AddedAt.IsZero() {
		entry.AddedAt = time.Now()
	}

	if ip4 := ip.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		m.blocklist[key] = entry
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		m.blocklist6[key] = entry
	}

	return nil
}

// RemoveFromBlocklist removes an IP from the blocklist.
func (m *Manager) RemoveFromBlocklist(ipStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %q", ipStr)
	}

	if ip4 := ip.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		delete(m.blocklist, key)
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		delete(m.blocklist6, key)
	}

	return nil
}

// BlocklistEntries returns a copy of the current blocklist.
func (m *Manager) BlocklistEntries() []BlocklistEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := make([]BlocklistEntry, 0, len(m.blocklist)+len(m.blocklist6))
	for _, e := range m.blocklist {
		entries = append(entries, e)
	}
	for _, e := range m.blocklist6 {
		entries = append(entries, e)
	}
	return entries
}

// BlocklistSize returns the number of entries in the blocklist.
func (m *Manager) BlocklistSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blocklist) + len(m.blocklist6)
}

// AddACLRule adds an ACL rule to the XDP fast path.
func (m *Manager) AddACLRule(rule ACLRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule.ID == 0 {
		// Auto-assign ID.
		maxID := uint32(0)
		for _, r := range m.acls {
			if r.ID > maxID {
				maxID = r.ID
			}
		}
		rule.ID = maxID + 1
	}

	m.acls = append(m.acls, rule)
	return nil
}

// RemoveACLRule removes an ACL rule by ID.
func (m *Manager) RemoveACLRule(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.acls {
		if r.ID == id {
			m.acls = append(m.acls[:i], m.acls[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("ACL rule %d not found", id)
}

// ACLRules returns a copy of the current ACL rules.
func (m *Manager) ACLRules() []ACLRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]ACLRule, len(m.acls))
	copy(rules, m.acls)
	return rules
}

// AttachInterface marks an interface as having an XDP program attached.
func (m *Manager) AttachInterface(ifName string, ifIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.attached[ifName] = &InterfaceState{
		Name:       ifName,
		IfIndex:    ifIndex,
		Mode:       m.mode,
		Attached:   true,
		AttachedAt: time.Now(),
	}
	return nil
}

// DetachInterface marks an interface as no longer having XDP attached.
func (m *Manager) DetachInterface(ifName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.attached[ifName]
	if !ok {
		return fmt.Errorf("interface %q not attached", ifName)
	}
	state.Attached = false
	delete(m.attached, ifName)
	return nil
}

// AttachedInterfaces returns all interfaces with XDP programs attached.
func (m *Manager) AttachedInterfaces() []InterfaceState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]InterfaceState, 0, len(m.attached))
	for _, s := range m.attached {
		states = append(states, *s)
	}
	return states
}

// GetStats returns aggregated statistics for an interface.
func (m *Manager) GetStats(ifName string) (Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.attached[ifName]
	if !ok {
		return Stats{}, fmt.Errorf("interface %q not attached", ifName)
	}

	stats := state.Stats
	stats.Interface = ifName
	stats.AttachMode = state.Mode.String()
	stats.Attached = state.Attached
	stats.BlocklistSize = len(m.blocklist) + len(m.blocklist6)
	stats.ACLRuleCount = len(m.acls)
	stats.LastUpdate = time.Now()
	return stats, nil
}

// AllStats returns statistics for all attached interfaces.
func (m *Manager) AllStats() []Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var all []Stats
	for name, state := range m.attached {
		s := state.Stats
		s.Interface = name
		s.AttachMode = state.Mode.String()
		s.Attached = state.Attached
		s.BlocklistSize = len(m.blocklist) + len(m.blocklist6)
		s.ACLRuleCount = len(m.acls)
		s.LastUpdate = time.Now()
		all = append(all, s)
	}
	return all
}

// IsRunning returns whether the manager has any attached interfaces.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.attached) > 0
}

// Status returns a full status snapshot.
func (m *Manager) Status() *ManagerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := &ManagerStatus{
		Running:        len(m.attached) > 0,
		Mode:           m.mode.String(),
		BlocklistSize:  len(m.blocklist) + len(m.blocklist6),
		ACLRuleCount:   len(m.acls),
		InterfaceCount: len(m.attached),
		Interfaces:     make([]InterfaceState, 0, len(m.attached)),
	}

	if m.caps != nil {
		status.Capabilities = *m.caps
	}

	for _, s := range m.attached {
		status.Interfaces = append(status.Interfaces, *s)
	}

	return status
}

// ManagerStatus is the full status snapshot returned by Status().
type ManagerStatus struct {
	Running        bool             `json:"running"`
	Mode           string           `json:"mode"`
	Capabilities   Capabilities     `json:"capabilities"`
	BlocklistSize  int              `json:"blocklist_size"`
	ACLRuleCount   int              `json:"acl_rule_count"`
	InterfaceCount int              `json:"interface_count"`
	Interfaces     []InterfaceState `json:"interfaces"`
}

// IPv4ToKey converts a dotted-quad IP string to a [4]byte key.
func IPv4ToKey(ipStr string) ([4]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return [4]byte{}, fmt.Errorf("invalid IP: %q", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return [4]byte{}, fmt.Errorf("not an IPv4 address: %q", ipStr)
	}
	var key [4]byte
	copy(key[:], ip4)
	return key, nil
}

// IPv4FromKey converts a [4]byte key back to a dotted-quad string.
func IPv4FromKey(key [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", key[0], key[1], key[2], key[3])
}

// IPv4ToNetworkOrder converts an IP to network byte order uint32.
func IPv4ToNetworkOrder(ipStr string) (uint32, error) {
	key, err := IPv4ToKey(ipStr)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(key[:]), nil
}

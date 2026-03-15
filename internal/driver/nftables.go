package driver

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	nft "github.com/google/nftables"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

// NFTables manages nftables ruleset application.
type NFTables struct {
	mu             sync.Mutex
	store          *config.Store
	rulesetDir     string
	confirmTimer   *time.Timer
	pendingRev     int
	confirmTimeout time.Duration
	WGListenPort   int // WireGuard listen port (0 = disabled).
}

// NewNFTables creates a new nftables driver.
func NewNFTables(store *config.Store, rulesetDir string) *NFTables {
	return &NFTables{
		store:          store,
		rulesetDir:     rulesetDir,
		confirmTimeout: 60 * time.Second,
	}
}

// Apply compiles the current config and applies it via netlink.
func (n *NFTables) Apply() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	input, err := n.buildInput()
	if err != nil {
		return fmt.Errorf("build input: %w", err)
	}

	// Compile text for persistence and DryRun display.
	ruleset, err := compiler.Compile(input)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	// Write text to file for reference and debugging.
	if err := n.writeRulesetFile(ruleset); err != nil {
		return fmt.Errorf("write ruleset file: %w", err)
	}

	// Apply via netlink (no shell-out to nft CLI).
	slog.Info("applying nftables ruleset via netlink")
	if err := applyNetlink(input); err != nil {
		return fmt.Errorf("netlink apply: %w", err)
	}

	if err := n.verify(ruleset); err != nil {
		slog.Warn("post-apply verification failed", "error", err)
		return fmt.Errorf("post-apply verification: %w", err)
	}

	return nil
}

// ApplyWithConfirm applies rules with an auto-rollback timer.
// Call Confirm() within the timeout to make permanent, or rules auto-rollback.
func (n *NFTables) ApplyWithConfirm(prevRev int) error {
	if err := n.Apply(); err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.pendingRev = prevRev
	if n.confirmTimer != nil {
		n.confirmTimer.Stop()
	}
	n.confirmTimer = time.AfterFunc(n.confirmTimeout, func() {
		slog.Warn("apply-confirm timeout, rolling back", "rev", prevRev)
		if err := n.store.Rollback(prevRev); err != nil {
			slog.Error("rollback failed", "error", err)
			return
		}
		if err := n.Apply(); err != nil {
			slog.Error("re-apply after rollback failed", "error", err)
		}
	})

	return nil
}

// Confirm stops the auto-rollback timer.
func (n *NFTables) Confirm() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.confirmTimer != nil {
		n.confirmTimer.Stop()
		n.confirmTimer = nil
	}
	n.pendingRev = 0
}

// DryRun compiles and returns the ruleset text without applying.
func (n *NFTables) DryRun() (string, error) {
	input, err := n.buildInput()
	if err != nil {
		return "", fmt.Errorf("build input: %w", err)
	}
	ruleset, err := compiler.Compile(input)
	if err != nil {
		return "", fmt.Errorf("compile: %w", err)
	}
	return ruleset.Text, nil
}

func (n *NFTables) buildInput() (*compiler.Input, error) {
	zones, err := n.store.ListZones()
	if err != nil {
		return nil, err
	}
	aliases, err := n.store.ListAliases()
	if err != nil {
		return nil, err
	}
	policies, err := n.store.ListPolicies()
	if err != nil {
		return nil, err
	}
	profiles, err := n.store.ListProfiles()
	if err != nil {
		return nil, err
	}
	devices, err := n.store.ListDevices()
	if err != nil {
		return nil, err
	}

	return &compiler.Input{
		Zones:        zones,
		Aliases:      aliases,
		Policies:     policies,
		Profiles:     profiles,
		Devices:      devices,
		WGListenPort: n.WGListenPort,
	}, nil
}

// writeRulesetFile persists the compiled ruleset text for debugging and reference.
func (n *NFTables) writeRulesetFile(ruleset *compiler.CompiledRuleset) error {
	if err := os.MkdirAll(n.rulesetDir, 0o750); err != nil {
		return fmt.Errorf("create ruleset dir: %w", err)
	}

	path := filepath.Join(n.rulesetDir, "gatekeeper.nft")
	if err := os.WriteFile(path, []byte(ruleset.Text), 0o640); err != nil {
		return fmt.Errorf("write ruleset: %w", err)
	}
	return nil
}

// verify queries nftables via netlink to confirm the expected table exists.
func (n *NFTables) verify(ruleset *compiler.CompiledRuleset) error {
	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables netlink connection: %w", err)
	}

	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == "gatekeeper" {
			slog.Info("post-apply verification passed")
			return nil
		}
	}
	return fmt.Errorf("gatekeeper table not found in nftables after apply")
}

// SafeApply attempts to compile and apply. On failure, it returns the error
// without terminating the process, allowing the daemon to start with stale rules.
func (n *NFTables) SafeApply() error {
	if err := n.Apply(); err != nil {
		slog.Error("safe apply failed, continuing with stale rules", "error", err)
		return err
	}
	return nil
}

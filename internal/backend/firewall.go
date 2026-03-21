package backend

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

// FirewallController implements the Firewall interface by combining a
// FirewallBackend (e.g., NftablesBackend) with a config.Store.
// This is the object wired into the daemon, API, web UI, and MCP.
type FirewallController struct {
	mu             sync.Mutex
	backend        FirewallBackend
	store          *config.Store
	WGListenPort   int
	MSSClampPMTU   bool // Enable TCP MSS clamping to path MTU in forward chain.
	APIPort        int  // Management API port (always allowed inbound).
	confirmTimer   *time.Timer
	confirmed      bool // Guards against timer/Confirm race.
	pendingRev     int
	confirmTimeout time.Duration
	lastArtifact   *Artifact
}

// NewFirewallController creates a Firewall backed by the given FirewallBackend.
func NewFirewallController(backend FirewallBackend, store *config.Store) *FirewallController {
	return &FirewallController{
		backend:        backend,
		store:          store,
		confirmTimeout: 60 * time.Second,
	}
}

// Apply compiles the current config and applies it via the backend.
func (fc *FirewallController) Apply() error {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.applyLocked()
}

// applyLocked performs the compile+apply cycle. Caller must hold fc.mu.
func (fc *FirewallController) applyLocked() error {
	input, err := fc.buildInput()
	if err != nil {
		return fmt.Errorf("build input: %w", err)
	}

	artifact, err := fc.backend.Compile(input)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	if err := fc.backend.Apply(artifact); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	// Verify post-apply.
	if ok, drifts, err := fc.backend.Verify(artifact); err != nil {
		slog.Warn("post-apply verification error", "error", err)
	} else if !ok {
		slog.Warn("post-apply drift detected", "drifts", len(drifts))
	}

	fc.lastArtifact = artifact
	return nil
}

// SafeApply attempts Apply. On failure, logs the error but does not terminate.
func (fc *FirewallController) SafeApply() error {
	if err := fc.Apply(); err != nil {
		slog.Error("safe apply failed, continuing with stale rules", "error", err)
		return err
	}
	return nil
}

// DryRun compiles and returns the ruleset text without applying.
func (fc *FirewallController) DryRun() (string, error) {
	input, err := fc.buildInput()
	if err != nil {
		return "", fmt.Errorf("build input: %w", err)
	}
	return fc.backend.DryRun(input)
}

// ApplyWithConfirm applies rules with an auto-rollback timer.
func (fc *FirewallController) ApplyWithConfirm(prevRev int) error {
	if err := fc.Apply(); err != nil {
		return err
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.pendingRev = prevRev
	fc.confirmed = false
	if fc.confirmTimer != nil {
		fc.confirmTimer.Stop()
	}
	fc.confirmTimer = time.AfterFunc(fc.confirmTimeout, func() {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		if fc.confirmed {
			return // Confirm() won the race — do not rollback.
		}
		slog.Warn("apply-confirm timeout, rolling back", "rev", prevRev)
		if err := fc.store.Rollback(prevRev); err != nil {
			slog.Error("rollback failed", "error", err)
			return
		}
		if err := fc.applyLocked(); err != nil {
			slog.Error("re-apply after rollback failed", "error", err)
			// M-N5: Last resort — if the backend supports emergency flush,
			// clear all rules to prevent lockout with broken rules.
			// The daemon will re-apply on next SIGHUP or restart.
			if flusher, ok := fc.backend.(interface{ EmergencyFlush() error }); ok {
				if fErr := flusher.EmergencyFlush(); fErr != nil {
					slog.Error("emergency flush also failed — manual intervention required", "error", fErr)
				} else {
					slog.Warn("emergency flush succeeded — firewall in permissive state until re-apply")
				}
			}
		}
	})

	return nil
}

// Confirm stops the auto-rollback timer. Sets confirmed flag to prevent
// a timer goroutine that already fired from rolling back after we return.
func (fc *FirewallController) Confirm() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.confirmed = true
	if fc.confirmTimer != nil {
		fc.confirmTimer.Stop()
		fc.confirmTimer = nil
	}
	fc.pendingRev = 0
}

// buildInput assembles the compiler input from the config store.
func (fc *FirewallController) buildInput() (*compiler.Input, error) {
	zones, err := fc.store.ListZones()
	if err != nil {
		return nil, err
	}
	aliases, err := fc.store.ListAliases()
	if err != nil {
		return nil, err
	}
	policies, err := fc.store.ListPolicies()
	if err != nil {
		return nil, err
	}
	profiles, err := fc.store.ListProfiles()
	if err != nil {
		return nil, err
	}
	devices, err := fc.store.ListDevices()
	if err != nil {
		return nil, err
	}

	return &compiler.Input{
		Zones:        zones,
		Aliases:      aliases,
		Policies:     policies,
		Profiles:     profiles,
		Devices:      devices,
		WGListenPort: fc.WGListenPort,
		MSSClampPMTU: fc.MSSClampPMTU,
		APIPort:      fc.APIPort,
	}, nil
}

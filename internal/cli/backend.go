// Package cli provides the CLI backend abstraction for Gatekeeper.
//
// The Backend interface allows the CLI to operate in two modes:
//   - DirectBackend: calls internal/ops directly (default, for local use)
//   - APIBackend: calls the REST API over HTTP (for remote use or fallback)
//
// This ensures the CLI can always use the same command logic regardless
// of whether it's operating locally or remotely.
package cli

import (
	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
)

// Backend defines the operations the CLI can perform. Both DirectBackend
// and APIBackend implement this interface, ensuring identical behavior
// regardless of the execution mode.
type Backend interface {
	// Zones
	ListZones() ([]model.Zone, error)
	GetZone(name string) (*model.Zone, error)
	CreateZone(z *model.Zone) error
	UpdateZone(z *model.Zone) error
	DeleteZone(name string) error

	// Aliases
	ListAliases() ([]model.Alias, error)
	GetAlias(name string) (*model.Alias, error)
	CreateAlias(a *model.Alias) error
	UpdateAlias(a *model.Alias) error
	DeleteAlias(name string) error
	AddAliasMember(aliasName, member string) error
	RemoveAliasMember(aliasName, member string) error

	// Profiles
	ListProfiles() ([]model.Profile, error)
	GetProfile(name string) (*model.Profile, error)
	CreateProfile(p *model.Profile) error
	UpdateProfile(p *model.Profile) error
	DeleteProfile(name string) error

	// Policies
	ListPolicies() ([]model.Policy, error)
	GetPolicy(name string) (*model.Policy, error)
	CreatePolicy(p *model.Policy) error
	UpdatePolicy(p *model.Policy) error
	DeletePolicy(name string) error
	CreateRule(policyName string, rule *model.Rule) error
	DeleteRule(id int64) error

	// Devices
	ListDevices() ([]model.DeviceAssignment, error)
	AssignDevice(ip, mac, hostname, profileName string, profileID int64) (*model.DeviceAssignment, error)
	UnassignDevice(ip string) error

	// Config
	Commit(message string) (int, error)
	Rollback(rev int) error
	ListRevisions() ([]ops.Revision, error)
	Diff(rev1, rev2 int) (*config.ConfigSnapshot, *config.ConfigSnapshot, error)
	Export() (*config.ConfigSnapshot, error)
	Import(snap *config.ConfigSnapshot) error

	// Diagnostics (read-only)
	ListAuditLog(limit int) ([]config.AuditEntry, error)
	PathTest(req compiler.PathTestRequest) (*compiler.PathTestResult, error)
	Explain(req compiler.PathTestRequest) (*compiler.ExplainResult, error)

	// WireGuard
	ListWGPeers() ([]driver.WGPeer, error)
	AddWGPeer(peer driver.WGPeer) error
	RemoveWGPeer(publicKey string) error
}

// DirectBackend implements Backend by calling the ops layer directly.
// This is the default mode when the CLI runs on the same host as the daemon.
type DirectBackend struct {
	o     *ops.Ops
	wg    *ops.WireGuardOps
	actor ops.Actor
}

// NewDirectBackend creates a backend that calls internal packages directly.
func NewDirectBackend(o *ops.Ops, wg *ops.WireGuardOps) *DirectBackend {
	return &DirectBackend{
		o:     o,
		wg:    wg,
		actor: ops.Actor{Source: "cli", User: "root"},
	}
}

func (d *DirectBackend) ListZones() ([]model.Zone, error)      { return d.o.ListZones() }
func (d *DirectBackend) GetZone(name string) (*model.Zone, error) { return d.o.GetZone(name) }
func (d *DirectBackend) CreateZone(z *model.Zone) error          { return d.o.CreateZone(d.actor, z) }
func (d *DirectBackend) UpdateZone(z *model.Zone) error          { return d.o.UpdateZone(d.actor, z) }
func (d *DirectBackend) DeleteZone(name string) error            { return d.o.DeleteZone(d.actor, name) }

func (d *DirectBackend) ListAliases() ([]model.Alias, error)      { return d.o.ListAliases() }
func (d *DirectBackend) GetAlias(name string) (*model.Alias, error) { return d.o.GetAlias(name) }
func (d *DirectBackend) CreateAlias(a *model.Alias) error          { return d.o.CreateAlias(d.actor, a) }
func (d *DirectBackend) UpdateAlias(a *model.Alias) error          { return d.o.UpdateAlias(d.actor, a) }
func (d *DirectBackend) DeleteAlias(name string) error            { return d.o.DeleteAlias(d.actor, name) }
func (d *DirectBackend) AddAliasMember(aliasName, member string) error {
	return d.o.AddAliasMember(d.actor, aliasName, member)
}
func (d *DirectBackend) RemoveAliasMember(aliasName, member string) error {
	return d.o.RemoveAliasMember(aliasName, member)
}

func (d *DirectBackend) ListProfiles() ([]model.Profile, error)        { return d.o.ListProfiles() }
func (d *DirectBackend) GetProfile(name string) (*model.Profile, error) { return d.o.GetProfile(name) }
func (d *DirectBackend) CreateProfile(p *model.Profile) error          { return d.o.CreateProfile(d.actor, p) }
func (d *DirectBackend) UpdateProfile(p *model.Profile) error          { return d.o.UpdateProfile(d.actor, p) }
func (d *DirectBackend) DeleteProfile(name string) error              { return d.o.DeleteProfile(d.actor, name) }

func (d *DirectBackend) ListPolicies() ([]model.Policy, error)        { return d.o.ListPolicies() }
func (d *DirectBackend) GetPolicy(name string) (*model.Policy, error) { return d.o.GetPolicy(name) }
func (d *DirectBackend) CreatePolicy(p *model.Policy) error            { return d.o.CreatePolicy(d.actor, p) }
func (d *DirectBackend) UpdatePolicy(p *model.Policy) error            { return d.o.UpdatePolicy(d.actor, p) }
func (d *DirectBackend) DeletePolicy(name string) error              { return d.o.DeletePolicy(d.actor, name) }
func (d *DirectBackend) CreateRule(policyName string, rule *model.Rule) error {
	return d.o.CreateRule(d.actor, policyName, rule)
}
func (d *DirectBackend) DeleteRule(id int64) error { return d.o.DeleteRule(d.actor, id) }

func (d *DirectBackend) ListDevices() ([]model.DeviceAssignment, error) { return d.o.ListDevices() }
func (d *DirectBackend) AssignDevice(ip, mac, hostname, profileName string, profileID int64) (*model.DeviceAssignment, error) {
	return d.o.AssignDevice(d.actor, ip, mac, hostname, profileName, profileID)
}
func (d *DirectBackend) UnassignDevice(ip string) error { return d.o.UnassignDevice(d.actor, ip) }

func (d *DirectBackend) Commit(message string) (int, error)    { return d.o.Commit(d.actor, message) }
func (d *DirectBackend) Rollback(rev int) error                 { return d.o.Rollback(d.actor, rev) }
func (d *DirectBackend) ListRevisions() ([]ops.Revision, error) { return d.o.ListRevisions() }
func (d *DirectBackend) Diff(rev1, rev2 int) (*config.ConfigSnapshot, *config.ConfigSnapshot, error) {
	return d.o.Diff(rev1, rev2)
}
func (d *DirectBackend) Export() (*config.ConfigSnapshot, error) { return d.o.Export() }
func (d *DirectBackend) Import(snap *config.ConfigSnapshot) error {
	return d.o.Import(d.actor, snap)
}

func (d *DirectBackend) ListAuditLog(limit int) ([]config.AuditEntry, error) {
	return d.o.ListAuditLog(limit)
}
func (d *DirectBackend) PathTest(req compiler.PathTestRequest) (*compiler.PathTestResult, error) {
	return d.o.PathTest(req)
}
func (d *DirectBackend) Explain(req compiler.PathTestRequest) (*compiler.ExplainResult, error) {
	return d.o.Explain(req)
}

func (d *DirectBackend) ListWGPeers() ([]driver.WGPeer, error) {
	if d.wg == nil {
		return nil, nil
	}
	return d.wg.ListPeers(), nil
}
func (d *DirectBackend) AddWGPeer(peer driver.WGPeer) error {
	if d.wg == nil {
		return nil
	}
	return d.wg.AddPeer(peer)
}
func (d *DirectBackend) RemoveWGPeer(publicKey string) error {
	if d.wg == nil {
		return nil
	}
	return d.wg.RemovePeer(publicKey)
}

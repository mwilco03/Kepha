package cli

import (
	"encoding/json"
	"fmt"

	"github.com/mwilco03/kepha/internal/compiler"
	"github.com/mwilco03/kepha/internal/config"
	"github.com/mwilco03/kepha/internal/driver"
	"github.com/mwilco03/kepha/internal/model"
	"github.com/mwilco03/kepha/internal/ops"
)

// APIBackend implements Backend by calling the REST API over HTTP.
// Used when GK_MODE=api or for remote CLI access.
type APIBackend struct {
	c *Client
}

// NewAPIBackend creates a backend that calls the REST API.
func NewAPIBackend(c *Client) *APIBackend {
	return &APIBackend{c: c}
}

func (a *APIBackend) ListZones() ([]model.Zone, error) {
	data, err := a.c.Get("/api/v1/zones")
	if err != nil {
		return nil, err
	}
	var zones []model.Zone
	return zones, json.Unmarshal(data, &zones)
}

func (a *APIBackend) GetZone(name string) (*model.Zone, error) {
	data, err := a.c.Get("/api/v1/zones/" + name)
	if err != nil {
		return nil, err
	}
	var z model.Zone
	return &z, json.Unmarshal(data, &z)
}

func (a *APIBackend) CreateZone(z *model.Zone) error {
	_, err := a.c.Post("/api/v1/zones", z)
	return err
}

func (a *APIBackend) UpdateZone(z *model.Zone) error {
	_, err := a.c.Put("/api/v1/zones/"+z.Name, z)
	return err
}

func (a *APIBackend) DeleteZone(name string) error {
	_, err := a.c.Delete("/api/v1/zones/"+name, nil)
	return err
}

func (a *APIBackend) ListAliases() ([]model.Alias, error) {
	data, err := a.c.Get("/api/v1/aliases")
	if err != nil {
		return nil, err
	}
	var aliases []model.Alias
	return aliases, json.Unmarshal(data, &aliases)
}

func (a *APIBackend) GetAlias(name string) (*model.Alias, error) {
	data, err := a.c.Get("/api/v1/aliases/" + name)
	if err != nil {
		return nil, err
	}
	var al model.Alias
	return &al, json.Unmarshal(data, &al)
}

func (a *APIBackend) CreateAlias(al *model.Alias) error {
	_, err := a.c.Post("/api/v1/aliases", al)
	return err
}

func (a *APIBackend) UpdateAlias(al *model.Alias) error {
	_, err := a.c.Put("/api/v1/aliases/"+al.Name, al)
	return err
}

func (a *APIBackend) DeleteAlias(name string) error {
	_, err := a.c.Delete("/api/v1/aliases/"+name, nil)
	return err
}

func (a *APIBackend) AddAliasMember(aliasName, member string) error {
	_, err := a.c.Post("/api/v1/aliases/"+aliasName+"/members", map[string]string{"member": member})
	return err
}

func (a *APIBackend) RemoveAliasMember(aliasName, member string) error {
	_, err := a.c.Delete("/api/v1/aliases/"+aliasName+"/members", map[string]string{"member": member})
	return err
}

func (a *APIBackend) ListProfiles() ([]model.Profile, error) {
	data, err := a.c.Get("/api/v1/profiles")
	if err != nil {
		return nil, err
	}
	var profiles []model.Profile
	return profiles, json.Unmarshal(data, &profiles)
}

func (a *APIBackend) GetProfile(name string) (*model.Profile, error) {
	data, err := a.c.Get("/api/v1/profiles/" + name)
	if err != nil {
		return nil, err
	}
	var p model.Profile
	return &p, json.Unmarshal(data, &p)
}

func (a *APIBackend) CreateProfile(p *model.Profile) error {
	_, err := a.c.Post("/api/v1/profiles", p)
	return err
}

func (a *APIBackend) UpdateProfile(p *model.Profile) error {
	_, err := a.c.Put("/api/v1/profiles/"+p.Name, p)
	return err
}

func (a *APIBackend) DeleteProfile(name string) error {
	_, err := a.c.Delete("/api/v1/profiles/"+name, nil)
	return err
}

func (a *APIBackend) ListPolicies() ([]model.Policy, error) {
	data, err := a.c.Get("/api/v1/policies")
	if err != nil {
		return nil, err
	}
	var policies []model.Policy
	return policies, json.Unmarshal(data, &policies)
}

func (a *APIBackend) GetPolicy(name string) (*model.Policy, error) {
	data, err := a.c.Get("/api/v1/policies/" + name)
	if err != nil {
		return nil, err
	}
	var p model.Policy
	return &p, json.Unmarshal(data, &p)
}

func (a *APIBackend) CreatePolicy(p *model.Policy) error {
	_, err := a.c.Post("/api/v1/policies", p)
	return err
}

func (a *APIBackend) UpdatePolicy(p *model.Policy) error {
	_, err := a.c.Put("/api/v1/policies/"+p.Name, p)
	return err
}

func (a *APIBackend) DeletePolicy(name string) error {
	_, err := a.c.Delete("/api/v1/policies/"+name, nil)
	return err
}

func (a *APIBackend) CreateRule(policyName string, rule *model.Rule) error {
	_, err := a.c.Post("/api/v1/policies/"+policyName+"/rules", rule)
	return err
}

func (a *APIBackend) DeleteRule(id int64) error {
	_, err := a.c.Delete(fmt.Sprintf("/api/v1/rules/%d", id), nil)
	return err
}

func (a *APIBackend) ListDevices() ([]model.DeviceAssignment, error) {
	data, err := a.c.Get("/api/v1/devices")
	if err != nil {
		return nil, err
	}
	var devices []model.DeviceAssignment
	return devices, json.Unmarshal(data, &devices)
}

func (a *APIBackend) AssignDevice(ip, mac, hostname, profileName string, profileID int64) (*model.DeviceAssignment, error) {
	body := map[string]any{
		"ip": ip, "mac": mac, "hostname": hostname,
		"profile": profileName, "profile_id": profileID,
	}
	data, err := a.c.Post("/api/v1/assign", body)
	if err != nil {
		return nil, err
	}
	var d model.DeviceAssignment
	return &d, json.Unmarshal(data, &d)
}

func (a *APIBackend) UnassignDevice(ip string) error {
	_, err := a.c.Delete("/api/v1/unassign", map[string]string{"ip": ip})
	return err
}

func (a *APIBackend) Commit(message string) (int, error) {
	data, err := a.c.Post("/api/v1/config/commit", map[string]string{"message": message})
	if err != nil {
		return 0, err
	}
	var result struct {
		Rev int `json:"rev"`
	}
	return result.Rev, json.Unmarshal(data, &result)
}

func (a *APIBackend) Rollback(rev int) error {
	_, err := a.c.Post(fmt.Sprintf("/api/v1/config/rollback/%d", rev), nil)
	return err
}

func (a *APIBackend) ListRevisions() ([]ops.Revision, error) {
	data, err := a.c.Get("/api/v1/config/revisions")
	if err != nil {
		return nil, err
	}
	var revs []ops.Revision
	return revs, json.Unmarshal(data, &revs)
}

func (a *APIBackend) Diff(rev1, rev2 int) (*config.ConfigSnapshot, *config.ConfigSnapshot, error) {
	data, err := a.c.Get(fmt.Sprintf("/api/v1/config/diff?rev1=%d&rev2=%d", rev1, rev2))
	if err != nil {
		return nil, nil, err
	}
	var result struct {
		Rev1 *config.ConfigSnapshot `json:"rev1"`
		Rev2 *config.ConfigSnapshot `json:"rev2"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, nil, err
	}
	return result.Rev1, result.Rev2, nil
}

func (a *APIBackend) Export() (*config.ConfigSnapshot, error) {
	data, err := a.c.Get("/api/v1/config/export")
	if err != nil {
		return nil, err
	}
	var snap config.ConfigSnapshot
	return &snap, json.Unmarshal(data, &snap)
}

func (a *APIBackend) Import(snap *config.ConfigSnapshot) error {
	_, err := a.c.Post("/api/v1/config/import", snap)
	return err
}

func (a *APIBackend) ListAuditLog(limit int) ([]config.AuditEntry, error) {
	data, err := a.c.Get(fmt.Sprintf("/api/v1/audit?limit=%d", limit))
	if err != nil {
		return nil, err
	}
	var entries []config.AuditEntry
	return entries, json.Unmarshal(data, &entries)
}

func (a *APIBackend) PathTest(req compiler.PathTestRequest) (*compiler.PathTestResult, error) {
	data, err := a.c.Post("/api/v1/test", req)
	if err != nil {
		return nil, err
	}
	var result compiler.PathTestResult
	return &result, json.Unmarshal(data, &result)
}

func (a *APIBackend) Explain(req compiler.PathTestRequest) (*compiler.ExplainResult, error) {
	data, err := a.c.Post("/api/v1/explain", req)
	if err != nil {
		return nil, err
	}
	var result compiler.ExplainResult
	return &result, json.Unmarshal(data, &result)
}

func (a *APIBackend) ListWGPeers() ([]driver.WGPeer, error) {
	data, err := a.c.Get("/api/v1/wg/peers")
	if err != nil {
		return nil, err
	}
	var peers []driver.WGPeer
	return peers, json.Unmarshal(data, &peers)
}

func (a *APIBackend) AddWGPeer(peer driver.WGPeer) error {
	_, err := a.c.Post("/api/v1/wg/peers", peer)
	return err
}

func (a *APIBackend) RemoveWGPeer(publicKey string) error {
	_, err := a.c.Delete("/api/v1/wg/peers/"+publicKey, nil)
	return err
}

func (a *APIBackend) PruneWGPeers(maxAgeSeconds int) ([]string, error) {
	data, err := a.c.Post("/api/v1/wg/prune", map[string]int{"max_age_seconds": maxAgeSeconds})
	if err != nil {
		return nil, err
	}
	var result struct {
		Pruned []string `json:"pruned"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Pruned, nil
}

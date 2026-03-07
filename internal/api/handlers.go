package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
)

type handlers struct {
	store   *config.Store
	nft     *driver.NFTables
	wg      *driver.WireGuard
	dnsmasq *driver.Dnsmasq
}

// --- Zones ---

func (h *handlers) listZones(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		zones, total, err := h.store.ListZonesPaginated(p)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if zones == nil {
			zones = []model.Zone{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": zones, "total": total, "limit": p.Limit, "offset": p.Offset})
		return
	}
	zones, err := h.store.ListZones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, zones)
}

func (h *handlers) getZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	zone, err := h.store.GetZone(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if zone == nil {
		writeError(w, http.StatusNotFound, "zone not found")
		return
	}
	writeJSON(w, http.StatusOK, zone)
}

func (h *handlers) createZone(w http.ResponseWriter, r *http.Request) {
	var z model.Zone
	if err := readJSON(r, &z); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if z.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validName(z.Name) {
		writeError(w, http.StatusBadRequest, "name must be alphanumeric with hyphens/underscores, max 64 chars")
		return
	}
	if isDryRun(r) {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "action": "create_zone", "data": z})
		return
	}
	if err := h.store.CreateZone(&z); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	_ = h.store.LogAudit("create", "zone", z.Name, z)
	writeJSON(w, http.StatusCreated, z)
}

func (h *handlers) updateZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var z model.Zone
	if err := readJSON(r, &z); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	z.Name = name
	if err := h.store.UpdateZone(&z); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.store.LogAudit("update", "zone", z.Name, z)
	writeJSON(w, http.StatusOK, z)
}

func (h *handlers) deleteZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.DeleteZone(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.store.LogAudit("delete", "zone", name, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Aliases ---

func (h *handlers) listAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := h.store.ListAliases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if aliases == nil {
		aliases = []model.Alias{}
	}
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		end := p.Offset + p.Limit
		if end > len(aliases) {
			end = len(aliases)
		}
		start := p.Offset
		if start > len(aliases) {
			start = len(aliases)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": aliases[start:end], "total": len(aliases), "limit": p.Limit, "offset": p.Offset})
		return
	}
	writeJSON(w, http.StatusOK, aliases)
}

func (h *handlers) getAlias(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	alias, err := h.store.GetAlias(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alias == nil {
		writeError(w, http.StatusNotFound, "alias not found")
		return
	}
	writeJSON(w, http.StatusOK, alias)
}

func (h *handlers) createAlias(w http.ResponseWriter, r *http.Request) {
	var a model.Alias
	if err := readJSON(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.Name == "" || a.Type == "" {
		writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}
	if !validName(a.Name) {
		writeError(w, http.StatusBadRequest, "name must be alphanumeric with hyphens/underscores, max 64 chars")
		return
	}
	if err := h.store.CreateAlias(&a); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	_ = h.store.LogAudit("create", "alias", a.Name, a)
	if a.Type == model.AliasTypeNested {
		if err := h.store.CheckAliasCycles(a.Name); err != nil {
			_ = h.store.DeleteAlias(a.Name)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *handlers) updateAlias(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var a model.Alias
	if err := readJSON(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.Name = name
	if err := h.store.UpdateAlias(&a); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *handlers) deleteAlias(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.DeleteAlias(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.store.LogAudit("delete", "alias", name, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handlers) addAliasMember(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Member string `json:"member"`
	}
	if err := readJSON(r, &body); err != nil || body.Member == "" {
		writeError(w, http.StatusBadRequest, "member is required")
		return
	}
	if err := h.store.AddAliasMember(name, body.Member); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (h *handlers) removeAliasMember(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Member string `json:"member"`
	}
	if err := readJSON(r, &body); err != nil || body.Member == "" {
		writeError(w, http.StatusBadRequest, "member is required")
		return
	}
	if err := h.store.RemoveAliasMember(name, body.Member); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// --- Profiles ---

func (h *handlers) listProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.store.ListProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profiles == nil {
		profiles = []model.Profile{}
	}
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		end := p.Offset + p.Limit
		if end > len(profiles) {
			end = len(profiles)
		}
		start := p.Offset
		if start > len(profiles) {
			start = len(profiles)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": profiles[start:end], "total": len(profiles), "limit": p.Limit, "offset": p.Offset})
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (h *handlers) getProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	profile, err := h.store.GetProfile(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profile == nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (h *handlers) createProfile(w http.ResponseWriter, r *http.Request) {
	var p model.Profile
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validName(p.Name) {
		writeError(w, http.StatusBadRequest, "name must be alphanumeric with hyphens/underscores, max 64 chars")
		return
	}
	if err := h.store.CreateProfile(&p); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *handlers) updateProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var p model.Profile
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Name = name
	if err := h.store.UpdateProfile(&p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *handlers) deleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.DeleteProfile(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Policies ---

func (h *handlers) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.ListPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if policies == nil {
		policies = []model.Policy{}
	}
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		end := p.Offset + p.Limit
		if end > len(policies) {
			end = len(policies)
		}
		start := p.Offset
		if start > len(policies) {
			start = len(policies)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": policies[start:end], "total": len(policies), "limit": p.Limit, "offset": p.Offset})
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (h *handlers) getPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	policy, err := h.store.GetPolicy(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if policy == nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *handlers) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validName(p.Name) {
		writeError(w, http.StatusBadRequest, "name must be alphanumeric with hyphens/underscores, max 64 chars")
		return
	}
	if err := h.store.CreatePolicy(&p); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *handlers) updatePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var p model.Policy
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.Name = name
	if err := h.store.UpdatePolicy(&p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.DeletePolicy(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Rules ---

func (h *handlers) createRule(w http.ResponseWriter, r *http.Request) {
	policyName := r.PathValue("name")
	var rule model.Rule
	if err := readJSON(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.CreateRule(policyName, &rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (h *handlers) deleteRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	if err := h.store.DeleteRule(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Devices ---

func (h *handlers) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if devices == nil {
		devices = []model.DeviceAssignment{}
	}
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		end := p.Offset + p.Limit
		if end > len(devices) {
			end = len(devices)
		}
		start := p.Offset
		if start > len(devices) {
			start = len(devices)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": devices[start:end], "total": len(devices), "limit": p.Limit, "offset": p.Offset})
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *handlers) assignDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP        string `json:"ip"`
		MAC       string `json:"mac"`
		Hostname  string `json:"hostname"`
		Profile   string `json:"profile"`
		ProfileID int64  `json:"profile_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}

	profileID := body.ProfileID
	if profileID == 0 && body.Profile != "" {
		p, err := h.store.GetProfile(body.Profile)
		if err != nil || p == nil {
			writeError(w, http.StatusBadRequest, "profile not found")
			return
		}
		profileID = p.ID
	}
	if profileID == 0 {
		writeError(w, http.StatusBadRequest, "profile or profile_id is required")
		return
	}

	d := &model.DeviceAssignment{
		IP:        body.IP,
		MAC:       body.MAC,
		Hostname:  body.Hostname,
		ProfileID: profileID,
	}
	if err := h.store.AssignDevice(d); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.store.LogAudit("assign", "device", d.IP, d)
	writeJSON(w, http.StatusCreated, d)
}

func (h *handlers) unassignDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &body); err != nil || body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	if err := h.store.UnassignDevice(body.IP); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unassigned"})
}

// --- Config ---

func (h *handlers) commitConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Message string `json:"message"`
	}
	_ = readJSON(r, &body)
	if body.Message == "" {
		body.Message = "manual commit"
	}

	if isDryRun(r) {
		if h.nft != nil {
			text, err := h.nft.DryRun()
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "ruleset": text})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "message": "no nftables driver"})
		return
	}

	rev, err := h.store.Commit(body.Message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if h.nft != nil {
		if err := h.nft.Apply(); err != nil {
			writeError(w, http.StatusInternalServerError, "commit saved but apply failed: "+err.Error())
			return
		}
	}

	_ = h.store.LogAudit("commit", "config", fmt.Sprintf("%d", rev), map[string]string{"message": body.Message})
	writeJSON(w, http.StatusOK, map[string]any{"rev": rev, "message": body.Message})
}

func (h *handlers) rollbackConfig(w http.ResponseWriter, r *http.Request) {
	revStr := r.PathValue("rev")
	rev, err := strconv.Atoi(revStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid revision number")
		return
	}
	if err := h.store.Rollback(rev); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if h.nft != nil {
		if err := h.nft.Apply(); err != nil {
			writeError(w, http.StatusInternalServerError, "rollback saved but apply failed: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled back", "rev": rev})
}

func (h *handlers) listRevisions(w http.ResponseWriter, r *http.Request) {
	revs, err := h.store.ListRevisions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, revs)
}

func (h *handlers) diffConfig(w http.ResponseWriter, r *http.Request) {
	rev1, _ := strconv.Atoi(r.URL.Query().Get("rev1"))
	rev2, _ := strconv.Atoi(r.URL.Query().Get("rev2"))
	if rev1 == 0 || rev2 == 0 {
		writeError(w, http.StatusBadRequest, "rev1 and rev2 query params required")
		return
	}
	snap1, snap2, err := h.store.Diff(rev1, rev2)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rev1": snap1, "rev2": snap2})
}

func (h *handlers) exportConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := h.store.Export()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (h *handlers) importConfig(w http.ResponseWriter, r *http.Request) {
	var snap config.ConfigSnapshot
	if err := readJSON(r, &snap); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.Import(&snap); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

func (h *handlers) confirmApply(w http.ResponseWriter, r *http.Request) {
	if h.nft != nil {
		h.nft.Confirm()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// --- Diagnostics ---

func (h *handlers) diagInterfaces(w http.ResponseWriter, r *http.Request) {
	zones, err := h.store.ListZones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type iface struct {
		Zone      string `json:"zone"`
		Interface string `json:"interface"`
		CIDR      string `json:"cidr"`
	}
	var ifaces []iface
	for _, z := range zones {
		if z.Interface != "" {
			ifaces = append(ifaces, iface{Zone: z.Name, Interface: z.Interface, CIDR: z.NetworkCIDR})
		}
	}
	writeJSON(w, http.StatusOK, ifaces)
}

func (h *handlers) diagPing(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	// Validate target is an IP or hostname (no shell injection).
	for _, c := range target {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':'
		if !valid {
			writeError(w, http.StatusBadRequest, "invalid target")
			return
		}
	}
	out, err := exec.CommandContext(r.Context(), "ping", "-c", "3", "-W", "2", target).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"target": target, "reachable": false, "output": string(out)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "reachable": true, "output": string(out)})
}

func (h *handlers) diagConnections(w http.ResponseWriter, r *http.Request) {
	out, err := exec.CommandContext(r.Context(), "ss", "-tunap").CombinedOutput()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get connections: "+err.Error())
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	writeJSON(w, http.StatusOK, map[string]any{"connections": lines})
}

func (h *handlers) dryRun(w http.ResponseWriter, r *http.Request) {
	if h.nft == nil {
		writeError(w, http.StatusServiceUnavailable, "nftables driver not available")
		return
	}
	text, err := h.nft.DryRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": text})
}

// --- WireGuard ---

func (h *handlers) listWGPeers(w http.ResponseWriter, r *http.Request) {
	if h.wg == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	writeJSON(w, http.StatusOK, h.wg.ListPeers())
}

func (h *handlers) addWGPeer(w http.ResponseWriter, r *http.Request) {
	if h.wg == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	var peer driver.WGPeer
	if err := readJSON(r, &peer); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if peer.PublicKey == "" || peer.AllowedIPs == "" {
		writeError(w, http.StatusBadRequest, "public_key and allowed_ips required")
		return
	}
	if err := h.wg.AddPeer(peer); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, peer)
}

func (h *handlers) removeWGPeer(w http.ResponseWriter, r *http.Request) {
	if h.wg == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	pubkey := r.PathValue("pubkey")
	if err := h.wg.RemovePeer(pubkey); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// --- DHCP Leases ---

func (h *handlers) diagLeases(w http.ResponseWriter, r *http.Request) {
	if h.dnsmasq == nil {
		writeJSON(w, http.StatusOK, []driver.Lease{})
		return
	}
	leases, err := h.dnsmasq.ParseLeaseFile("/var/lib/misc/dnsmasq.leases")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if leases == nil {
		leases = []driver.Lease{}
	}
	writeJSON(w, http.StatusOK, leases)
}

// --- Path Test ---

func (h *handlers) pathTest(w http.ResponseWriter, r *http.Request) {
	var req compiler.PathTestRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SrcIP == "" || req.DstIP == "" {
		writeError(w, http.StatusBadRequest, "src_ip and dst_ip required")
		return
	}

	input, err := h.buildCompilerInput()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := compiler.PathTest(input, req)
	writeJSON(w, http.StatusOK, result)
}

func (h *handlers) buildCompilerInput() (*compiler.Input, error) {
	zones, err := h.store.ListZones()
	if err != nil {
		return nil, err
	}
	aliases, err := h.store.ListAliases()
	if err != nil {
		return nil, err
	}
	policies, err := h.store.ListPolicies()
	if err != nil {
		return nil, err
	}
	profiles, err := h.store.ListProfiles()
	if err != nil {
		return nil, err
	}
	devices, err := h.store.ListDevices()
	if err != nil {
		return nil, err
	}
	return &compiler.Input{
		Zones:    zones,
		Aliases:  aliases,
		Policies: policies,
		Profiles: profiles,
		Devices:  devices,
	}, nil
}

// --- Explain ---

func (h *handlers) explainPath(w http.ResponseWriter, r *http.Request) {
	var req compiler.PathTestRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SrcIP == "" || req.DstIP == "" {
		writeError(w, http.StatusBadRequest, "src_ip and dst_ip required")
		return
	}

	input, err := h.buildCompilerInput()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := compiler.Explain(input, req)
	writeJSON(w, http.StatusOK, result)
}

// --- Audit Log ---

func (h *handlers) listAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	entries, err := h.store.ListAuditLog(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []config.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// --- Helpers ---

func isDryRun(r *http.Request) bool {
	return r.URL.Query().Get("dry_run") == "true"
}

func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit.
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// validName checks that a resource name contains only safe characters.
func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

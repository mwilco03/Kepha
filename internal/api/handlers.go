package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mwilco03/kepha/internal/backend"
	"github.com/mwilco03/kepha/internal/compiler"
	"github.com/mwilco03/kepha/internal/config"
	"github.com/mwilco03/kepha/internal/driver"
	"github.com/mwilco03/kepha/internal/model"
	"github.com/mwilco03/kepha/internal/ops"
	"github.com/mwilco03/kepha/internal/rbac"
	"github.com/mwilco03/kepha/internal/service"
)

// paginateAndRespond handles the common in-memory pagination pattern.
// If limit/offset query params are present, slices the data and returns
// a paginated response. Otherwise returns the full slice. Returns true
// if it handled the response (caller should return).
func paginateAndRespond(w http.ResponseWriter, r *http.Request, total int, slicer func(start, end int) any) bool {
	if !r.URL.Query().Has("limit") && !r.URL.Query().Has("offset") {
		return false
	}
	p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
	start := p.Offset
	if start > total {
		start = total
	}
	end := p.Offset + p.Limit
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   slicer(start, end),
		"total":  total,
		"limit":  p.Limit,
		"offset": p.Offset,
	})
	return true
}

// actorFromRequest extracts the RBAC key identity from the request context,
// falling back to "api" if RBAC is not enabled.
func actorFromRequest(r *http.Request) ops.Actor {
	if ak := rbac.APIKeyFromContext(r.Context()); ak != nil {
		return ops.Actor{Source: "api", User: ak.Name + "/" + ak.ID}
	}
	return ops.Actor{Source: "api", User: "api"}
}

// apiNetManager is the subset of NetworkManager the API handlers actually need.
// Narrowed from the 31-method god interface per M-SA4.
type apiNetManager interface {
	backend.LinkManager
	backend.DiagManager
}

type handlers struct {
	ops     *ops.Ops
	wgOps   *ops.WireGuardOps
	nft     backend.Firewall       // Was *driver.NFTables; now any Firewall implementation.
	dnsmasq *driver.Dnsmasq        // Only used for lease parsing (daemon-owned)
	net     apiNetManager // Narrowed from 31-method NetworkManager (M-SA4).
}

// --- Zones ---

func (h *handlers) listZones(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") {
		p := config.ParsePagination(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
		zones, total, err := h.ops.Store().ListZonesPaginated(p)
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
	zones, err := h.ops.ListZones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, zones)
}

func (h *handlers) getZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	zone, err := h.ops.GetZone(name)
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
	if isDryRun(r) {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "action": "create_zone", "data": z})
		return
	}
	if err := h.ops.CreateZone(actorFromRequest(r), &z); err != nil {
		if ops.IsConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
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
	if err := h.ops.UpdateZone(actorFromRequest(r), &z); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (h *handlers) deleteZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.DeleteZone(actorFromRequest(r), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Aliases ---

func (h *handlers) listAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := h.ops.ListAliases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if aliases == nil {
		aliases = []model.Alias{}
	}
	if paginateAndRespond(w, r, len(aliases), func(s, e int) any { return aliases[s:e] }) {
		return
	}
	writeJSON(w, http.StatusOK, aliases)
}

func (h *handlers) getAlias(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	alias, err := h.ops.GetAlias(name)
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
	if err := h.ops.CreateAlias(actorFromRequest(r), &a); err != nil {
		if ops.IsConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
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
	if err := h.ops.UpdateAlias(actorFromRequest(r), &a); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *handlers) deleteAlias(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.DeleteAlias(actorFromRequest(r), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
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
	if err := h.ops.AddAliasMember(actorFromRequest(r), name, body.Member); err != nil {
		if ops.IsNotFound(err) {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
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
	if err := h.ops.RemoveAliasMember(actorFromRequest(r), name, body.Member); err != nil {
		if ops.IsNotFound(err) {
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
	profiles, err := h.ops.ListProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profiles == nil {
		profiles = []model.Profile{}
	}
	if paginateAndRespond(w, r, len(profiles), func(s, e int) any { return profiles[s:e] }) {
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (h *handlers) getProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	profile, err := h.ops.GetProfile(name)
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
	if err := h.ops.CreateProfile(actorFromRequest(r), &p); err != nil {
		if ops.IsConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
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
	if err := h.ops.UpdateProfile(actorFromRequest(r), &p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *handlers) deleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.DeleteProfile(actorFromRequest(r), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Policies ---

func (h *handlers) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.ops.ListPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if policies == nil {
		policies = []model.Policy{}
	}
	if paginateAndRespond(w, r, len(policies), func(s, e int) any { return policies[s:e] }) {
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (h *handlers) getPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	policy, err := h.ops.GetPolicy(name)
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
	if err := h.ops.CreatePolicy(actorFromRequest(r), &p); err != nil {
		if ops.IsConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
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
	if err := h.ops.UpdatePolicy(actorFromRequest(r), &p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.ops.DeletePolicy(actorFromRequest(r), name); err != nil {
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
	if err := h.ops.CreateRule(actorFromRequest(r), policyName, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	if err := h.ops.DeleteRule(actorFromRequest(r), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Devices ---

func (h *handlers) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.ops.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if devices == nil {
		devices = []model.DeviceAssignment{}
	}
	if paginateAndRespond(w, r, len(devices), func(s, e int) any { return devices[s:e] }) {
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
	d, err := h.ops.AssignDevice(actorFromRequest(r), body.IP, body.MAC, body.Hostname, body.Profile, body.ProfileID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
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
	if err := h.ops.UnassignDevice(actorFromRequest(r), body.IP); err != nil {
		if ops.IsNotFound(err) {
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

	// Record the previous revision so we can auto-rollback on failure.
	prevRev := 0
	if revs, err := h.ops.ListRevisions(); err == nil && len(revs) > 0 {
		prevRev = revs[0].RevNumber
	}

	rev, err := h.ops.Commit(actorFromRequest(r), body.Message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Daemon-owned: apply nftables after commit with auto-rollback timer.
	// If /api/v1/config/confirm is not called within 60s, the config
	// automatically rolls back to the previous revision. This prevents
	// lockouts from bad firewall rules.
	if h.nft != nil {
		if prevRev > 0 {
			if err := h.nft.ApplyWithConfirm(prevRev); err != nil {
				writeError(w, http.StatusInternalServerError, "commit saved but nft apply failed: "+err.Error())
				return
			}
		} else {
			// First commit ever — no previous revision to rollback to.
			if err := h.nft.Apply(); err != nil {
				writeError(w, http.StatusInternalServerError, "commit saved but nft apply failed: "+err.Error())
				return
			}
		}
	}

	// Daemon-owned: apply dnsmasq config after commit.
	if h.dnsmasq != nil {
		if err := h.dnsmasq.Apply(); err != nil {
			slog.Error("dnsmasq apply after commit failed", "error", err)
		}
	}

	resp := map[string]any{"rev": rev, "message": body.Message}
	if prevRev > 0 && h.nft != nil {
		resp["confirm_required"] = true
		resp["confirm_timeout_sec"] = 60
		resp["rollback_rev"] = prevRev
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handlers) rollbackConfig(w http.ResponseWriter, r *http.Request) {
	revStr := r.PathValue("rev")
	rev, err := strconv.Atoi(revStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid revision number")
		return
	}
	if err := h.ops.Rollback(actorFromRequest(r), rev); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Daemon-owned: apply nftables after rollback.
	if h.nft != nil {
		if err := h.nft.Apply(); err != nil {
			writeError(w, http.StatusInternalServerError, "rollback saved but nft apply failed: "+err.Error())
			return
		}
	}

	// Daemon-owned: apply dnsmasq config after rollback.
	if h.dnsmasq != nil {
		if err := h.dnsmasq.Apply(); err != nil {
			slog.Error("dnsmasq apply after rollback failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled back", "rev": rev})
}

func (h *handlers) listRevisions(w http.ResponseWriter, r *http.Request) {
	revs, err := h.ops.ListRevisions()
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
	snap1, snap2, err := h.ops.Diff(rev1, rev2)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rev1": snap1, "rev2": snap2})
}

func (h *handlers) exportConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := h.ops.Export()
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
	if err := h.ops.Import(actorFromRequest(r), &snap); err != nil {
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
	zones, err := h.ops.ListZones()
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

func (h *handlers) diagLinks(w http.ResponseWriter, r *http.Request) {
	if h.net == nil {
		writeError(w, http.StatusServiceUnavailable, "network manager not available")
		return
	}
	links, err := h.net.LinkList()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, links)
}

func (h *handlers) diagTopology(w http.ResponseWriter, r *http.Request) {
	topo, err := service.DiscoverTopology()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, topo)
}

func (h *handlers) diagPing(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	// Validate target is an IP or hostname.
	for _, c := range target {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':'
		if !valid {
			writeError(w, http.StatusBadRequest, "invalid target")
			return
		}
	}

	if h.net == nil {
		writeError(w, http.StatusServiceUnavailable, "network manager not available")
		return
	}

	result, err := h.net.Ping(target, 3, 2, "")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"target": target, "reachable": false, "output": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":    target,
		"reachable": result.Received > 0,
		"output":    result.Output,
		"sent":      result.Sent,
		"received":  result.Received,
		"avg_rtt":   result.AvgRTT.String(),
	})
}

func (h *handlers) diagConnections(w http.ResponseWriter, r *http.Request) {
	if h.net == nil {
		writeError(w, http.StatusServiceUnavailable, "network manager not available")
		return
	}

	conns, err := h.net.Connections()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get connections: %v", err))
		return
	}

	// Format as lines for backward compatibility.
	var lines []string
	lines = append(lines, "Proto\tLocal\tPeer\tState")
	for _, c := range conns {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s", c.Protocol, c.LocalAddr, c.PeerAddr, c.State))
	}
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
	if h.wgOps == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	writeJSON(w, http.StatusOK, h.wgOps.ListPeers())
}

func (h *handlers) addWGPeer(w http.ResponseWriter, r *http.Request) {
	if h.wgOps == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	var peer driver.WGPeer
	if err := readJSON(r, &peer); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.wgOps.AddPeer(peer); err != nil {
		if ops.IsConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, peer)
}

func (h *handlers) removeWGPeer(w http.ResponseWriter, r *http.Request) {
	if h.wgOps == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	pubkey := r.PathValue("pubkey")
	if err := h.wgOps.RemovePeer(pubkey); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (h *handlers) pruneWGPeers(w http.ResponseWriter, r *http.Request) {
	if h.wgOps == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	var body struct {
		MaxAgeSeconds int `json:"max_age_seconds"`
	}
	// Body is optional — default to 0 (prune never-handshaked only).
	_ = readJSON(r, &body)
	maxAge := time.Duration(body.MaxAgeSeconds) * time.Second
	pruned, err := h.wgOps.PruneStalePeers(maxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pruned": pruned,
		"count":  len(pruned),
	})
}

func (h *handlers) generateWGClientConfig(w http.ResponseWriter, r *http.Request) {
	if h.wgOps == nil {
		writeError(w, http.StatusServiceUnavailable, "wireguard not configured")
		return
	}
	var body struct {
		PublicKey      string `json:"public_key"`
		ServerEndpoint string `json:"server_endpoint"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, clientPubKey, err := h.wgOps.GenerateClientConfig(body.PublicKey, body.ServerEndpoint)
	if err != nil {
		if ops.IsNotFound(err) {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"config":     configText,
		"public_key": clientPubKey,
	})
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
	result, err := h.ops.PathTest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Explain ---

func (h *handlers) explainPath(w http.ResponseWriter, r *http.Request) {
	var req compiler.PathTestRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.ops.Explain(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
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
	if limit > 1000 {
		limit = 1000
	}
	entries, err := h.ops.ListAuditLog(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []config.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// --- Performance ---

func (h *handlers) perfNIC(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var nics []backend.NICInfo
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		// In sysfs, real interfaces are symlinks to directories.
		// Non-interface entries (e.g. bonding_masters) are plain files.
		fi, err := os.Stat(filepath.Join("/sys/class/net", name))
		if err != nil || !fi.IsDir() {
			continue
		}
		info, err := h.net.NICInfo(name)
		if err != nil {
			continue
		}
		nics = append(nics, *info)
	}
	if nics == nil {
		nics = []backend.NICInfo{}
	}
	writeJSON(w, http.StatusOK, nics)
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

// --- MTU handlers ---

type mtuHandlers struct {
	mgr   *service.MTUManager
	store *config.Store
}

func (h *mtuHandlers) mtuStatus(w http.ResponseWriter, r *http.Request) {
	zones, err := h.store.ListZones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.mgr.GetMTUStatus(zones))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FRRouting provides dynamic routing capabilities (BGP, OSPF) as a managed
// service via FRRouting (FRR). FRR is the industry-standard open-source
// routing suite that implements BGP, OSPF, and other routing protocols.
//
// This allows the Gatekeeper firewall to participate in dynamic routing with
// upstream providers or adjacent routers, which is essential for multi-homed
// networks, ISP peering, and enterprise deployments.
type FRRouting struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

// BGPNeighbor represents a BGP peer configuration.
type BGPNeighbor struct {
	Address   string `json:"address"`
	RemoteASN string `json:"remote_asn"`
	Desc      string `json:"description"`
	Password  string `json:"password,omitempty"`
}

// OSPFArea represents an OSPF area with its associated networks.
type OSPFArea struct {
	AreaID   string   `json:"area_id"`
	Networks []string `json:"networks"`
}

// NewFRRouting creates a new FRRouting service instance. The confDir is the
// directory where generated configuration fragments are staged before being
// written to /etc/frr/.
func NewFRRouting(confDir string) *FRRouting {
	return &FRRouting{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (f *FRRouting) Name() string           { return "frrouting" }
func (f *FRRouting) DisplayName() string    { return "FRRouting (Dynamic Routing)" }
func (f *FRRouting) Category() string       { return "network" }
func (f *FRRouting) Dependencies() []string { return nil }

func (f *FRRouting) Description() string {
	return "Dynamic routing service using FRRouting (FRR). Supports BGP and OSPF for peering with upstream routers, ISPs, and adjacent networks."
}

func (f *FRRouting) DefaultConfig() map[string]string {
	return map[string]string{
		"mode":              "bgp",
		"router_id":         "",
		"bgp_asn":           "65000",
		"bgp_neighbors":     "[]",
		"bgp_networks":      "[]",
		"bgp_redistribute":  "",
		"ospf_areas":        "[]",
		"ospf_redistribute": "",
		"log_level":         "informational",
		"graceful_restart":  "true",
	}
}

func (f *FRRouting) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"mode":              {Description: "Routing mode: bgp, ospf, or both", Default: "bgp", Required: true, Type: "string"},
		"router_id":         {Description: "Router ID in IP address format (e.g. 10.0.0.1)", Required: true, Type: "string"},
		"bgp_asn":           {Description: "Local BGP Autonomous System Number", Default: "65000", Type: "string"},
		"bgp_neighbors":     {Description: "JSON array of BGP neighbors: [{address, remote_asn, description, password}]", Default: "[]", Type: "string"},
		"bgp_networks":      {Description: "JSON array of CIDR networks to advertise via BGP", Default: "[]", Type: "string"},
		"bgp_redistribute":  {Description: "Routes to redistribute into BGP (comma-separated: connected, static, ospf)", Type: "string"},
		"ospf_areas":        {Description: "JSON array of OSPF areas: [{area_id, networks: [CIDRs]}]", Default: "[]", Type: "string"},
		"ospf_redistribute": {Description: "Routes to redistribute into OSPF (comma-separated: connected, static, bgp)", Type: "string"},
		"log_level":         {Description: "FRR log level: informational, debugging, warnings, errors", Default: "informational", Type: "string"},
		"graceful_restart":  {Description: "Enable graceful restart for hitless protocol convergence", Default: "true", Type: "bool"},
	}
}

func (f *FRRouting) Validate(cfg map[string]string) error {
	// Validate mode.
	mode := cfg["mode"]
	if mode != "bgp" && mode != "ospf" && mode != "both" {
		return fmt.Errorf("invalid mode %q: must be bgp, ospf, or both", mode)
	}

	// Validate router_id is a valid IP.
	routerID := cfg["router_id"]
	if routerID == "" {
		return fmt.Errorf("router_id is required")
	}
	if ip := net.ParseIP(routerID); ip == nil {
		return fmt.Errorf("invalid router_id %q: must be a valid IP address", routerID)
	}

	// Validate log level.
	logLevel := cfg["log_level"]
	if logLevel != "" {
		validLevels := map[string]bool{
			"informational": true,
			"debugging":     true,
			"warnings":      true,
			"errors":        true,
		}
		if !validLevels[logLevel] {
			return fmt.Errorf("invalid log_level %q: must be informational, debugging, warnings, or errors", logLevel)
		}
	}

	// Validate graceful_restart.
	if gr := cfg["graceful_restart"]; gr != "" && gr != "true" && gr != "false" {
		return fmt.Errorf("invalid graceful_restart %q: must be true or false", gr)
	}

	// Validate BGP-specific fields when BGP is active.
	if mode == "bgp" || mode == "both" {
		if err := f.validateBGP(cfg); err != nil {
			return err
		}
	}

	// Validate OSPF-specific fields when OSPF is active.
	if mode == "ospf" || mode == "both" {
		if err := f.validateOSPF(cfg); err != nil {
			return err
		}
	}

	// Validate redistribute values.
	if err := f.validateRedistribute(cfg["bgp_redistribute"], "bgp_redistribute", []string{"connected", "static", "ospf"}); err != nil {
		return err
	}
	if err := f.validateRedistribute(cfg["ospf_redistribute"], "ospf_redistribute", []string{"connected", "static", "bgp"}); err != nil {
		return err
	}

	return nil
}

func (f *FRRouting) validateBGP(cfg map[string]string) error {
	// Validate ASN.
	asnStr := cfg["bgp_asn"]
	if asnStr == "" {
		return fmt.Errorf("bgp_asn is required when mode includes BGP")
	}
	asn, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil || asn == 0 {
		return fmt.Errorf("invalid bgp_asn %q: must be a positive integer", asnStr)
	}

	// Validate neighbors JSON.
	if raw := cfg["bgp_neighbors"]; raw != "" && raw != "[]" {
		var neighbors []BGPNeighbor
		if err := json.Unmarshal([]byte(raw), &neighbors); err != nil {
			return fmt.Errorf("invalid bgp_neighbors JSON: %w", err)
		}
		for i, n := range neighbors {
			if ip := net.ParseIP(n.Address); ip == nil {
				return fmt.Errorf("bgp_neighbors[%d]: invalid address %q", i, n.Address)
			}
			if _, err := strconv.ParseUint(n.RemoteASN, 10, 32); err != nil {
				return fmt.Errorf("bgp_neighbors[%d]: invalid remote_asn %q", i, n.RemoteASN)
			}
		}
	}

	// Validate networks JSON.
	if raw := cfg["bgp_networks"]; raw != "" && raw != "[]" {
		var networks []string
		if err := json.Unmarshal([]byte(raw), &networks); err != nil {
			return fmt.Errorf("invalid bgp_networks JSON: %w", err)
		}
		for i, cidr := range networks {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("bgp_networks[%d]: invalid CIDR %q: %w", i, cidr, err)
			}
		}
	}

	return nil
}

func (f *FRRouting) validateOSPF(cfg map[string]string) error {
	if raw := cfg["ospf_areas"]; raw != "" && raw != "[]" {
		var areas []OSPFArea
		if err := json.Unmarshal([]byte(raw), &areas); err != nil {
			return fmt.Errorf("invalid ospf_areas JSON: %w", err)
		}
		for i, a := range areas {
			if ip := net.ParseIP(a.AreaID); ip == nil {
				// Also accept plain integers like "0".
				if _, err := strconv.ParseUint(a.AreaID, 10, 32); err != nil {
					return fmt.Errorf("ospf_areas[%d]: invalid area_id %q (use dotted IP or integer)", i, a.AreaID)
				}
			}
			if len(a.Networks) == 0 {
				return fmt.Errorf("ospf_areas[%d]: at least one network is required", i)
			}
			for j, cidr := range a.Networks {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					return fmt.Errorf("ospf_areas[%d].networks[%d]: invalid CIDR %q: %w", i, j, cidr, err)
				}
			}
		}
	}
	return nil
}

func (f *FRRouting) validateRedistribute(value, field string, allowed []string) error {
	if value == "" {
		return nil
	}
	validSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		validSet[a] = true
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !validSet[item] {
			return fmt.Errorf("invalid %s value %q: allowed values are %s", field, item, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func (f *FRRouting) Start(cfg map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg

	if err := os.MkdirAll(f.confDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Generate the daemons file to enable the correct FRR daemons.
	if err := f.generateDaemonsFile(); err != nil {
		return err
	}

	// Generate the unified frr.conf.
	if err := f.generateFRRConf(); err != nil {
		return err
	}

	// Copy generated configs to /etc/frr/.
	if err := f.installConfigs(); err != nil {
		return err
	}

	// Start FRR.
	if err := Proc.Restart("frr"); err != nil {
		return fmt.Errorf("start frr: %w", err)
	}

	f.state = StateRunning
	slog.Info("frrouting started", "mode", cfg["mode"], "router_id", cfg["router_id"])
	return nil
}

func (f *FRRouting) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := Proc.Stop("frr"); err != nil {
		return fmt.Errorf("stop frr: %w", err)
	}

	f.state = StateStopped
	slog.Info("frrouting stopped")
	return nil
}

func (f *FRRouting) Reload(cfg map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg

	// Regenerate the daemons file (in case mode changed).
	if err := f.generateDaemonsFile(); err != nil {
		return err
	}

	// Regenerate frr.conf.
	if err := f.generateFRRConf(); err != nil {
		return err
	}

	// Install configs to /etc/frr/.
	if err := f.installConfigs(); err != nil {
		return err
	}

	// Try reload first, fall back to restart.
	if err := Proc.Reload("frr"); err != nil {
		slog.Warn("frr reload failed, falling back to restart", "error", err)
		if err2 := Proc.Restart("frr"); err2 != nil {
			return fmt.Errorf("restart frr: %w", err2)
		}
	}

	slog.Info("frrouting reloaded", "mode", cfg["mode"])
	return nil
}

func (f *FRRouting) Status() State {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.state != StateRunning {
		return f.state
	}

	// Verify FRR is actually running via ProcessManager.
	status, err := Proc.Status("frr")
	if err != nil || !status.Running {
		f.state = StateError
		return StateError
	}

	return StateRunning
}

// generateDaemonsFile writes the FRR daemons file that controls which routing
// daemons are started. Zebra is always enabled as it provides the routing
// table interface.
func (f *FRRouting) generateDaemonsFile() error {
	cfg := f.cfg
	mode := cfg["mode"]

	bgpd := "no"
	ospfd := "no"
	if mode == "bgp" || mode == "both" {
		bgpd = "yes"
	}
	if mode == "ospf" || mode == "both" {
		ospfd = "yes"
	}

	var b strings.Builder
	b.WriteString("# Gatekeeper FRR daemons config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")
	b.WriteString("zebra=yes\n")
	b.WriteString(fmt.Sprintf("bgpd=%s\n", bgpd))
	b.WriteString(fmt.Sprintf("ospfd=%s\n", ospfd))
	b.WriteString("ospf6d=no\n")
	b.WriteString("ripd=no\n")
	b.WriteString("ripngd=no\n")
	b.WriteString("isisd=no\n")
	b.WriteString("pimd=no\n")
	b.WriteString("ldpd=no\n")
	b.WriteString("nhrpd=no\n")
	b.WriteString("eigrpd=no\n")
	b.WriteString("babeld=no\n")
	b.WriteString("sharpd=no\n")
	b.WriteString("staticd=yes\n")
	b.WriteString("pbrd=no\n")
	b.WriteString("bfdd=no\n")
	b.WriteString("fabricd=no\n")
	b.WriteString("\nvtysh_enable=yes\n")
	b.WriteString("zebra_options=\"  -A 127.0.0.1 -s 90000000\"\n")
	b.WriteString("bgpd_options=\"  -A 127.0.0.1\"\n")
	b.WriteString("ospfd_options=\"  -A 127.0.0.1\"\n")
	b.WriteString("staticd_options=\"  -A 127.0.0.1\"\n")

	daemonsPath := filepath.Join(f.confDir, "daemons")
	if err := os.WriteFile(daemonsPath, []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("write daemons file: %w", err)
	}

	slog.Info("frr daemons file generated", "path", daemonsPath)
	return nil
}

// generateFRRConf builds the unified frr.conf from the service configuration.
func (f *FRRouting) generateFRRConf() error {
	cfg := f.cfg
	mode := cfg["mode"]

	var b strings.Builder
	b.WriteString("! Gatekeeper FRR config — auto-generated\n")
	b.WriteString("! DO NOT EDIT — managed by gatekeeperd\n!\n")
	b.WriteString("frr version 8.5\n")
	b.WriteString("frr defaults traditional\n")

	// Logging.
	logLevel := cfg["log_level"]
	if logLevel == "" {
		logLevel = "informational"
	}
	b.WriteString(fmt.Sprintf("log syslog %s\n", logLevel))
	b.WriteString(fmt.Sprintf("log file /var/log/frr/frr.log %s\n", logLevel))

	// Hostname and router-id.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "gatekeeper"
	}
	b.WriteString(fmt.Sprintf("hostname %s\n", hostname))
	b.WriteString("service integrated-vtysh-config\n!\n")

	// Zebra configuration.
	b.WriteString("ip forwarding\n")
	b.WriteString("ipv6 forwarding\n!\n")

	// BGP configuration.
	if mode == "bgp" || mode == "both" {
		f.writeBGPConfig(&b, cfg)
	}

	// OSPF configuration.
	if mode == "ospf" || mode == "both" {
		f.writeOSPFConfig(&b, cfg)
	}

	b.WriteString("!\nline vty\n!\n")

	confPath := filepath.Join(f.confDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("write frr.conf: %w", err)
	}

	slog.Info("frr.conf generated", "path", confPath)
	return nil
}

// writeBGPConfig appends the BGP router configuration block.
func (f *FRRouting) writeBGPConfig(b *strings.Builder, cfg map[string]string) {
	asn := cfg["bgp_asn"]
	routerID := cfg["router_id"]
	graceful := cfg["graceful_restart"] == "true"

	b.WriteString(fmt.Sprintf("router bgp %s\n", asn))
	b.WriteString(fmt.Sprintf(" bgp router-id %s\n", routerID))
	b.WriteString(" bgp log-neighbor-changes\n")
	b.WriteString(" no bgp ebgp-requires-policy\n")

	if graceful {
		b.WriteString(" bgp graceful-restart\n")
	}

	// Neighbors.
	if raw := cfg["bgp_neighbors"]; raw != "" && raw != "[]" {
		var neighbors []BGPNeighbor
		if err := json.Unmarshal([]byte(raw), &neighbors); err == nil {
			for _, n := range neighbors {
				b.WriteString(fmt.Sprintf(" neighbor %s remote-as %s\n", n.Address, n.RemoteASN))
				if n.Desc != "" {
					b.WriteString(fmt.Sprintf(" neighbor %s description %s\n", n.Address, n.Desc))
				}
				if n.Password != "" {
					b.WriteString(fmt.Sprintf(" neighbor %s password %s\n", n.Address, n.Password))
				}
			}
		}
	}

	// Address family IPv4 unicast.
	b.WriteString(" !\n")
	b.WriteString(" address-family ipv4 unicast\n")

	// Networks to advertise.
	if raw := cfg["bgp_networks"]; raw != "" && raw != "[]" {
		var networks []string
		if err := json.Unmarshal([]byte(raw), &networks); err == nil {
			for _, cidr := range networks {
				b.WriteString(fmt.Sprintf("  network %s\n", cidr))
			}
		}
	}

	// Redistribution.
	if redist := cfg["bgp_redistribute"]; redist != "" {
		for _, r := range strings.Split(redist, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				b.WriteString(fmt.Sprintf("  redistribute %s\n", r))
			}
		}
	}

	// Activate neighbors in address family.
	if raw := cfg["bgp_neighbors"]; raw != "" && raw != "[]" {
		var neighbors []BGPNeighbor
		if err := json.Unmarshal([]byte(raw), &neighbors); err == nil {
			for _, n := range neighbors {
				b.WriteString(fmt.Sprintf("  neighbor %s activate\n", n.Address))
			}
		}
	}

	b.WriteString(" exit-address-family\n")
	b.WriteString("!\n")
}

// writeOSPFConfig appends the OSPF router configuration block.
func (f *FRRouting) writeOSPFConfig(b *strings.Builder, cfg map[string]string) {
	routerID := cfg["router_id"]
	graceful := cfg["graceful_restart"] == "true"

	b.WriteString("router ospf\n")
	b.WriteString(fmt.Sprintf(" ospf router-id %s\n", routerID))
	b.WriteString(" ospf log-adjacency-changes\n")

	if graceful {
		b.WriteString(" graceful-restart\n")
	}

	// Areas and networks.
	if raw := cfg["ospf_areas"]; raw != "" && raw != "[]" {
		var areas []OSPFArea
		if err := json.Unmarshal([]byte(raw), &areas); err == nil {
			for _, a := range areas {
				for _, cidr := range a.Networks {
					b.WriteString(fmt.Sprintf(" network %s area %s\n", cidr, a.AreaID))
				}
			}
		}
	}

	// Redistribution.
	if redist := cfg["ospf_redistribute"]; redist != "" {
		for _, r := range strings.Split(redist, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				b.WriteString(fmt.Sprintf(" redistribute %s\n", r))
			}
		}
	}

	b.WriteString("!\n")
}

// installConfigs copies the generated config files from the staging directory
// to /etc/frr/ where FRR expects them.
func (f *FRRouting) installConfigs() error {
	frrDir := "/etc/frr"
	if err := os.MkdirAll(frrDir, 0o755); err != nil {
		return fmt.Errorf("create /etc/frr: %w", err)
	}

	files := []string{"frr.conf", "daemons"}
	for _, name := range files {
		src := filepath.Join(f.confDir, name)
		dst := filepath.Join(frrDir, name)

		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read staged %s: %w", name, err)
		}
		if err := os.WriteFile(dst, data, 0o640); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}

	// Ensure ownership is correct for the frr user.
	for _, name := range files {
		dst := filepath.Join(frrDir, name)
		if uid, gid, err := lookupUser("frr"); err == nil {
			if err := os.Chown(dst, uid, gid); err != nil {
				slog.Warn("chown frr config failed", "file", dst, "error", err)
			}
		} else {
			slog.Warn("frr user not found, skipping chown", "error", err)
		}
	}

	return nil
}

func lookupUser(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

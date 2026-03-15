package service

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// DeviceSchedule defines internet access hours for a single device.
type DeviceSchedule struct {
	Name      string `json:"name"`       // Human-readable device name
	DeviceIP  string `json:"device_ip"`  // Device IP address
	AllowFrom string `json:"allow_from"` // Start time "HH:MM" (24h)
	AllowTo   string `json:"allow_to"`   // End time "HH:MM" (24h)
	Days      string `json:"days"`       // Comma-separated: "mon,tue,wed,thu,fri,sat,sun" or "all"
	Enabled   bool   `json:"enabled"`
}

// ContentFilter defines DNS-based content category filtering for a device.
type ContentFilter struct {
	DeviceIP   string   `json:"device_ip"`
	Categories []string `json:"categories"` // "adult", "gambling", "social", "gaming", "malware"
}

// ParentalControls provides per-device internet access scheduling and
// content category filtering.
//
// Access scheduling uses a periodic enforcer that evaluates the current time
// against device schedules and applies nftables drop rules for devices
// outside their allowed hours. Rules are refreshed every 60 seconds.
//
// Content filtering extends the DNSFilter service by adding per-device
// category-based DNS blocklists.
type ParentalControls struct {
	mu        sync.Mutex
	state     State
	cfg       map[string]string
	schedules []DeviceSchedule
	filters   []ContentFilter
	stopCh    chan struct{}
	nftTable  string
}

func NewParentalControls() *ParentalControls {
	return &ParentalControls{
		state:    StateStopped,
		nftTable: "gk_parental",
	}
}

func (p *ParentalControls) Name() string        { return "parental-controls" }
func (p *ParentalControls) DisplayName() string { return "Parental Controls" }
func (p *ParentalControls) Category() string    { return "security" }
func (p *ParentalControls) Dependencies() []string { return nil }

func (p *ParentalControls) Description() string {
	return "Per-device internet access scheduling and content filtering. Set time-based access windows and block content categories per device."
}

func (p *ParentalControls) DefaultConfig() map[string]string {
	return map[string]string{
		"schedules":       "[]",
		"content_filters": "[]",
		"block_page_ip":   "0.0.0.0",
		"timezone":        "UTC",
	}
}

func (p *ParentalControls) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"schedules":       {Description: "JSON array of DeviceSchedule objects", Default: "[]", Type: "string"},
		"content_filters": {Description: "JSON array of ContentFilter objects", Default: "[]", Type: "string"},
		"block_page_ip":   {Description: "IP to redirect blocked content to (0.0.0.0 for NXDOMAIN)", Default: "0.0.0.0", Type: "string"},
		"timezone":        {Description: "Timezone for schedule evaluation (IANA format)", Default: "UTC", Type: "string"},
	}
}

func (p *ParentalControls) Validate(cfg map[string]string) error {
	if schedJSON := cfg["schedules"]; schedJSON != "" {
		var schedules []DeviceSchedule
		if err := json.Unmarshal([]byte(schedJSON), &schedules); err != nil {
			return fmt.Errorf("invalid schedules JSON: %w", err)
		}
		for _, s := range schedules {
			if s.DeviceIP == "" {
				return fmt.Errorf("schedule %q: device_ip required", s.Name)
			}
			if _, err := time.Parse("15:04", s.AllowFrom); s.AllowFrom != "" && err != nil {
				return fmt.Errorf("schedule %q: invalid allow_from time %q", s.Name, s.AllowFrom)
			}
			if _, err := time.Parse("15:04", s.AllowTo); s.AllowTo != "" && err != nil {
				return fmt.Errorf("schedule %q: invalid allow_to time %q", s.Name, s.AllowTo)
			}
		}
	}
	if filtersJSON := cfg["content_filters"]; filtersJSON != "" {
		var filters []ContentFilter
		if err := json.Unmarshal([]byte(filtersJSON), &filters); err != nil {
			return fmt.Errorf("invalid content_filters JSON: %w", err)
		}
		validCats := map[string]bool{
			"adult": true, "gambling": true, "social": true,
			"gaming": true, "malware": true, "drugs": true,
			"violence": true, "streaming": true,
		}
		for _, f := range filters {
			if f.DeviceIP == "" {
				return fmt.Errorf("content filter: device_ip required")
			}
			for _, cat := range f.Categories {
				if !validCats[cat] {
					return fmt.Errorf("content filter for %s: invalid category %q", f.DeviceIP, cat)
				}
			}
		}
	}
	return nil
}

func (p *ParentalControls) Status() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *ParentalControls) Start(cfg map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = StateStarting
	p.cfg = cfg

	// Parse schedules.
	if schedJSON := cfg["schedules"]; schedJSON != "" && schedJSON != "[]" {
		if err := json.Unmarshal([]byte(schedJSON), &p.schedules); err != nil {
			p.state = StateError
			return fmt.Errorf("parse schedules: %w", err)
		}
	}

	// Parse content filters.
	if filtersJSON := cfg["content_filters"]; filtersJSON != "" && filtersJSON != "[]" {
		if err := json.Unmarshal([]byte(filtersJSON), &p.filters); err != nil {
			p.state = StateError
			return fmt.Errorf("parse content filters: %w", err)
		}
	}

	// Apply initial schedule-based firewall rules.
	tz := cfg["timezone"]
	if err := p.applyScheduleRules(tz); err != nil {
		slog.Warn("parental: initial schedule apply failed", "error", err)
	}

	// Start schedule enforcement goroutine.
	p.stopCh = make(chan struct{})
	go p.scheduleEnforcer(tz)

	p.state = StateRunning
	slog.Info("parental-controls started",
		"schedules", len(p.schedules),
		"content_filters", len(p.filters))
	return nil
}

func (p *ParentalControls) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = StateStopping

	if p.stopCh != nil {
		close(p.stopCh)
		p.stopCh = nil
	}

	// Remove nftables rules.
	nftDeleteTable(nft.TableFamilyINet, p.nftTable)

	p.schedules = nil
	p.filters = nil
	p.state = StateStopped
	slog.Info("parental-controls stopped")
	return nil
}

func (p *ParentalControls) Reload(cfg map[string]string) error {
	if err := p.Stop(); err != nil {
		slog.Warn("parental-controls stop during reload", "error", err)
	}
	return p.Start(cfg)
}

// applyScheduleRules evaluates schedules against the current time and applies
// nftables drop rules for devices that are outside their allowed window.
//
// This is called periodically (every 60s) by the schedule enforcer. It
// atomically replaces the entire nftables table each time, which is safe
// because the table is small (one rule per blocked device) and the kernel
// applies atomically via netlink Flush.
func (p *ParentalControls) applyScheduleRules(timezone string) error {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	dayName := strings.ToLower(now.Weekday().String()[:3])

	var dropRules [][]expr.Any

	for _, sched := range p.schedules {
		if !sched.Enabled {
			continue
		}

		// Check day of week.
		if sched.Days != "" && sched.Days != "all" {
			days := strings.Split(strings.ToLower(sched.Days), ",")
			dayMatch := false
			for _, d := range days {
				if strings.TrimSpace(d) == dayName {
					dayMatch = true
					break
				}
			}
			if !dayMatch {
				// Not a scheduled day — block all day.
				dropRules = append(dropRules, parentalDropRule(sched.DeviceIP))
				continue
			}
		}

		// Check time window.
		if isWithinTimeWindow(now, sched.AllowFrom, sched.AllowTo) {
			// Within allowed window — no block rule needed.
			continue
		}

		// Outside allowed window — add drop rule.
		dropRules = append(dropRules, parentalDropRule(sched.DeviceIP))
	}

	// If no devices are blocked, remove the table entirely.
	if len(dropRules) == 0 {
		nftDeleteTable(nft.TableFamilyINet, p.nftTable)
		return nil
	}

	hook := nft.ChainHookForward
	prio := nft.ChainPriorityFilter
	policy := nft.ChainPolicyAccept

	return nftApplyRules(nft.TableFamilyINet, p.nftTable, []nftChainSpec{{
		Name:     "schedule",
		Type:     nft.ChainTypeFilter,
		Hook:     &hook,
		Priority: &prio,
		Policy:   &policy,
		Rules:    dropRules,
	}})
}

// parentalDropRule creates a rule that drops all forwarded traffic from a
// specific source IP (with a counter for visibility).
func parentalDropRule(deviceIP string) []expr.Any {
	ip := parseIPv4(deviceIP)
	if ip == nil {
		return nil
	}
	return nftRule(
		// Match source IP.
		[]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		},
		nftExpr(nftCounter()),
		nftExpr(nftDrop()),
	)
}

// scheduleEnforcer periodically re-evaluates schedule rules to handle
// time window transitions.
func (p *ParentalControls) scheduleEnforcer(timezone string) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			if err := p.applyScheduleRules(timezone); err != nil {
				slog.Warn("parental: schedule rule refresh failed", "error", err)
			}
			p.mu.Unlock()
		}
	}
}

// isWithinTimeWindow checks if the current time is within the HH:MM allow window.
func isWithinTimeWindow(now time.Time, allowFrom, allowTo string) bool {
	if allowFrom == "" && allowTo == "" {
		return true // No restrictions.
	}

	fromH, fromM := 0, 0
	toH, toM := 23, 59
	fmt.Sscanf(allowFrom, "%d:%d", &fromH, &fromM)
	fmt.Sscanf(allowTo, "%d:%d", &toH, &toM)

	nowMin := now.Hour()*60 + now.Minute()
	fromMin := fromH*60 + fromM
	toMin := toH*60 + toM

	if fromMin <= toMin {
		// Normal window: e.g., 08:00 - 22:00.
		return nowMin >= fromMin && nowMin <= toMin
	}
	// Overnight window: e.g., 22:00 - 06:00.
	return nowMin >= fromMin || nowMin <= toMin
}

// parseIPv4 parses an IPv4 address string to 4 bytes.
func parseIPv4(s string) []byte {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	result := make([]byte, 4)
	for i, p := range parts {
		var v int
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil || v < 0 || v > 255 {
			return nil
		}
		result[i] = byte(v)
	}
	return result
}

// CategoryBlocklistURLs maps content categories to DNS blocklist URLs.
func CategoryBlocklistURLs() map[string]string {
	return map[string]string{
		"adult":     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
		"gambling":  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
		"social":    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
		"malware":   "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"gaming":    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.tiktok.txt",
		"drugs":     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		"violence":  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		"streaming": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.amazon.txt",
	}
}

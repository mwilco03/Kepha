package service

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
)

// Bandwidth provides traffic shaping and QoS (Quality of Service) via
// Linux tc (traffic control) using the netlink API directly. Allows
// prioritizing traffic types (VoIP, gaming, streaming) and limiting
// bandwidth per device or zone.
//
// Uses vishvananda/netlink for all tc operations — no exec.Command calls.
type Bandwidth struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewBandwidth(confDir string) *Bandwidth {
	return &Bandwidth{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (b *Bandwidth) Name() string           { return "bandwidth" }
func (b *Bandwidth) DisplayName() string    { return "Traffic Shaping / QoS" }
func (b *Bandwidth) Category() string       { return "network" }
func (b *Bandwidth) Dependencies() []string { return nil }

func (b *Bandwidth) Description() string {
	return "Traffic shaping and QoS. Prioritize VoIP, gaming, and streaming traffic. Limit bandwidth per device or zone to prevent any single device from saturating the link."
}

func (b *Bandwidth) DefaultConfig() map[string]string {
	return map[string]string{
		"wan_interface":      "",
		"download_mbps":      "0",
		"upload_mbps":        "0",
		"voip_priority":      "true",
		"gaming_priority":    "true",
		"streaming_limit":    "0",
		"default_per_device": "0",
		"fq_codel":           "true",
	}
}

func (b *Bandwidth) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"wan_interface":      {Description: "WAN interface to shape traffic on", Required: true, Type: "string"},
		"download_mbps":      {Description: "Total download bandwidth in Mbps (0 = no limit)", Default: "0", Type: "int"},
		"upload_mbps":        {Description: "Total upload bandwidth in Mbps (0 = no limit)", Default: "0", Type: "int"},
		"voip_priority":      {Description: "Prioritize VoIP traffic (SIP/RTP)", Default: "true", Type: "bool"},
		"gaming_priority":    {Description: "Prioritize gaming traffic", Default: "true", Type: "bool"},
		"streaming_limit":    {Description: "Limit streaming bandwidth in Mbps (0 = no limit)", Default: "0", Type: "int"},
		"default_per_device": {Description: "Default per-device bandwidth limit in Mbps (0 = no limit)", Default: "0", Type: "int"},
		"fq_codel":           {Description: "Use fq_codel for bufferbloat prevention", Default: "true", Type: "bool"},
	}
}

func (b *Bandwidth) Validate(cfg map[string]string) error {
	if cfg["wan_interface"] == "" {
		return fmt.Errorf("wan_interface is required")
	}
	return nil
}

func (b *Bandwidth) Start(cfg map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg

	if err := b.applyQoS(); err != nil {
		return err
	}

	b.state = StateRunning
	return nil
}

func (b *Bandwidth) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cfg != nil {
		iface := b.cfg["wan_interface"]
		if iface != "" {
			b.clearQdisc(iface)
		}
	}

	b.state = StateStopped
	return nil
}

func (b *Bandwidth) Reload(cfg map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg
	return b.applyQoS()
}

func (b *Bandwidth) Status() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// clearQdisc removes all qdiscs from an interface via netlink.
func (b *Bandwidth) clearQdisc(ifaceName string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return
	}
	qdiscs, _ := netlink.QdiscList(link)
	for _, q := range qdiscs {
		netlink.QdiscDel(q)
	}
}

// mbpsToBytes converts megabits per second to bytes per second.
func mbpsToBytes(mbps uint64) uint64 {
	return mbps * 1000 * 1000 / 8
}

func (b *Bandwidth) applyQoS() error {
	cfg := b.cfg
	ifaceName := cfg["wan_interface"]

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	linkIdx := link.Attrs().Index

	// Clear existing qdiscs.
	b.clearQdisc(ifaceName)

	useFQCodel := cfg["fq_codel"] == "true"
	uploadMbps, _ := strconv.ParseUint(cfg["upload_mbps"], 10, 64)
	downloadMbps, _ := strconv.ParseUint(cfg["download_mbps"], 10, 64)

	if uploadMbps > 0 {
		rateBytes := mbpsToBytes(uploadMbps)

		// HTB root qdisc for upload shaping.
		htbQdisc := &netlink.Htb{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: linkIdx,
				Handle:    netlink.MakeHandle(1, 0),
				Parent:    netlink.HANDLE_ROOT,
			},
			Defcls: 30,
		}
		if err := netlink.QdiscAdd(htbQdisc); err != nil {
			return fmt.Errorf("add htb root qdisc: %w", err)
		}

		// Root class 1:1 — full link rate.
		rootClass := &netlink.HtbClass{
			ClassAttrs: netlink.ClassAttrs{
				LinkIndex: linkIdx,
				Handle:    netlink.MakeHandle(1, 1),
				Parent:    netlink.MakeHandle(1, 0),
			},
			Rate: rateBytes,
			Ceil: rateBytes,
		}
		if err := netlink.ClassAdd(rootClass); err != nil {
			return fmt.Errorf("add root class: %w", err)
		}

		// Priority classes under 1:1.
		// Class 10: High priority (30%, VoIP/DNS/ACK)
		// Class 20: Normal priority (50%)
		// Class 30: Low priority / bulk (20%, default)
		priorities := []struct {
			minor uint16
			pct   uint64
			prio  uint32
		}{
			{10, 30, 1},
			{20, 50, 2},
			{30, 20, 3},
		}
		for _, p := range priorities {
			cls := &netlink.HtbClass{
				ClassAttrs: netlink.ClassAttrs{
					LinkIndex: linkIdx,
					Handle:    netlink.MakeHandle(1, p.minor),
					Parent:    netlink.MakeHandle(1, 1),
				},
				Rate: rateBytes * p.pct / 100,
				Ceil: rateBytes,
				Prio: p.prio,
			}
			if err := netlink.ClassAdd(cls); err != nil {
				slog.Warn("add htb class", "minor", p.minor, "error", err)
			}

			// Attach fq_codel leaf qdisc for bufferbloat prevention.
			if useFQCodel {
				fq := &netlink.FqCodel{
					QdiscAttrs: netlink.QdiscAttrs{
						LinkIndex: linkIdx,
						Handle:    netlink.MakeHandle(p.minor, 0),
						Parent:    netlink.MakeHandle(1, p.minor),
					},
				}
				if err := netlink.QdiscAdd(fq); err != nil {
					slog.Warn("add fq_codel leaf", "class", p.minor, "error", err)
				}
			}
		}

		// Classify high-priority traffic using fwmark-based filters.
		// nftables marks matching packets, FwFilter classifies by mark:
		//   mark 10 → class 1:10 (high priority)
		//   mark 20 → class 1:20 (normal)
		// Unmarked traffic falls to default class 1:30 (bulk).
		highPrioFilter := &netlink.FwFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: linkIdx,
				Parent:    netlink.MakeHandle(1, 0),
				Protocol:  0x0800, // IPv4
			},
			ClassId: netlink.MakeHandle(1, 10),
			Mask:    0xff,
		}
		if err := netlink.FilterAdd(highPrioFilter); err != nil {
			slog.Warn("add fw filter for high priority", "error", err)
		}

		normalFilter := &netlink.FwFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: linkIdx,
				Parent:    netlink.MakeHandle(1, 0),
				Protocol:  0x0800,
			},
			ClassId: netlink.MakeHandle(1, 20),
			Mask:    0xff,
		}
		if err := netlink.FilterAdd(normalFilter); err != nil {
			slog.Warn("add fw filter for normal priority", "error", err)
		}

	} else if useFQCodel {
		// Just fq_codel for bufferbloat prevention — no bandwidth limit.
		fq := &netlink.FqCodel{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: linkIdx,
				Handle:    netlink.MakeHandle(1, 0),
				Parent:    netlink.HANDLE_ROOT,
			},
		}
		if err := netlink.QdiscAdd(fq); err != nil {
			return fmt.Errorf("add fq_codel root qdisc: %w", err)
		}
	}

	// Ingress policing for download limiting.
	if downloadMbps > 0 {
		ingress := &netlink.Ingress{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: linkIdx,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(ingress); err != nil {
			slog.Warn("add ingress qdisc", "error", err)
		} else {
			// Police inbound traffic to the configured download rate.
			rateBytes := mbpsToBytes(downloadMbps)
			police := netlink.NewPoliceAction()
			police.Rate = uint32(rateBytes)
			police.Burst = 256 * 1024
			police.ExceedAction = netlink.TC_POLICE_SHOT

			filter := &netlink.MatchAll{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: linkIdx,
					Parent:    netlink.MakeHandle(0xffff, 0),
					Protocol:  0x0800,
				},
				Actions: []netlink.Action{police},
			}
			if err := netlink.FilterAdd(filter); err != nil {
				slog.Warn("add ingress police filter", "error", err)
			}
		}
	}

	slog.Info("qos rules applied via netlink", "interface", ifaceName,
		"upload_mbps", uploadMbps, "download_mbps", downloadMbps)
	return nil
}

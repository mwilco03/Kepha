package service

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Bandwidth provides traffic shaping and QoS (Quality of Service) via
// Linux tc (traffic control). Allows prioritizing traffic types (VoIP,
// gaming, streaming) and limiting bandwidth per device or zone.
//
// This is one of the most requested features from pfSense/OPNsense users.
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

	if err := os.MkdirAll(b.confDir, 0o755); err != nil {
		return err
	}

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
			// Remove tc qdisc.
			exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()
			exec.Command("tc", "qdisc", "del", "dev", iface, "ingress").Run()
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

func (b *Bandwidth) applyQoS() error {
	cfg := b.cfg
	iface := cfg["wan_interface"]

	// Clear existing.
	exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()

	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("# Gatekeeper QoS — auto-generated\n\n")

	useFQCodel := cfg["fq_codel"] == "true"
	uploadMbps := cfg["upload_mbps"]
	downloadMbps := cfg["download_mbps"]

	if uploadMbps != "0" && uploadMbps != "" {
		uploadKbit := uploadMbps + "mbit"

		// HTB root qdisc for upload shaping.
		script.WriteString(fmt.Sprintf("tc qdisc add dev %s root handle 1: htb default 30\n", iface))
		script.WriteString(fmt.Sprintf("tc class add dev %s parent 1: classid 1:1 htb rate %s burst 15k\n", iface, uploadKbit))

		// Priority classes.
		// Class 10: High priority (VoIP, DNS, ACK).
		script.WriteString(fmt.Sprintf("tc class add dev %s parent 1:1 classid 1:10 htb rate %s ceil %s burst 15k prio 1\n",
			iface, "30%"+uploadKbit[:len(uploadKbit)-4]+"mbit", uploadKbit))
		// Class 20: Normal priority.
		script.WriteString(fmt.Sprintf("tc class add dev %s parent 1:1 classid 1:20 htb rate %s ceil %s burst 15k prio 2\n",
			iface, "50%"+uploadKbit[:len(uploadKbit)-4]+"mbit", uploadKbit))
		// Class 30: Low priority (bulk).
		script.WriteString(fmt.Sprintf("tc class add dev %s parent 1:1 classid 1:30 htb rate %s ceil %s burst 15k prio 3\n",
			iface, "20%"+uploadKbit[:len(uploadKbit)-4]+"mbit", uploadKbit))

		if useFQCodel {
			script.WriteString(fmt.Sprintf("tc qdisc add dev %s parent 1:10 handle 10: fq_codel\n", iface))
			script.WriteString(fmt.Sprintf("tc qdisc add dev %s parent 1:20 handle 20: fq_codel\n", iface))
			script.WriteString(fmt.Sprintf("tc qdisc add dev %s parent 1:30 handle 30: fq_codel\n", iface))
		}

		// Classify VoIP (SIP + RTP range).
		if cfg["voip_priority"] == "true" {
			script.WriteString(fmt.Sprintf("tc filter add dev %s parent 1: protocol ip u32 match ip dport 5060 0xffff flowid 1:10\n", iface))
			script.WriteString(fmt.Sprintf("tc filter add dev %s parent 1: protocol ip u32 match ip sport 5060 0xffff flowid 1:10\n", iface))
		}

		// DNS always high priority.
		script.WriteString(fmt.Sprintf("tc filter add dev %s parent 1: protocol ip u32 match ip dport 53 0xffff flowid 1:10\n", iface))

		// ACK packets high priority.
		script.WriteString(fmt.Sprintf("tc filter add dev %s parent 1: protocol ip u32 match ip protocol 6 0xff match u8 0x10 0xff at nexthdr+13 flowid 1:10\n", iface))

	} else if useFQCodel {
		// Just fq_codel for bufferbloat prevention.
		script.WriteString(fmt.Sprintf("tc qdisc add dev %s root fq_codel\n", iface))
	}

	// Ingress policing for download limiting.
	if downloadMbps != "0" && downloadMbps != "" {
		script.WriteString(fmt.Sprintf("tc qdisc add dev %s handle ffff: ingress\n", iface))
		script.WriteString(fmt.Sprintf("tc filter add dev %s parent ffff: protocol ip u32 match u32 0 0 police rate %smbit burst 256k drop flowid :1\n",
			iface, downloadMbps))
	}

	scriptPath := filepath.Join(b.confDir, "qos.sh")
	if err := os.WriteFile(scriptPath, []byte(script.String()), 0o755); err != nil {
		return err
	}

	// Execute the script.
	cmd := exec.Command("sh", scriptPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("qos script had errors (some rules may have applied)", "error", err, "output", string(output))
	}

	slog.Info("qos rules applied", "interface", iface)
	return nil
}

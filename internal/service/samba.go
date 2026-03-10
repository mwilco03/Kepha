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

// Samba provides SMB file sharing on the LAN.
// Common use cases: network backup target, shared media folder,
// printer sharing, and Time Machine-compatible backup for macOS.
type Samba struct {
	mu      sync.Mutex
	state   State
	confDir string
	cfg     map[string]string
}

func NewSamba(confDir string) *Samba {
	return &Samba{
		confDir: confDir,
		state:   StateStopped,
	}
}

func (s *Samba) Name() string           { return "samba" }
func (s *Samba) DisplayName() string    { return "Samba (SMB File Sharing)" }
func (s *Samba) Category() string       { return "sharing" }
func (s *Samba) Dependencies() []string { return nil }

func (s *Samba) Description() string {
	return "SMB/CIFS file sharing for LAN devices. Provides network shares for backup, media, and general file sharing with Windows, macOS, and Linux clients."
}

func (s *Samba) DefaultConfig() map[string]string {
	return map[string]string{
		"workgroup":      "WORKGROUP",
		"server_string":  "Gatekeeper File Server",
		"netbios_name":   "",
		"interfaces":     "",
		"share_path":     "/srv/samba/share",
		"share_name":     "shared",
		"share_comment":  "Gatekeeper Shared Files",
		"share_writable": "true",
		"share_guest_ok": "false",
		"valid_users":    "",
		"log_level":      "1",
		"max_log_size":   "1000",
		"min_protocol":   "SMB2",
		"time_machine":   "false",
		"tm_path":        "/srv/samba/timemachine",
		"tm_max_size":    "500G",
	}
}

func (s *Samba) ConfigSchema() map[string]ConfigField {
	return map[string]ConfigField{
		"workgroup":      {Description: "Windows workgroup name", Default: "WORKGROUP", Type: "string"},
		"server_string":  {Description: "Server description shown to clients", Default: "Gatekeeper File Server", Type: "string"},
		"netbios_name":   {Description: "NetBIOS name (empty = hostname)", Type: "string"},
		"interfaces":     {Description: "Interfaces to serve (comma-separated, empty = LAN)", Type: "string"},
		"share_path":     {Description: "Path to shared directory", Default: "/srv/samba/share", Required: true, Type: "path"},
		"share_name":     {Description: "Share name visible to clients", Default: "shared", Type: "string"},
		"share_comment":  {Description: "Share description", Default: "Gatekeeper Shared Files", Type: "string"},
		"share_writable": {Description: "Allow write access", Default: "true", Type: "bool"},
		"share_guest_ok": {Description: "Allow guest access (no password)", Default: "false", Type: "bool"},
		"valid_users":    {Description: "Comma-separated list of allowed users (empty = all)", Type: "string"},
		"log_level":      {Description: "Samba log verbosity (0-10)", Default: "1", Type: "int"},
		"max_log_size":   {Description: "Max log file size in KB", Default: "1000", Type: "int"},
		"min_protocol":   {Description: "Minimum SMB protocol version", Default: "SMB2", Type: "string"},
		"time_machine":   {Description: "Enable Time Machine backup share for macOS", Default: "false", Type: "bool"},
		"tm_path":        {Description: "Time Machine backup path", Default: "/srv/samba/timemachine", Type: "path"},
		"tm_max_size":    {Description: "Time Machine max backup size", Default: "500G", Type: "string"},
	}
}

func (s *Samba) Validate(cfg map[string]string) error {
	if path := cfg["share_path"]; path == "" {
		return fmt.Errorf("share_path is required")
	}
	proto := cfg["min_protocol"]
	if proto != "" && proto != "SMB2" && proto != "SMB3" && proto != "SMB2_10" && proto != "SMB3_00" && proto != "SMB3_11" {
		return fmt.Errorf("invalid min_protocol: %s (use SMB2, SMB2_10, SMB3, SMB3_00, or SMB3_11)", proto)
	}
	return nil
}

func (s *Samba) Start(cfg map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg

	// Create share directories.
	if path := cfg["share_path"]; path != "" {
		if err := os.MkdirAll(path, 0o775); err != nil {
			return fmt.Errorf("create share dir: %w", err)
		}
	}
	if cfg["time_machine"] == "true" {
		if path := cfg["tm_path"]; path != "" {
			if err := os.MkdirAll(path, 0o775); err != nil {
				return fmt.Errorf("create time machine dir: %w", err)
			}
		}
	}

	if err := s.generateConfig(); err != nil {
		return err
	}

	// Start smbd and nmbd.
	for _, svc := range []string{"smbd", "nmbd"} {
		cmd := exec.Command("systemctl", "start", svc)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("start %s: %s: %w", svc, string(output), err)
		}
	}

	s.state = StateRunning
	return nil
}

func (s *Samba) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, svc := range []string{"smbd", "nmbd"} {
		cmd := exec.Command("systemctl", "stop", svc)
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to stop samba service", "service", svc, "error", err, "output", string(output))
		}
	}

	s.state = StateStopped
	return nil
}

func (s *Samba) Reload(cfg map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg

	if err := s.generateConfig(); err != nil {
		return err
	}

	cmd := exec.Command("smbcontrol", "all", "reload-config")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reload samba: %s: %w", string(output), err)
	}
	return nil
}

func (s *Samba) Status() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Samba) generateConfig() error {
	cfg := s.cfg
	var b strings.Builder

	b.WriteString("# Gatekeeper Samba config — auto-generated\n")
	b.WriteString("# DO NOT EDIT — managed by gatekeeperd\n\n")

	b.WriteString("[global]\n")
	b.WriteString(fmt.Sprintf("  workgroup = %s\n", cfg["workgroup"]))
	b.WriteString(fmt.Sprintf("  server string = %s\n", cfg["server_string"]))
	if name := cfg["netbios_name"]; name != "" {
		b.WriteString(fmt.Sprintf("  netbios name = %s\n", name))
	}
	if ifaces := cfg["interfaces"]; ifaces != "" {
		b.WriteString(fmt.Sprintf("  interfaces = %s\n", strings.ReplaceAll(ifaces, ",", " ")))
		b.WriteString("  bind interfaces only = yes\n")
	}
	b.WriteString(fmt.Sprintf("  log level = %s\n", cfg["log_level"]))
	b.WriteString(fmt.Sprintf("  max log size = %s\n", cfg["max_log_size"]))
	b.WriteString(fmt.Sprintf("  server min protocol = %s\n", cfg["min_protocol"]))

	// Security settings.
	b.WriteString("  security = user\n")
	b.WriteString("  map to guest = Bad User\n")
	b.WriteString("  passdb backend = tdbsam\n")

	// Fruit extensions for macOS compatibility.
	b.WriteString("  vfs objects = fruit streams_xattr\n")
	b.WriteString("  fruit:metadata = stream\n")
	b.WriteString("  fruit:model = MacSamba\n")
	b.WriteString("  fruit:posix_rename = yes\n")
	b.WriteString("  fruit:veto_appledouble = no\n")
	b.WriteString("  fruit:nfs_aces = no\n")
	b.WriteString("  fruit:wipe_intentionally_left_blank_rfork = yes\n")
	b.WriteString("  fruit:delete_empty_adfiles = yes\n")

	b.WriteString("\n")

	// Main share.
	shareName := cfg["share_name"]
	if shareName == "" {
		shareName = "shared"
	}
	b.WriteString(fmt.Sprintf("[%s]\n", shareName))
	b.WriteString(fmt.Sprintf("  comment = %s\n", cfg["share_comment"]))
	b.WriteString(fmt.Sprintf("  path = %s\n", cfg["share_path"]))
	if cfg["share_writable"] == "true" {
		b.WriteString("  writable = yes\n")
	} else {
		b.WriteString("  writable = no\n")
	}
	if cfg["share_guest_ok"] == "true" {
		b.WriteString("  guest ok = yes\n")
	} else {
		b.WriteString("  guest ok = no\n")
	}
	if users := cfg["valid_users"]; users != "" {
		b.WriteString(fmt.Sprintf("  valid users = %s\n", strings.ReplaceAll(users, ",", " ")))
	}
	b.WriteString("  create mask = 0664\n")
	b.WriteString("  directory mask = 0775\n")

	// Time Machine share.
	if cfg["time_machine"] == "true" {
		b.WriteString("\n[TimeMachine]\n")
		b.WriteString("  comment = Time Machine Backups\n")
		b.WriteString(fmt.Sprintf("  path = %s\n", cfg["tm_path"]))
		b.WriteString("  writable = yes\n")
		b.WriteString("  guest ok = no\n")
		b.WriteString("  fruit:time machine = yes\n")
		if maxSize := cfg["tm_max_size"]; maxSize != "" {
			b.WriteString(fmt.Sprintf("  fruit:time machine max size = %s\n", maxSize))
		}
		b.WriteString("  create mask = 0600\n")
		b.WriteString("  directory mask = 0700\n")
	}

	confPath := filepath.Join(s.confDir, "smb.conf")
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write samba config: %w", err)
	}

	slog.Info("samba config generated", "path", confPath)
	return nil
}

package backend

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// OpenRCManager manages processes on Alpine Linux via OpenRC conventions.
// It does NOT shell out to rc-service — it reads /run PID files and
// sends signals directly via os.FindProcess + Signal.
//
// For service start/stop, it reads the init script to find the daemon binary
// and manages it directly. This is the primary (Alpine) process manager.
type OpenRCManager struct {
	// PIDDir is where PID files live (default: /run).
	PIDDir string
}

// NewOpenRCManager creates an OpenRC-based process manager.
func NewOpenRCManager() *OpenRCManager {
	return &OpenRCManager{
		PIDDir: "/run",
	}
}

// Start starts a service by executing its OpenRC init script.
func (m *OpenRCManager) Start(svc string) error {
	// Try rc-service first (Alpine OpenRC).
	initPath := filepath.Join("/etc/init.d", svc)
	if _, err := os.Stat(initPath); err != nil {
		return fmt.Errorf("init script not found: %s", initPath)
	}
	slog.Info("starting service via OpenRC", "service", svc)
	cmd := exec.Command(initPath, "start")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start %s: %s: %w", svc, string(output), err)
	}
	return nil
}

// Stop stops a service by finding its PID and sending SIGTERM.
func (m *OpenRCManager) Stop(service string) error {
	pid, err := m.FindProcess(service)
	if err != nil {
		return fmt.Errorf("find %s: %w", service, err)
	}
	if err := m.Signal(pid, SigTERM); err != nil {
		return fmt.Errorf("stop %s (pid %d): %w", service, pid, err)
	}

	// Wait briefly for clean shutdown.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !m.IsRunning(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running.
	return m.Signal(pid, SigKILL)
}

// Restart stops then starts a service.
func (m *OpenRCManager) Restart(service string) error {
	_ = m.Stop(service) // Ignore stop error (might not be running).
	return m.Start(service)
}

// Reload sends SIGHUP to a running service.
func (m *OpenRCManager) Reload(service string) error {
	pid, err := m.FindProcess(service)
	if err != nil {
		return fmt.Errorf("find %s for reload: %w", service, err)
	}
	return m.Signal(pid, SigHUP)
}

// Status returns the process status by checking its PID file and /proc.
func (m *OpenRCManager) Status(service string) (ProcessStatus, error) {
	pid, err := m.readPID(service)
	if err != nil {
		return ProcessStatus{Running: false}, nil
	}

	if !m.IsRunning(pid) {
		return ProcessStatus{Running: false, PID: pid}, nil
	}

	uptime, _ := m.processUptime(pid)
	return ProcessStatus{
		Running: true,
		PID:     pid,
		Uptime:  uptime,
	}, nil
}

// Signal sends a signal to a process by PID using native Go syscall.
func (m *OpenRCManager) Signal(pid int, sig ProcessSignal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	return p.Signal(syscall.Signal(sig))
}

// FindProcess finds a running process by name using /proc traversal.
// No pidof, no pgrep — pure /proc/[pid]/cmdline parsing.
func (m *OpenRCManager) FindProcess(name string) (int, error) {
	// First try PID file (most reliable for daemons).
	if pid, err := m.readPID(name); err == nil && m.IsRunning(pid) {
		return pid, nil
	}

	// Fall back to /proc scan.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}

		// cmdline is NUL-separated. The first field is the binary path.
		args := strings.Split(string(cmdline), "\x00")
		if len(args) == 0 {
			continue
		}

		bin := filepath.Base(args[0])
		if bin == name || args[0] == name {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process %q not found", name)
}

// IsRunning checks if a process is alive by sending signal 0.
func (m *OpenRCManager) IsRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 tests if the process exists without actually sending a signal.
	return p.Signal(syscall.Signal(0)) == nil
}

// readPID reads a PID from common PID file locations.
func (m *OpenRCManager) readPID(service string) (int, error) {
	// Try common PID file patterns.
	candidates := []string{
		filepath.Join(m.PIDDir, service+".pid"),
		filepath.Join(m.PIDDir, service, service+".pid"),
		filepath.Join("/var/run", service+".pid"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pidStr := strings.TrimSpace(string(data))
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		return pid, nil
	}

	return 0, fmt.Errorf("no PID file found for %s", service)
}

// processUptime reads process start time from /proc/[pid]/stat.
func (m *OpenRCManager) processUptime(pid int) (time.Duration, error) {
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}

	// /proc/[pid]/stat field 22 is starttime in clock ticks since boot.
	// We need the system boot time from /proc/stat to calculate wall time.
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return 0, fmt.Errorf("unexpected /proc/stat format")
	}

	startTicks, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return 0, err
	}

	// Read system uptime.
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/uptime format")
	}
	systemUptime, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, err
	}

	// Clock ticks per second — read from kernel config, default 100.
	clockTicksPerSec := getClockTicks()
	processStartSec := float64(startTicks) / clockTicksPerSec
	processUptime := systemUptime - processStartSec

	if processUptime < 0 {
		processUptime = 0
	}

	return time.Duration(processUptime * float64(time.Second)), nil
}

// getClockTicks returns the kernel's clock tick rate (USER_HZ).
// Uses the C library sysconf(_SC_CLK_TCK) via getconf. Falls back to 100.
func getClockTicks() float64 {
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && v > 0 {
			return float64(v)
		}
	}
	return 100 // Default for nearly all Linux systems.
}

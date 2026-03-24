package backend

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Ethtool ioctl constants. vishvananda/netlink does not support ethtool,
// so we use raw ioctls via syscall (no exec.Command, no external deps).
const (
	siocEthtool = 0x8946

	// Get/set commands for individual offload features.
	ethtoolGTSO    = 0x1e
	ethtoolSTSO    = 0x1f
	ethtoolGGSO    = 0x23
	ethtoolSGSO    = 0x24
	ethtoolGGRO    = 0x2b
	ethtoolSGRO    = 0x2c
	ethtoolGRXCSUM = 0x14
	ethtoolSRXCSUM = 0x15
	ethtoolGTXCSUM = 0x16
	ethtoolSTXCSUM = 0x17
)

// offloadCmds maps feature names to [get, set] ethtool command pairs.
var offloadCmds = map[string][2]uint32{
	"tso":         {ethtoolGTSO, ethtoolSTSO},
	"gro":         {ethtoolGGRO, ethtoolSGRO},
	"gso":         {ethtoolGGSO, ethtoolSGSO},
	"rx_checksum": {ethtoolGRXCSUM, ethtoolSRXCSUM},
	"tx_checksum": {ethtoolGTXCSUM, ethtoolSTXCSUM},
}

// NICInfo reads hardware details from sysfs, /proc, and ethtool ioctls.
func (m *LinuxNetworkManager) NICInfo(iface string) (*NICInfo, error) {
	if err := validSysfsName(iface); err != nil {
		return nil, err
	}
	base := filepath.Join("/sys/class/net", iface)
	if _, err := os.Stat(base); err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	info := &NICInfo{
		Name:       iface,
		SpeedMbps:  readSysfsInt(base, "speed", -1),
		Duplex:     readSysfsStr(base, "duplex", "unknown"),
		MTU:        readSysfsInt(base, "mtu", 1500),
		TxQueueLen: readSysfsInt(base, "tx_queue_len", 1000),
		Driver:     readDriverName(base),
	}
	info.RxQueues, info.TxQueues = countQueues(base)
	info.Stats = readNICStats(base)
	info.Offloads = readOffloads(iface)
	info.IRQs = findNICIRQs(iface)
	return info, nil
}

// SetIRQAffinity pins an IRQ to specific CPUs.
func (m *LinuxNetworkManager) SetIRQAffinity(irq int, cpuList string) error {
	// Validate cpuList contains only digits, commas, and hyphens.
	for _, c := range cpuList {
		if !((c >= '0' && c <= '9') || c == ',' || c == '-') {
			return fmt.Errorf("invalid cpu list: %q", cpuList)
		}
	}
	path := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq)
	return os.WriteFile(path, []byte(cpuList), 0o644)
}

// NICSetOffload enables or disables a NIC offload feature via ethtool ioctl.
func (m *LinuxNetworkManager) NICSetOffload(iface string, feature string, enabled bool) error {
	cmds, ok := offloadCmds[feature]
	if !ok {
		return fmt.Errorf("unknown offload feature: %s", feature)
	}
	return ethtoolSet(iface, cmds[1], enabled)
}

// --- sysfs helpers ---

func readSysfsInt(base, name string, defVal int) int {
	data, err := os.ReadFile(filepath.Join(base, name))
	if err != nil {
		return defVal
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return defVal
	}
	return v
}

func readSysfsStr(base, name string, defVal string) string {
	data, err := os.ReadFile(filepath.Join(base, name))
	if err != nil {
		return defVal
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return defVal
	}
	return s
}

func readSysfsUint64(dir, name string) uint64 {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v
}

func readDriverName(base string) string {
	target, err := os.Readlink(filepath.Join(base, "device", "driver"))
	if err != nil {
		return "unknown"
	}
	return filepath.Base(target)
}

func countQueues(base string) (rx, tx int) {
	entries, err := os.ReadDir(filepath.Join(base, "queues"))
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "rx-") {
			rx++
		} else if strings.HasPrefix(n, "tx-") {
			tx++
		}
	}
	return
}

func readNICStats(base string) NICStats {
	d := filepath.Join(base, "statistics")
	return NICStats{
		RxBytes:   readSysfsUint64(d, "rx_bytes"),
		TxBytes:   readSysfsUint64(d, "tx_bytes"),
		RxPackets: readSysfsUint64(d, "rx_packets"),
		TxPackets: readSysfsUint64(d, "tx_packets"),
		RxErrors:  readSysfsUint64(d, "rx_errors"),
		TxErrors:  readSysfsUint64(d, "tx_errors"),
		RxDropped: readSysfsUint64(d, "rx_dropped"),
		TxDropped: readSysfsUint64(d, "tx_dropped"),
	}
}

// --- /proc/interrupts parsing ---

// findNICIRQs scans /proc/interrupts for lines mentioning iface and returns
// the IRQ numbers. Multi-queue NICs show as "eth0-0", "eth0-1", etc.
func findNICIRQs(iface string) []int {
	f, err := os.Open("/proc/interrupts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var irqs []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Match exact interface name or queue suffix (e.g., "eth0", "eth0-0", "eth0-tx-0").
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		lastField := fields[len(fields)-1]
		if lastField != iface && !strings.HasPrefix(lastField, iface+"-") {
			continue
		}
		irqStr := strings.TrimSuffix(fields[0], ":")
		irqNum, err := strconv.Atoi(irqStr)
		if err != nil {
			continue
		}
		irqs = append(irqs, irqNum)
	}
	return irqs
}

// --- ethtool ioctl ---

// ethtoolValue is the ethtool_value struct used by get/set ioctls.
type ethtoolValue struct {
	cmd  uint32
	data uint32
}

// ifreqEthtool is the ifreq struct layout for SIOCETHTOOL.
// name [16] + data pointer + padding to fill the union.
type ifreqEthtool struct {
	name [16]byte
	data uintptr
}

func ethtoolGet(iface string, cmd uint32) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	val := ethtoolValue{cmd: cmd}
	var ifr ifreqEthtool
	copy(ifr.name[:], iface)
	ifr.data = uintptr(unsafe.Pointer(&val))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocEthtool, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return false, errno
	}
	return val.data != 0, nil
}

func ethtoolSet(iface string, cmd uint32, enabled bool) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var data uint32
	if enabled {
		data = 1
	}
	val := ethtoolValue{cmd: cmd, data: data}
	var ifr ifreqEthtool
	copy(ifr.name[:], iface)
	ifr.data = uintptr(unsafe.Pointer(&val))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocEthtool, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func readOffloads(iface string) map[string]bool {
	offloads := make(map[string]bool)
	for name, cmds := range offloadCmds {
		enabled, err := ethtoolGet(iface, cmds[0])
		if err == nil {
			offloads[name] = enabled
		}
	}
	return offloads
}

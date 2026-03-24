package backend

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LinuxNetworkManager implements NetworkManager using /proc and /sys
// instead of shelling out to ip, sysctl, ss, conntrack, etc.
//
// For operations that require netlink (link add/del, addr, route), this
// implementation uses the vishvananda/netlink library. For simpler reads,
// it parses /proc directly.
type LinuxNetworkManager struct{}

// NewLinuxNetworkManager creates a new network manager.
func NewLinuxNetworkManager() *LinuxNetworkManager {
	return &LinuxNetworkManager{}
}

// SysctlSet writes a sysctl value directly to /proc/sys.
// No exec.Command("sysctl", "-w", ...) — just a file write.
func (m *LinuxNetworkManager) SysctlSet(key string, value string) error {
	// Convert dot notation to path: net.ipv4.ip_forward → /proc/sys/net/ipv4/ip_forward
	path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
	// Validate resolved path is under /proc/sys/ to prevent path traversal.
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err == nil {
		resolved = filepath.Join(resolved, filepath.Base(path))
	} else {
		resolved = filepath.Clean(path)
	}
	if !strings.HasPrefix(resolved, "/proc/sys/") {
		return fmt.Errorf("sysctl path %q resolves outside /proc/sys/", key)
	}
	if err := os.WriteFile(resolved, []byte(value), 0o644); err != nil {
		return fmt.Errorf("sysctl set %s=%s: %w", key, value, err)
	}
	return nil
}

// SysctlGet reads a sysctl value from /proc/sys.
func (m *LinuxNetworkManager) SysctlGet(key string) (string, error) {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
	// Resolve symlinks and validate path stays under /proc/sys/.
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err == nil {
		resolved = filepath.Join(resolved, filepath.Base(path))
	} else {
		resolved = filepath.Clean(path)
	}
	if !strings.HasPrefix(resolved, "/proc/sys/") {
		return "", fmt.Errorf("sysctl path %q resolves outside /proc/sys/", key)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("sysctl get %s: %w", key, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Ping sends ICMP echo requests using raw sockets (no exec.Command("ping")).
// If iface is non-empty, binds to that interface's IP for source routing.
func (m *LinuxNetworkManager) Ping(target string, count int, timeoutSec int, iface string) (PingResult, error) {
	result := PingResult{Sent: count}

	// Resolve hostname to IP.
	addrs, err := net.LookupHost(target)
	if err != nil {
		return result, fmt.Errorf("resolve %s: %w", target, err)
	}
	if len(addrs) == 0 {
		return result, fmt.Errorf("no addresses found for %s", target)
	}
	ip := addrs[0]

	// Use ICMP raw socket, optionally bound to a specific interface.
	var conn net.Conn
	if iface != "" {
		localIP, localErr := interfaceIPv4(iface)
		if localErr != nil {
			return result, localErr
		}
		dialer := net.Dialer{
			LocalAddr: &net.IPAddr{IP: localIP},
			Timeout:   time.Duration(timeoutSec) * time.Second,
		}
		conn, err = dialer.Dial("ip4:icmp", ip)
	} else {
		conn, err = net.DialTimeout("ip4:icmp", ip, time.Duration(timeoutSec)*time.Second)
	}
	if err != nil {
		// Fall back to TCP connect test if ICMP not available (unprivileged).
		return m.tcpPing(target, count, timeoutSec)
	}
	defer conn.Close()

	var totalRTT time.Duration
	for i := 0; i < count; i++ {
		// Build ICMP echo request.
		msg := buildICMPEcho(uint16(os.Getpid()&0xffff), uint16(i))
		if err := conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second)); err != nil {
			continue
		}

		start := time.Now()
		if _, err := conn.Write(msg); err != nil {
			continue
		}

		reply := make([]byte, 1500)
		n, err := conn.Read(reply)
		if err != nil {
			continue
		}

		rtt := time.Since(start)
		totalRTT += rtt
		result.Received++

		// Basic ICMP reply validation (skip IP header, check type=0 echo reply).
		if n > 20 && reply[20] == 0 {
			result.Output += fmt.Sprintf("Reply from %s: time=%v\n", ip, rtt.Round(time.Microsecond))
		}
	}

	if result.Received > 0 {
		result.AvgRTT = totalRTT / time.Duration(result.Received)
	}

	return result, nil
}

// interfaceIPv4 returns the first IPv4 address of the named interface.
func interfaceIPv4(name string) (net.IP, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", name, err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on %s", name)
}

const tcpPingPort = "80" // Fallback port for TCP connectivity check when ICMP unavailable.

// tcpPing falls back to TCP connect for ping when ICMP isn't available.
func (m *LinuxNetworkManager) tcpPing(target string, count int, timeoutSec int) (PingResult, error) {
	result := PingResult{Sent: count}

	var totalRTT time.Duration
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target+":"+tcpPingPort, time.Duration(timeoutSec)*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		rtt := time.Since(start)
		totalRTT += rtt
		result.Received++
		result.Output += fmt.Sprintf("tcp connect to %s: time=%v\n", target, rtt.Round(time.Microsecond))
	}

	if result.Received > 0 {
		result.AvgRTT = totalRTT / time.Duration(result.Received)
	}
	return result, nil
}

// buildICMPEcho builds a minimal ICMP Echo Request packet.
func buildICMPEcho(id, seq uint16) []byte {
	msg := make([]byte, 8)
	msg[0] = 8 // Type: Echo Request
	msg[1] = 0 // Code
	// Checksum (bytes 2-3) computed below.
	msg[4] = byte(id >> 8)
	msg[5] = byte(id)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq)

	// Compute checksum.
	var sum uint32
	for i := 0; i < len(msg)-1; i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	cs := ^uint16(sum)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)

	return msg
}

// Connections returns active TCP/UDP connections by parsing /proc/net/tcp
// and /proc/net/udp. Replaces exec.Command("ss", "-tunap").
func (m *LinuxNetworkManager) Connections() ([]Connection, error) {
	var conns []Connection

	tcpConns, err := m.parseProcNet("/proc/net/tcp", "tcp")
	if err == nil {
		conns = append(conns, tcpConns...)
	}

	udpConns, err := m.parseProcNet("/proc/net/udp", "udp")
	if err == nil {
		conns = append(conns, udpConns...)
	}

	tcp6Conns, err := m.parseProcNet("/proc/net/tcp6", "tcp6")
	if err == nil {
		conns = append(conns, tcp6Conns...)
	}

	udp6Conns, err := m.parseProcNet("/proc/net/udp6", "udp6")
	if err == nil {
		conns = append(conns, udp6Conns...)
	}

	return conns, nil
}

// parseProcNet parses /proc/net/{tcp,udp} files.
func (m *LinuxNetworkManager) parseProcNet(path, proto string) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []Connection
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header.
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		localAddr := parseHexAddr(fields[1])
		remoteAddr := parseHexAddr(fields[2])
		state := parseTCPState(fields[3])

		var pid int
		var process string
		if len(fields) >= 8 {
			// Field 7 is inode; we could map to PID via /proc/[pid]/fd but
			// that's expensive. For now, leave PID empty.
			_ = fields[7]
		}

		conns = append(conns, Connection{
			Protocol:  proto,
			LocalAddr: localAddr,
			PeerAddr:  remoteAddr,
			State:     state,
			PID:       pid,
			Process:   process,
		})
	}

	return conns, nil
}

// parseHexAddr converts /proc/net hex address format to human-readable.
// Format: "0100007F:1F90" → "127.0.0.1:8080"
func parseHexAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}

	hexIP := parts[0]
	hexPort := parts[1]

	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return s
	}

	// IPv4: 8 hex chars, little-endian.
	if len(hexIP) == 8 {
		ip, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return s
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d",
			ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff, port)
	}

	return fmt.Sprintf("[%s]:%d", hexIP, port)
}

// tcpStates maps /proc/net/tcp state hex to human-readable names.
var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// parseTCPState converts /proc/net/tcp state hex to human-readable.
func parseTCPState(hex string) string {
	if s, ok := tcpStates[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}

// ConntrackList parses /proc/net/nf_conntrack for connection tracking entries.
// Replaces exec.Command("conntrack", "-L").
func (m *LinuxNetworkManager) ConntrackList(proto string) ([]ConntrackEntry, error) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return nil, fmt.Errorf("open conntrack: %w", err)
	}
	defer f.Close()

	var entries []ConntrackEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Filter by protocol using the parsed field (index 2) instead of
		// substring search, which could false-match on addresses/other fields.
		if proto != "" {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] != proto {
				continue
			}
		}

		entry := parseConntrackLine(line)
		if entry.Protocol != "" {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// parseConntrackLine parses a single /proc/net/nf_conntrack line.
func parseConntrackLine(line string) ConntrackEntry {
	var entry ConntrackEntry
	fields := strings.Fields(line)

	for _, f := range fields {
		switch {
		case strings.HasPrefix(f, "src=") && entry.SrcAddr == "":
			entry.SrcAddr = strings.TrimPrefix(f, "src=")
		case strings.HasPrefix(f, "dst=") && entry.DstAddr == "":
			entry.DstAddr = strings.TrimPrefix(f, "dst=")
		case strings.HasPrefix(f, "sport=") && entry.SrcPort == 0:
			entry.SrcPort, _ = strconv.Atoi(strings.TrimPrefix(f, "sport="))
		case strings.HasPrefix(f, "dport=") && entry.DstPort == 0:
			entry.DstPort, _ = strconv.Atoi(strings.TrimPrefix(f, "dport="))
		case strings.HasPrefix(f, "bytes=") && entry.Bytes == 0:
			entry.Bytes, _ = strconv.ParseInt(strings.TrimPrefix(f, "bytes="), 10, 64)
		case strings.HasPrefix(f, "packets=") && entry.Packets == 0:
			entry.Packets, _ = strconv.ParseInt(strings.TrimPrefix(f, "packets="), 10, 64)
		}
	}

	// Protocol is field index 2 (after "ipv4 2").
	if len(fields) >= 3 {
		entry.Protocol = fields[2]
	}

	// State (e.g., ESTABLISHED) is typically a standalone capitalized word.
	for _, f := range fields {
		switch f {
		case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT",
			"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",
			"LISTEN", "UNREPLIED", "ASSURED":
			entry.State = f
		}
	}

	return entry
}

// Netlink-dependent method implementations are in network_netlink.go.

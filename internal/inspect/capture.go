package inspect

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Capturer performs live packet capture on network interfaces using
// AF_PACKET raw sockets (Linux). It extracts TLS ClientHello messages
// and feeds them to the fingerprint engine.
//
// AF_PACKET provides zero-copy packet access directly from the kernel,
// bypassing libpcap. This gives better performance and fewer dependencies.
type Capturer struct {
	mu       sync.Mutex
	engine   *Engine
	ifaces   []string
	bpfFilt  string
	fds      []int           // raw socket file descriptors
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
	stats    CaptureStats
}

// CaptureStats tracks capture performance metrics.
type CaptureStats struct {
	PacketsRead    uint64    `json:"packets_read"`
	PacketsParsed  uint64    `json:"packets_parsed"`
	PacketsErrors  uint64    `json:"packets_errors"`
	TLSHandshakes  uint64    `json:"tls_handshakes"`
	StartedAt      time.Time `json:"started_at"`
}

// NewCapturer creates a new packet capturer.
func NewCapturer(engine *Engine, ifaces []string, bpfFilter string) *Capturer {
	return &Capturer{
		engine:  engine,
		ifaces:  ifaces,
		bpfFilt: bpfFilter,
		stopCh:  make(chan struct{}),
	}
}

// Start begins packet capture on all configured interfaces.
func (c *Capturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	for _, ifName := range c.ifaces {
		fd, err := openAFPacket(ifName)
		if err != nil {
			slog.Warn("failed to open AF_PACKET on interface", "interface", ifName, "error", err)
			continue
		}

		// Apply a kernel-level BPF filter for "tcp port 443" to reduce
		// user-space processing. Only TLS-bearing packets reach us.
		if err := attachTCPPort443Filter(fd); err != nil {
			slog.Warn("failed to attach BPF filter", "interface", ifName, "error", err)
			// Continue anyway — we'll get more packets but still work.
		}

		c.fds = append(c.fds, fd)
		c.wg.Add(1)
		go c.captureLoop(fd, ifName)
	}

	if len(c.fds) == 0 {
		return fmt.Errorf("no interfaces could be opened for capture")
	}

	c.running = true
	c.stats.StartedAt = time.Now()
	slog.Info("packet capture started", "interfaces", c.ifaces, "sockets", len(c.fds))
	return nil
}

// Stop halts all packet capture goroutines.
func (c *Capturer) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.stopCh)
	c.mu.Unlock()

	// Close all sockets — this unblocks any recvfrom calls.
	for _, fd := range c.fds {
		syscall.Close(fd)
	}

	c.wg.Wait()
	slog.Info("packet capture stopped",
		"packets_read", c.stats.PacketsRead,
		"tls_handshakes", c.stats.TLSHandshakes,
	)
	return nil
}

// Stats returns a snapshot of capture statistics.
func (c *Capturer) Stats() CaptureStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// captureLoop reads packets from a single AF_PACKET socket.
func (c *Capturer) captureLoop(fd int, ifName string) {
	defer c.wg.Done()

	buf := make([]byte, 65536) // Max Ethernet frame size.

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Set a read deadline so we periodically check stopCh.
		// AF_PACKET sockets support SO_RCVTIMEO.
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout or interrupted — check if we should stop.
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			// Socket closed = we're stopping.
			return
		}
		if n < 54 { // Minimum: Ethernet(14) + IP(20) + TCP(20)
			continue
		}

		c.mu.Lock()
		c.stats.PacketsRead++
		c.mu.Unlock()

		c.processPacket(buf[:n], ifName)
	}
}

// processPacket extracts TLS ClientHello from a raw Ethernet frame.
func (c *Capturer) processPacket(pkt []byte, ifName string) {
	// Ethernet header: dst(6) + src(6) + ethertype(2) = 14 bytes.
	if len(pkt) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	payload := pkt[14:]

	// Handle VLAN (802.1Q).
	if etherType == 0x8100 || etherType == 0x88a8 {
		if len(payload) < 4 {
			return
		}
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}

	if etherType != 0x0800 { // IPv4 only for now.
		return
	}

	// IPv4 header.
	if len(payload) < 20 {
		return
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || ihl > len(payload) {
		return
	}
	protocol := payload[9]
	if protocol != 6 { // TCP only.
		return
	}
	srcIP := fmt.Sprintf("%d.%d.%d.%d", payload[12], payload[13], payload[14], payload[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", payload[16], payload[17], payload[18], payload[19])
	tcpPayload := payload[ihl:]

	// TCP header.
	if len(tcpPayload) < 20 {
		return
	}
	dataOff := int(tcpPayload[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcpPayload) {
		return
	}
	tlsData := tcpPayload[dataOff:]

	// Check for TLS Handshake record (content type 0x16).
	if len(tlsData) < 6 || tlsData[0] != 0x16 {
		return
	}

	// Check for ClientHello (handshake type 0x01 at offset 5).
	if tlsData[5] != 0x01 {
		return
	}

	c.mu.Lock()
	c.stats.TLSHandshakes++
	c.mu.Unlock()

	// Parse ClientHello.
	hello, err := ParseClientHello(tlsData)
	if err != nil {
		c.mu.Lock()
		c.stats.PacketsErrors++
		c.mu.Unlock()
		return
	}

	hello.SrcIP = srcIP
	hello.DstIP = dstIP
	hello.Timestamp = time.Now()

	c.mu.Lock()
	c.stats.PacketsParsed++
	c.mu.Unlock()

	// Fingerprint it.
	fp, err := c.engine.FingerprintTLS(hello)
	if err != nil {
		return
	}

	// Check threat feeds inline.
	threat, _ := c.engine.CheckThreat(fp.Hash)
	if threat != nil && threat.Matched {
		slog.Warn("TLS fingerprint matches threat feed",
			"hash", fp.Hash,
			"src_ip", srcIP,
			"dst_ip", dstIP,
			"sni", hello.SNI,
			"threat", threat.ThreatName,
			"severity", threat.Severity,
			"feed", threat.FeedName,
		)
	}
}

// openAFPacket creates a raw AF_PACKET socket bound to an interface.
func openAFPacket(ifName string) (int, error) {
	// Create raw socket: AF_PACKET, SOCK_RAW, ETH_P_ALL.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, fmt.Errorf("socket: %w (need CAP_NET_RAW)", err)
	}

	// Resolve interface index.
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("interface %q: %w", ifName, err)
	}

	// Bind to the specific interface.
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("bind: %w", err)
	}

	// Set promiscuous mode.
	mreq := packetMreq{
		ifindex: int32(iface.Index),
		typ:     1, // PACKET_MR_PROMISC
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(263), // SOL_PACKET
		uintptr(1),   // PACKET_ADD_MEMBERSHIP
		uintptr(unsafe.Pointer(&mreq)),
		unsafe.Sizeof(mreq),
		0,
	)
	if errno != 0 {
		// Non-fatal — we can capture without promisc.
		slog.Debug("promisc mode failed", "interface", ifName, "error", errno)
	}

	return fd, nil
}

type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	addr    [8]byte
}

// attachTCPPort443Filter attaches a classic BPF program that filters
// for TCP port 443 (TLS). This runs in the kernel so non-matching
// packets never cross the kernel/user boundary.
func attachTCPPort443Filter(fd int) error {
	// BPF bytecode for: tcp dst port 443
	// Generated equivalent of: tcpdump -dd 'tcp dst port 443'
	filter := []bpfInsn{
		{0x28, 0, 0, 12},          // ldh [12]              ; load ethertype
		{0x15, 0, 8, 0x0800},      // jeq #0x0800, +0, +8   ; IPv4?
		{0x30, 0, 0, 23},          // ldb [23]              ; load protocol
		{0x15, 0, 6, 6},           // jeq #6, +0, +6        ; TCP?
		{0x28, 0, 0, 20},          // ldh [20]              ; load frag offset
		{0x45, 4, 0, 0x1fff},      // jset #0x1fff, +4, +0  ; fragment?
		{0xb1, 0, 0, 14},          // ldxb 4*([14]&0xf)     ; IP header len
		{0x48, 0, 0, 16},          // ldh [x+16]            ; load dst port
		{0x15, 0, 1, 443},         // jeq #443, +0, +1      ; port 443?
		{0x06, 0, 0, 65535},       // ret #65535            ; accept
		{0x06, 0, 0, 0},           // ret #0                ; reject
	}

	prog := bpfProgram{
		length: uint16(len(filter)),
		filter: &filter[0],
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(26), // SO_ATTACH_FILTER
		uintptr(unsafe.Pointer(&prog)),
		unsafe.Sizeof(prog),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", errno)
	}
	return nil
}

type bpfInsn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type bpfProgram struct {
	length uint16
	_      [6]byte // padding to align filter pointer
	filter *bpfInsn
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

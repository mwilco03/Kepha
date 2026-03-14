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

// processPacket extracts TLS ClientHello, SSH KEX Init, or QUIC Initial from a raw Ethernet frame.
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
	srcIP := fmt.Sprintf("%d.%d.%d.%d", payload[12], payload[13], payload[14], payload[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", payload[16], payload[17], payload[18], payload[19])

	switch protocol {
	case 1: // ICMP
		c.processICMPPacket(payload, srcIP, dstIP)
	case 6: // TCP
		c.processTCPPacket(payload, payload[ihl:], srcIP, dstIP)
	case 17: // UDP
		c.processUDPPacket(payload[ihl:], srcIP, dstIP)
	}
}

// processTCPPacket handles TCP segments for all supported protocols.
// ipPayload is the full IP packet (for teardown parsing), tcpPayload starts at TCP header.
func (c *Capturer) processTCPPacket(ipPayload, tcpPayload []byte, srcIP, dstIP string) {
	if len(tcpPayload) < 20 {
		return
	}

	dstPort := binary.BigEndian.Uint16(tcpPayload[0:2])
	flags := tcpPayload[13]
	dataOff := int(tcpPayload[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcpPayload) {
		return
	}

	// Track TCP FIN/RST for teardown fingerprinting.
	if flags&0x01 != 0 || flags&0x04 != 0 { // FIN or RST
		td, err := ParseTCPFlags(ipPayload)
		if err == nil {
			_, _ = c.engine.FingerprintTCPTeardown(td)
		}
	}

	appData := tcpPayload[dataOff:]
	if len(appData) == 0 {
		return
	}

	switch dstPort {
	case 443:
		// Check for HTTP/2 preface first (cleartext h2c on port 443 is rare
		// but HTTP/2 SETTINGS follow TLS in the same stream after ALPN negotiation).
		if DetectHTTP2Preface(appData) {
			if len(appData) > 24 {
				settings, err := ParseHTTP2Settings(appData[24:])
				if err == nil {
					settings.SrcIP = srcIP
					settings.DstIP = dstIP
					_, _ = c.engine.FingerprintHTTP2(settings)
				}
			}
			return
		}
		c.processTLSData(appData, srcIP, dstIP)
	case 22:
		c.processSSHData(appData, srcIP, dstIP)
	case 25, 587: // SMTP
		banner := ParseSMTPBanner(appData)
		if banner != nil {
			banner.SrcIP = srcIP
			banner.DstIP = dstIP
			banner.Port = dstPort
			_, _ = c.engine.FingerprintBanner(banner)
		}
	case 80, 8080: // HTTP
		banner := ParseHTTPServerBanner(appData)
		if banner != nil {
			banner.SrcIP = srcIP
			banner.DstIP = dstIP
			banner.Port = dstPort
			_, _ = c.engine.FingerprintBanner(banner)
		}
	}
}

// processTLSData handles TLS handshake records (ClientHello, Certificate).
func (c *Capturer) processTLSData(tlsData []byte, srcIP, dstIP string) {
	// Check for TLS Handshake record (content type 0x16).
	if len(tlsData) < 6 || tlsData[0] != 0x16 {
		return
	}

	hsType := tlsData[5]

	switch hsType {
	case 0x01: // ClientHello
		c.mu.Lock()
		c.stats.TLSHandshakes++
		c.mu.Unlock()

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

		fp, err := c.engine.FingerprintTLS(hello)
		if err != nil {
			return
		}

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

	case 0x0b: // Certificate
		chain, err := ParseCertificateMessage(tlsData)
		if err != nil {
			return
		}
		chain.SrcIP = srcIP
		chain.DstIP = dstIP
		chain.Timestamp = time.Now()

		c.mu.Lock()
		c.stats.PacketsParsed++
		c.mu.Unlock()

		fp, err := c.engine.FingerprintCert(chain)
		if err != nil {
			return
		}

		if len(fp.Alerts) > 0 {
			slog.Warn("certificate alerts",
				"hash", fp.Hash,
				"src_ip", srcIP,
				"subject", fp.LeafSubject,
				"alerts", fp.Alerts,
			)
		}
	}
}

// processSSHData handles SSH protocol messages (banner and KEX_INIT).
func (c *Capturer) processSSHData(data []byte, srcIP, dstIP string) {
	if len(data) < 4 {
		return
	}

	// SSH banner starts with "SSH-".
	if len(data) >= 4 && string(data[:4]) == "SSH-" {
		banner, err := ParseSSHBanner(data)
		if err != nil {
			return
		}
		slog.Debug("SSH banner captured", "src_ip", srcIP, "banner", banner)
		return
	}

	// SSH binary packet: length(4) + padding_length(1) + payload...
	// Check if this could be an SSH_MSG_KEXINIT.
	if len(data) < 6 {
		return
	}
	pktLen := int(binary.BigEndian.Uint32(data[0:4]))
	if pktLen < 2 || pktLen > len(data)-4 {
		return
	}
	paddingLen := int(data[4])
	msgType := data[5]

	if msgType != 20 { // SSH_MSG_KEXINIT
		return
	}

	// Parse from the message type byte onward.
	payloadEnd := 4 + pktLen - paddingLen
	if payloadEnd > len(data) || payloadEnd < 6 {
		return
	}

	kex, err := ParseSSHKexInit(data[5:payloadEnd])
	if err != nil {
		c.mu.Lock()
		c.stats.PacketsErrors++
		c.mu.Unlock()
		return
	}

	kex.SrcIP = srcIP
	kex.DstIP = dstIP
	kex.Timestamp = time.Now()

	c.mu.Lock()
	c.stats.PacketsParsed++
	c.mu.Unlock()

	fp, err := c.engine.FingerprintSSH(kex)
	if err != nil {
		return
	}

	threat, _ := c.engine.CheckThreat(fp.Hash)
	if threat != nil && threat.Matched {
		slog.Warn("SSH fingerprint matches threat feed",
			"hash", fp.Hash,
			"src_ip", srcIP,
			"dst_ip", dstIP,
			"server", kex.IsServer,
			"threat", threat.ThreatName,
			"severity", threat.Severity,
			"feed", threat.FeedName,
		)
	}
}

// processUDPPacket handles UDP datagrams (QUIC, DNS).
func (c *Capturer) processUDPPacket(udpPayload []byte, srcIP, dstIP string) {
	// UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes.
	if len(udpPayload) < 8 {
		return
	}

	dstPort := binary.BigEndian.Uint16(udpPayload[2:4])
	appData := udpPayload[8:]

	switch dstPort {
	case 443:
		c.processQUICData(appData, udpPayload, srcIP, dstIP)
	case 53:
		c.processDNSData(appData, srcIP, dstIP)
	}
}

// processQUICData handles QUIC Initial packets from UDP port 443.
func (c *Capturer) processQUICData(quicData, udpPayload []byte, srcIP, dstIP string) {
	if len(quicData) < 5 {
		return
	}

	// Check for QUIC long header (form bit = 1).
	if quicData[0]&0x80 == 0 {
		return // Short header — not an Initial packet.
	}

	qi, err := ParseQUICInitial(quicData)
	if err != nil {
		return
	}

	qi.SrcIP = srcIP
	qi.DstIP = dstIP
	qi.SrcPort = binary.BigEndian.Uint16(udpPayload[0:2])
	qi.DstPort = 443
	qi.Timestamp = time.Now()

	if qi.ClientHello != nil {
		qi.ClientHello.SrcIP = srcIP
		qi.ClientHello.DstIP = dstIP
	}

	c.mu.Lock()
	c.stats.PacketsParsed++
	c.mu.Unlock()

	fp, err := c.engine.FingerprintQUIC(qi)
	if err != nil {
		return
	}

	threat, _ := c.engine.CheckThreat(fp.Hash)
	if threat != nil && threat.Matched {
		sni := ""
		if qi.ClientHello != nil {
			sni = qi.ClientHello.SNI
		}
		slog.Warn("QUIC fingerprint matches threat feed",
			"hash", fp.Hash,
			"src_ip", srcIP,
			"dst_ip", dstIP,
			"sni", sni,
			"threat", threat.ThreatName,
			"severity", threat.Severity,
			"feed", threat.FeedName,
		)
	}
}

// processDNSData handles DNS queries from UDP port 53.
func (c *Capturer) processDNSData(data []byte, srcIP, dstIP string) {
	query, err := ParseDNSQuery(data)
	if err != nil {
		return
	}

	query.SrcIP = srcIP
	query.DstIP = dstIP
	query.Timestamp = time.Now()

	c.mu.Lock()
	c.stats.PacketsParsed++
	c.mu.Unlock()

	fp, err := c.engine.FingerprintDNS(query)
	if err != nil {
		return
	}

	if len(fp.Alerts) > 0 {
		slog.Warn("DNS fingerprint alerts",
			"hash", fp.Hash,
			"src_ip", srcIP,
			"alerts", fp.Alerts,
		)
	}
}

// processICMPPacket handles ICMP messages.
// ipPayload starts at the IP header.
func (c *Capturer) processICMPPacket(ipPayload []byte, srcIP, dstIP string) {
	msg, err := ParseICMP(ipPayload)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.stats.PacketsParsed++
	c.mu.Unlock()

	fp, err := c.engine.FingerprintICMP(msg)
	if err != nil {
		return
	}

	if len(fp.Alerts) > 0 {
		slog.Warn("ICMP fingerprint alerts",
			"hash", fp.Hash,
			"src_ip", srcIP,
			"type", msg.Type,
			"alerts", fp.Alerts,
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

// attachBPFFilter attaches a classic BPF program that captures all IP traffic
// relevant to fingerprinting: TCP (TLS, SSH, HTTP, SMTP), UDP (QUIC, DNS), and ICMP.
// This runs in the kernel so non-matching packets never cross the kernel/user boundary.
func attachTCPPort443Filter(fd int) error {
	// BPF filter: IPv4 AND (TCP OR UDP OR ICMP)
	// We accept all TCP/UDP/ICMP packets and filter by port in userspace.
	// This is simpler than encoding every port combination in BPF and still
	// filters out ARP, IPv6, and other non-IPv4 traffic at kernel level.
	filter := []bpfInsn{
		{0x28, 0, 0, 12},          // ldh [12]              ; load ethertype
		{0x15, 0, 5, 0x0800},      // jeq #0x0800, +0, +5   ; IPv4?
		{0x30, 0, 0, 23},          // ldb [23]              ; load protocol
		{0x15, 2, 0, 6},           // jeq #6 (TCP), +2, +0  ; TCP?
		{0x15, 1, 0, 17},          // jeq #17 (UDP), +1, +0 ; UDP?
		{0x15, 0, 1, 1},           // jeq #1 (ICMP), +0, +1 ; ICMP?
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

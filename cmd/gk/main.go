package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/gatekeeper-firewall/gatekeeper/internal/backend"
	"github.com/gatekeeper-firewall/gatekeeper/internal/cli"
	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/model"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
)

var version = "dev"

func main() {
	outputFmt := os.Getenv("GK_OUTPUT")
	if outputFmt == "" {
		outputFmt = "json"
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	backend, cleanup := initBackend()
	defer cleanup()

	cmd := os.Args[1]

	var err error
	switch cmd {
	case "version":
		fmt.Printf("gk %s\n", version)
		return
	case "status":
		err = cmdStatus(backend, outputFmt)
	case "zone":
		err = cmdZone(backend, os.Args[2:], outputFmt)
	case "alias":
		err = cmdAlias(backend, os.Args[2:], outputFmt)
	case "profile":
		err = cmdProfile(backend, os.Args[2:], outputFmt)
	case "policy":
		err = cmdPolicy(backend, os.Args[2:], outputFmt)
	case "assign":
		err = cmdAssign(backend, os.Args[2:])
	case "unassign":
		err = cmdUnassign(backend, os.Args[2:])
	case "commit":
		err = cmdCommit(backend, os.Args[2:])
	case "rollback":
		err = cmdRollback(backend, os.Args[2:])
	case "diff":
		err = cmdDiff(backend, os.Args[2:])
	case "export":
		err = cmdExport(backend)
	case "import":
		err = cmdImport(backend, os.Args[2:])
	case "wg":
		err = cmdWG(backend, os.Args[2:], outputFmt)
	case "leases":
		err = cmdLeases(backend, outputFmt)
	case "test":
		err = cmdTest(backend, os.Args[2:])
	case "explain":
		err = cmdExplain(backend, os.Args[2:], outputFmt)
	case "audit":
		err = cmdAudit(backend, outputFmt)
	case "service", "svc":
		err = cmdService(os.Args[2:])
	case "ping":
		err = cmdPing(os.Args[2:])
	case "perf":
		err = cmdPerf(os.Args[2:], outputFmt)
	case "deps":
		err = cmdDeps(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// initBackend selects the CLI backend based on GK_MODE.
//   - "api":    uses the HTTP API client (remote or fallback mode)
//   - "direct": opens the SQLite DB directly via the ops layer (default)
func initBackend() (cli.Backend, func()) {
	mode := os.Getenv("GK_MODE")
	if mode == "" {
		mode = "direct"
	}

	if mode == "api" {
		apiKey := os.Getenv("GK_API_KEY")
		client := cli.NewClient("", apiKey) // auto-detect URL
		return cli.NewAPIBackend(client), func() {}
	}

	// Direct mode: open the SQLite database and call ops directly.
	dbPath := os.Getenv("GK_DB")
	if dbPath == "" {
		dbPath = "/var/lib/gatekeeper/gatekeeper.db"
	}
	store, err := config.NewStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open database %s: %v\n", dbPath, err)
		fmt.Fprintf(os.Stderr, "hint: set GK_MODE=api to use the HTTP API instead\n")
		os.Exit(1)
	}
	o := ops.New(store)
	return cli.NewDirectBackend(o, nil), func() { store.Close() }
}

// signalDaemon sends SIGHUP to the daemon to trigger a config apply.
// The CLI writes to the DB, the daemon owns the actual apply.
func signalDaemon() error {
	pidFile := "/run/gatekeeper/gatekeeperd.pid"
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("cannot read daemon PID file %s: %w (is gatekeeperd running?)", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid PID in %s: %w", pidFile, err)
	}
	// Use syscall.Kill for signaling — no shell execution, no injection risk.
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to signal daemon (pid %d): %w", pid, err)
	}
	return nil
}

func cmdStatus(b cli.Backend, outputFmt string) error {
	// Status is a simple health check — list zones as a proxy.
	zones, err := b.ListZones()
	if err != nil {
		return err
	}
	if outputFmt == "table" {
		fmt.Printf("Status: ok\nZones:  %d\n", len(zones))
		return nil
	}
	return printJSON(map[string]any{"status": "ok", "zones": len(zones)})
}

func cmdZone(b cli.Backend, args []string, outputFmt string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk zone <list|show|create|delete> [options]")
	}
	switch args[0] {
	case "list":
		zones, err := b.ListZones()
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tINTERFACE\tCIDR\tTRUST\tDESCRIPTION")
			for _, z := range zones {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", z.ID, z.Name, z.Interface, z.NetworkCIDR, z.TrustLevel, z.Description)
			}
			return tw.Flush()
		}
		return printJSON(zones)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk zone show <name>")
		}
		zone, err := b.GetZone(args[1])
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tINTERFACE\tCIDR\tTRUST\tDESCRIPTION")
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", zone.ID, zone.Name, zone.Interface, zone.NetworkCIDR, zone.TrustLevel, zone.Description)
			return tw.Flush()
		}
		return printJSON(zone)
	case "create":
		fs := flag.NewFlagSet("zone create", flag.ExitOnError)
		name := fs.String("name", "", "Zone name")
		iface := fs.String("interface", "", "Network interface")
		cidr := fs.String("cidr", "", "Network CIDR")
		trust := fs.String("trust", "none", "Trust level")
		_ = fs.Parse(args[1:])
		z := &model.Zone{Name: *name, Interface: *iface, NetworkCIDR: *cidr, TrustLevel: *trust}
		if err := b.CreateZone(z); err != nil {
			return err
		}
		return printJSON(z)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk zone delete <name>")
		}
		return b.DeleteZone(args[1])
	default:
		return fmt.Errorf("unknown zone command: %s", args[0])
	}
}

func cmdAlias(b cli.Backend, args []string, outputFmt string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk alias <list|show|create|delete|add-member>")
	}
	switch args[0] {
	case "list":
		aliases, err := b.ListAliases()
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tTYPE\tMEMBERS\tDESCRIPTION")
			for _, a := range aliases {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Type, strings.Join(a.Members, ", "), a.Description)
			}
			return tw.Flush()
		}
		return printJSON(aliases)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk alias show <name>")
		}
		alias, err := b.GetAlias(args[1])
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tTYPE\tMEMBERS\tDESCRIPTION")
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", alias.ID, alias.Name, alias.Type, strings.Join(alias.Members, ", "), alias.Description)
			return tw.Flush()
		}
		return printJSON(alias)
	case "create":
		fs := flag.NewFlagSet("alias create", flag.ExitOnError)
		name := fs.String("name", "", "Alias name")
		typ := fs.String("type", "host", "Alias type")
		members := fs.String("members", "", "Comma-separated members")
		_ = fs.Parse(args[1:])
		var memberList []string
		if *members != "" {
			memberList = strings.Split(*members, ",")
		}
		a := &model.Alias{Name: *name, Type: model.AliasType(*typ), Members: memberList}
		if err := b.CreateAlias(a); err != nil {
			return err
		}
		return printJSON(a)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk alias delete <name>")
		}
		return b.DeleteAlias(args[1])
	case "add-member":
		if len(args) < 3 {
			return fmt.Errorf("usage: gk alias add-member <alias> <member>")
		}
		return b.AddAliasMember(args[1], args[2])
	default:
		return fmt.Errorf("unknown alias command: %s", args[0])
	}
}

func cmdProfile(b cli.Backend, args []string, outputFmt string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk profile <list|show|create>")
	}
	switch args[0] {
	case "list":
		profiles, err := b.ListProfiles()
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tZONE_ID\tPOLICY\tDESCRIPTION")
			for _, p := range profiles {
				fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\n", p.ID, p.Name, p.ZoneID, p.PolicyName, p.Description)
			}
			return tw.Flush()
		}
		return printJSON(profiles)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk profile show <name>")
		}
		profile, err := b.GetProfile(args[1])
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tZONE_ID\tPOLICY\tDESCRIPTION")
			fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\n", profile.ID, profile.Name, profile.ZoneID, profile.PolicyName, profile.Description)
			return tw.Flush()
		}
		return printJSON(profile)
	case "create":
		fs := flag.NewFlagSet("profile create", flag.ExitOnError)
		name := fs.String("name", "", "Profile name")
		zoneID := fs.Int("zone-id", 0, "Zone ID")
		policy := fs.String("policy", "", "Policy name")
		_ = fs.Parse(args[1:])
		p := &model.Profile{Name: *name, ZoneID: int64(*zoneID), PolicyName: *policy}
		if err := b.CreateProfile(p); err != nil {
			return err
		}
		return printJSON(p)
	default:
		return fmt.Errorf("unknown profile command: %s", args[0])
	}
}

func cmdPolicy(b cli.Backend, args []string, outputFmt string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk policy <list|show>")
	}
	switch args[0] {
	case "list":
		policies, err := b.ListPolicies()
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tDEFAULT_ACTION\tRULES\tDESCRIPTION")
			for _, p := range policies {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\n", p.ID, p.Name, p.DefaultAction, len(p.Rules), p.Description)
			}
			return tw.Flush()
		}
		return printJSON(policies)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk policy show <name>")
		}
		policy, err := b.GetPolicy(args[1])
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			fmt.Printf("Policy: %s (default: %s)\n", policy.Name, policy.DefaultAction)
			if policy.Description != "" {
				fmt.Printf("Description: %s\n", policy.Description)
			}
			fmt.Println()
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ORDER\tSRC\tDST\tPROTO\tPORTS\tACTION\tLOG\tDESCRIPTION")
			for _, r := range policy.Rules {
				logStr := ""
				if r.Log {
					logStr = "yes"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.Order, r.SrcAlias, r.DstAlias, r.Protocol, r.Ports, r.Action, logStr, r.Description)
			}
			return tw.Flush()
		}
		return printJSON(policy)
	default:
		return fmt.Errorf("unknown policy command: %s", args[0])
	}
}

func cmdAssign(b cli.Backend, args []string) error {
	fs := flag.NewFlagSet("assign", flag.ExitOnError)
	profile := fs.String("profile", "", "Profile name")
	hostname := fs.String("hostname", "", "Device hostname")
	mac := fs.String("mac", "", "MAC address")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: gk assign <ip> --profile <name> [--hostname <name>] [--mac <addr>]")
	}
	ip := fs.Arg(0)
	d, err := b.AssignDevice(ip, *mac, *hostname, *profile, 0)
	if err != nil {
		return err
	}
	return printJSON(d)
}

func cmdUnassign(b cli.Backend, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk unassign <ip>")
	}
	return b.UnassignDevice(args[0])
}

func cmdCommit(b cli.Backend, args []string) error {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	message := fs.String("message", "", "Commit message")
	_ = fs.Parse(args)
	msg := *message
	if msg == "" {
		msg = strings.Join(fs.Args(), " ")
	}
	if msg == "" {
		msg = "manual commit"
	}

	// Write the revision to the DB.
	rev, err := b.Commit(msg)
	if err != nil {
		return err
	}
	fmt.Printf("committed revision %d\n", rev)

	// Signal the daemon to apply the new config.
	// In direct mode, the CLI only writes to the DB — apply is daemon-owned.
	if os.Getenv("GK_MODE") != "api" {
		if err := signalDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			fmt.Fprintf(os.Stderr, "config committed but not applied — restart gatekeeperd or run 'gk commit' via API\n")
		}
	}
	return nil
}

func cmdRollback(b cli.Backend, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk rollback <rev>")
	}
	rev, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid revision number: %s", args[0])
	}
	if err := b.Rollback(rev); err != nil {
		return err
	}
	fmt.Printf("rolled back to revision %d\n", rev)

	// Signal daemon to apply.
	if os.Getenv("GK_MODE") != "api" {
		if err := signalDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	return nil
}

func cmdDiff(b cli.Backend, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gk diff <rev1> <rev2>")
	}
	rev1, _ := strconv.Atoi(args[0])
	rev2, _ := strconv.Atoi(args[1])
	snap1, snap2, err := b.Diff(rev1, rev2)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"rev1": snap1, "rev2": snap2})
}

func cmdExport(b cli.Backend) error {
	snap, err := b.Export()
	if err != nil {
		return err
	}
	return printJSON(snap)
}

func cmdImport(b cli.Backend, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk import <file.json>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	var snap config.ConfigSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return b.Import(&snap)
}

func cmdWG(b cli.Backend, args []string, outputFmt string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk wg <peers|add-peer|remove-peer|prune>")
	}
	switch args[0] {
	case "peers":
		peers, err := b.ListWGPeers()
		if err != nil {
			return err
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tPUBLIC_KEY\tALLOWED_IPS\tENDPOINT")
			for _, p := range peers {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.PublicKey, p.AllowedIPs, p.Endpoint)
			}
			return tw.Flush()
		}
		return printJSON(peers)
	case "add-peer":
		fs := flag.NewFlagSet("wg add-peer", flag.ExitOnError)
		pubKey := fs.String("pubkey", "", "Peer public key")
		allowedIPs := fs.String("allowed-ips", "", "Allowed IPs (e.g. 10.50.0.2/32)")
		name := fs.String("name", "", "Peer name")
		_ = fs.Parse(args[1:])
		if *pubKey == "" || *allowedIPs == "" {
			return fmt.Errorf("usage: gk wg add-peer --pubkey <key> --allowed-ips <cidr> [--name <name>]")
		}
		return b.AddWGPeer(driver.WGPeer{PublicKey: *pubKey, AllowedIPs: *allowedIPs, Name: *name})
	case "remove-peer":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk wg remove-peer <pubkey>")
		}
		return b.RemoveWGPeer(args[1])
	case "prune":
		fs := flag.NewFlagSet("wg prune", flag.ExitOnError)
		maxAge := fs.Int("max-age", 0, "Max seconds since last handshake (0 = prune never-connected only)")
		_ = fs.Parse(args[1:])
		pruned, err := b.PruneWGPeers(*maxAge)
		if err != nil {
			return err
		}
		if len(pruned) == 0 {
			fmt.Println("no stale peers found")
			return nil
		}
		fmt.Printf("pruned %d stale peer(s):\n", len(pruned))
		for _, pk := range pruned {
			fmt.Printf("  %s\n", pk)
		}
		return nil
	default:
		return fmt.Errorf("unknown wg command: %s", args[0])
	}
}

func cmdLeases(b cli.Backend, outputFmt string) error {
	// Leases are read from a local file — in direct mode, read directly.
	// In API mode, call the API endpoint.
	if os.Getenv("GK_MODE") == "api" {
		client := cli.NewClient("", os.Getenv("GK_API_KEY")) // auto-detect URL
		data, err := client.Get("/api/v1/diag/leases")
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	}

	// Direct mode: parse lease file locally.
	data, err := os.ReadFile("/var/lib/misc/dnsmasq.leases")
	if err != nil {
		if os.IsNotExist(err) {
			return printJSON([]struct{}{})
		}
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	type lease struct {
		Expiry   string `json:"expiry"`
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	}
	var leases []lease
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			leases = append(leases, lease{Expiry: fields[0], MAC: fields[1], IP: fields[2], Hostname: fields[3]})
		}
	}
	if outputFmt == "table" {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "EXPIRY\tMAC\tIP\tHOSTNAME")
		for _, l := range leases {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Expiry, l.MAC, l.IP, l.Hostname)
		}
		return tw.Flush()
	}
	return printJSON(leases)
}

func cmdTest(b cli.Backend, args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	srcIP := fs.String("src", "", "Source IP")
	dstIP := fs.String("dst", "", "Destination IP")
	proto := fs.String("proto", "tcp", "Protocol (tcp, udp, icmp)")
	port := fs.Int("port", 0, "Destination port")
	_ = fs.Parse(args)
	if *srcIP == "" || *dstIP == "" {
		return fmt.Errorf("usage: gk test --src <ip> --dst <ip> [--proto tcp] [--port 80]")
	}
	result, err := b.PathTest(compiler.PathTestRequest{
		SrcIP: *srcIP, DstIP: *dstIP, Protocol: *proto, DstPort: *port,
	})
	if err != nil {
		return err
	}
	return printJSON(result)
}

func cmdPing(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk ping <target>")
	}
	target := args[0]
	// Validate target to prevent command injection.
	for _, c := range target {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':'
		if !valid {
			return fmt.Errorf("invalid target: must be an IP or hostname")
		}
	}
	cmd := newCommand("ping", "-c", "3", "-W", "2", target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdExplain(b cli.Backend, args []string, outputFmt string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	srcIP := fs.String("src", "", "Source IP")
	dstIP := fs.String("dst", "", "Destination IP")
	proto := fs.String("proto", "tcp", "Protocol (tcp, udp, icmp)")
	port := fs.Int("port", 0, "Destination port")
	_ = fs.Parse(args)
	if *srcIP == "" || *dstIP == "" {
		return fmt.Errorf("usage: gk explain --src <ip> --dst <ip> [--proto tcp] [--port 80]")
	}
	result, err := b.Explain(compiler.PathTestRequest{
		SrcIP: *srcIP, DstIP: *dstIP, Protocol: *proto, DstPort: *port,
	})
	if err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("Source zone: %s → Destination zone: %s\n", result.SrcZone, result.DstZone)
		fmt.Printf("Final action: %s\n\n", result.FinalAction)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ORDER\tPOLICY\tPROTO\tPORTS\tACTION\tMATCH\tDESCRIPTION")
		for _, r := range result.MatchingRules {
			match := " "
			if r.Matches {
				match = "*"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Order, r.PolicyName, r.Protocol, r.Ports, r.Action, match, r.Description)
		}
		tw.Flush()
		if len(result.Trace) > 0 {
			fmt.Println("\nTrace:")
			for _, t := range result.Trace {
				fmt.Printf("  %s\n", t)
			}
		}
		return nil
	}
	return printJSON(result)
}

func cmdAudit(b cli.Backend, outputFmt string) error {
	entries, err := b.ListAuditLog(100)
	if err != nil {
		return err
	}
	if outputFmt == "table" {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTIMESTAMP\tSOURCE\tACTION\tRESOURCE\tRESOURCE_ID")
		for _, e := range entries {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Timestamp, e.Source, e.Action, e.Resource, e.ResourceID)
		}
		return tw.Flush()
	}
	return printJSON(entries)
}

func cmdService(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk service <list|show|enable|disable|config> [options]")
	}

	// Services always use the API backend since the service manager lives in the daemon.
	client := cli.NewClient("", os.Getenv("GK_API_KEY")) // auto-detect URL

	switch args[0] {
	case "list":
		data, err := client.Get("/api/v1/services")
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk service show <name>")
		}
		data, err := client.Get("/api/v1/services/" + args[1])
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	case "schema":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk service schema <name>")
		}
		data, err := client.Get("/api/v1/services/" + args[1] + "/schema")
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	case "enable":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk service enable <name>")
		}
		data, err := client.Post("/api/v1/services/"+args[1]+"/enable", nil)
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	case "disable":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk service disable <name>")
		}
		data, err := client.Post("/api/v1/services/"+args[1]+"/disable", nil)
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	case "config":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk service config <name> [key=value ...]")
		}
		name := args[1]
		if len(args) == 2 {
			// Show current config.
			data, err := client.Get("/api/v1/services/" + name)
			if err != nil {
				return err
			}
			return printJSONRaw(data)
		}
		// Parse key=value pairs.
		cfg := make(map[string]string)
		for _, kv := range args[2:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid config format: %s (use key=value)", kv)
			}
			cfg[parts[0]] = parts[1]
		}
		data, err := client.Put("/api/v1/services/"+name+"/config", cfg)
		if err != nil {
			return err
		}
		return printJSONRaw(data)
	default:
		return fmt.Errorf("unknown service command: %s", args[0])
	}
}

func cmdDeps(args []string) error {
	pm, err := backend.DetectPackageManager()
	if err != nil {
		return err
	}
	fmt.Printf("Detected package manager: %s\n", pm.Name())

	subcmd := "check"
	if len(args) > 0 {
		subcmd = args[0]
	}

	switch subcmd {
	case "check":
		fmt.Println("Checking Gatekeeper dependencies...")
		installed, err := pm.EnsureDeps()
		if err != nil {
			return err
		}
		if len(installed) == 0 {
			fmt.Println("All dependencies are already installed.")
		} else {
			fmt.Printf("Installed %d package(s): %s\n", len(installed), strings.Join(installed, ", "))
		}
		return nil
	case "install":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk deps install <package> [package...]")
		}
		return pm.Install(args[1:]...)
	default:
		return fmt.Errorf("usage: gk deps <check|install> [packages...]")
	}
}

func cmdPerf(args []string, outputFmt string) error {
	subcmd := "status"
	if len(args) > 0 {
		subcmd = args[0]
	}

	switch subcmd {
	case "status":
		tuner := service.NewPerformanceTuner()
		status := tuner.GetPerfStatus()
		if outputFmt == "table" {
			fmt.Println("=== Conntrack ===")
			fmt.Printf("  Max entries:   %d\n", status.Conntrack.Max)
			fmt.Printf("  Buckets:       %d\n", status.Conntrack.Buckets)
			fmt.Printf("  Active:        %d\n", status.Conntrack.Count)
			fmt.Printf("  System RAM:    %d MB\n", status.Conntrack.RAMMB)
			fmt.Println()
			fmt.Println("=== TCP ===")
			fmt.Printf("  Congestion:    %s\n", status.TCPCongestion)
			fmt.Printf("  Fast Open:     %s\n", status.TCPFastOpen)
			fmt.Println()
			fmt.Println("=== Flowtables ===")
			fmt.Printf("  Enabled:       %v\n", status.Flowtables)
			if len(status.FlowtableZones) > 0 {
				fmt.Printf("  Zone filter:   %s\n", strings.Join(status.FlowtableZones, ", "))
			}
			if len(status.NotrackZones) > 0 {
				fmt.Printf("  Notrack zones: %s\n", strings.Join(status.NotrackZones, ", "))
			}
			if len(status.NICs) > 0 {
				fmt.Println()
				fmt.Println("=== NICs ===")
				tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tDRIVER\tSPEED\tRX_Q\tTX_Q\tIRQS\tTSO\tGRO\tGSO")
				for _, n := range status.NICs {
					speed := fmt.Sprintf("%d Mbps", n.SpeedMbps)
					if n.SpeedMbps < 0 {
						speed = "unknown"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%v\t%v\t%v\n",
						n.Name, n.Driver, speed, n.RxQueues, n.TxQueues, n.IRQs,
						n.Offloads["tso"], n.Offloads["gro"], n.Offloads["gso"])
				}
				tw.Flush()
			}
			return nil
		}
		return printJSON(status)

	case "conntrack":
		if len(args) > 1 && args[1] == "--max" && len(args) > 2 {
			// gk perf conntrack --max 262144
			// Configure conntrack_max via the service config API.
			client := cli.NewClient("", os.Getenv("GK_API_KEY"))
			cfg := map[string]string{"conntrack_max": args[2], "conntrack_auto": "false"}
			data, err := client.Put("/api/v1/services/performance-tuner/config", cfg)
			if err != nil {
				return err
			}
			return printJSONRaw(data)
		}
		// Show conntrack status.
		st := service.GetConntrackStatus()
		if outputFmt == "table" {
			fmt.Printf("Max entries:   %d\n", st.Max)
			fmt.Printf("Buckets:       %d\n", st.Buckets)
			fmt.Printf("Active:        %d\n", st.Count)
			fmt.Printf("Usage:         %.1f%%\n", float64(st.Count)/float64(max(st.Max, 1))*100)
			fmt.Printf("System RAM:    %d MB\n", st.RAMMB)
			return nil
		}
		return printJSON(st)

	case "nic":
		ifaces := detectCLIInterfaces()
		if len(args) > 1 {
			ifaces = args[1:]
		}
		nm := backend.NewLinuxNetworkManager()
		var nics []service.NICPerfInfo
		for _, iface := range ifaces {
			info, err := nm.NICInfo(iface)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", iface, err)
				continue
			}
			nics = append(nics, service.NICPerfInfo{
				Name:      info.Name,
				Driver:    info.Driver,
				SpeedMbps: info.SpeedMbps,
				RxQueues:  info.RxQueues,
				TxQueues:  info.TxQueues,
				IRQs:      len(info.IRQs),
				Offloads:  info.Offloads,
			})
		}
		if outputFmt == "table" {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tDRIVER\tSPEED\tRX_Q\tTX_Q\tIRQS\tTSO\tGRO\tGSO\tRX_CSUM\tTX_CSUM")
			for _, n := range nics {
				speed := fmt.Sprintf("%d Mbps", n.SpeedMbps)
				if n.SpeedMbps < 0 {
					speed = "unknown"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%v\t%v\t%v\t%v\t%v\n",
					n.Name, n.Driver, speed, n.RxQueues, n.TxQueues, n.IRQs,
					n.Offloads["tso"], n.Offloads["gro"], n.Offloads["gso"],
					n.Offloads["rx_checksum"], n.Offloads["tx_checksum"])
			}
			return tw.Flush()
		}
		return printJSON(nics)

	default:
		return fmt.Errorf("usage: gk perf <status|conntrack|nic> [options]")
	}
}

// detectCLIInterfaces returns non-loopback, up interfaces for CLI use.
func detectCLIInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	return result
}

func printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func printJSONRaw(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return nil
	}
	return printJSON(v)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: gk <command> [options]

Commands:
  status      Show daemon status
  zone        Manage zones (list, show, create, delete)
  alias       Manage aliases (list, show, create, delete, add-member)
  profile     Manage profiles (list, show, create)
  policy      Manage policies (list, show)
  assign      Assign device to profile
  unassign    Remove device assignment
  commit      Commit pending changes
  rollback    Rollback to a previous revision
  diff        Show config differences between revisions
  export      Export configuration as JSON
  import      Import configuration from JSON file
  wg          Manage WireGuard peers (peers, add-peer, remove-peer, prune)
  leases      Show DHCP leases
  test        Test packet path (--src <ip> --dst <ip> [--proto tcp] [--port 80])
  explain     Show all matching rules for a src→dst pair
  audit       Show audit log of mutations
  service     Manage services (list, show, enable, disable, config)
  perf        Performance tuning (status, conntrack, nic)
  ping        Ping a target host
  deps        Manage system dependencies (check, install)
  version     Show version

Environment:
  GK_MODE     Backend mode: direct (default) or api
  GK_DB       SQLite database path (direct mode, default: /var/lib/gatekeeper/gatekeeper.db)
  GK_API_URL  API base URL (api mode, auto-detects http/https)
  GK_API_KEY  API key for authentication (api mode)
  GK_OUTPUT   Output format: json (default) or table`)
}

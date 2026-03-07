package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gatekeeper-firewall/gatekeeper/internal/cli"
)

var version = "dev"

func main() {
	apiURL := os.Getenv("GK_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
	apiKey := os.Getenv("GK_API_KEY")
	// Reserved for future table/json output format toggle.
	_ = os.Getenv("GK_OUTPUT")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	client := cli.NewClient(apiURL, apiKey)
	cmd := os.Args[1]

	var err error
	switch cmd {
	case "version":
		fmt.Printf("gk %s\n", version)
		return
	case "status":
		err = cmdStatus(client)
	case "zone":
		err = cmdZone(client, os.Args[2:])
	case "alias":
		err = cmdAlias(client, os.Args[2:])
	case "profile":
		err = cmdProfile(client, os.Args[2:])
	case "policy":
		err = cmdPolicy(client, os.Args[2:])
	case "assign":
		err = cmdAssign(client, os.Args[2:])
	case "unassign":
		err = cmdUnassign(client, os.Args[2:])
	case "commit":
		err = cmdCommit(client, os.Args[2:])
	case "rollback":
		err = cmdRollback(client, os.Args[2:])
	case "diff":
		err = cmdDiff(client, os.Args[2:])
	case "export":
		err = cmdExport(client)
	case "import":
		err = cmdImport(client, os.Args[2:])
	case "wg":
		err = cmdWG(client, os.Args[2:])
	case "leases":
		err = cmdLeases(client)
	case "test":
		err = cmdTest(client, os.Args[2:])
	case "ping":
		err = cmdPing(client, os.Args[2:])
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

func cmdStatus(c *cli.Client) error {
	data, err := c.Get("/api/v1/status")
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdZone(c *cli.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk zone <list|show|create|delete> [options]")
	}
	switch args[0] {
	case "list":
		data, err := c.Get("/api/v1/zones")
		if err != nil {
			return err
		}
		return printJSON(data)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk zone show <name>")
		}
		data, err := c.Get("/api/v1/zones/" + args[1])
		if err != nil {
			return err
		}
		return printJSON(data)
	case "create":
		fs := flag.NewFlagSet("zone create", flag.ExitOnError)
		name := fs.String("name", "", "Zone name")
		iface := fs.String("interface", "", "Network interface")
		cidr := fs.String("cidr", "", "Network CIDR")
		trust := fs.String("trust", "none", "Trust level")
		_ = fs.Parse(args[1:])
		data, err := c.Post("/api/v1/zones", map[string]string{
			"name": *name, "interface": *iface, "network_cidr": *cidr, "trust_level": *trust,
		})
		if err != nil {
			return err
		}
		return printJSON(data)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk zone delete <name>")
		}
		data, err := c.Delete("/api/v1/zones/"+args[1], nil)
		if err != nil {
			return err
		}
		return printJSON(data)
	default:
		return fmt.Errorf("unknown zone command: %s", args[0])
	}
}

func cmdAlias(c *cli.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk alias <list|show|create|delete|add-member|remove-member>")
	}
	switch args[0] {
	case "list":
		data, err := c.Get("/api/v1/aliases")
		if err != nil {
			return err
		}
		return printJSON(data)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk alias show <name>")
		}
		data, err := c.Get("/api/v1/aliases/" + args[1])
		if err != nil {
			return err
		}
		return printJSON(data)
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
		data, err := c.Post("/api/v1/aliases", map[string]any{
			"name": *name, "type": *typ, "members": memberList,
		})
		if err != nil {
			return err
		}
		return printJSON(data)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk alias delete <name>")
		}
		data, err := c.Delete("/api/v1/aliases/"+args[1], nil)
		if err != nil {
			return err
		}
		return printJSON(data)
	case "add-member":
		if len(args) < 3 {
			return fmt.Errorf("usage: gk alias add-member <alias> <member>")
		}
		data, err := c.Post("/api/v1/aliases/"+args[1]+"/members", map[string]string{"member": args[2]})
		if err != nil {
			return err
		}
		return printJSON(data)
	default:
		return fmt.Errorf("unknown alias command: %s", args[0])
	}
}

func cmdProfile(c *cli.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk profile <list|show|create>")
	}
	switch args[0] {
	case "list":
		data, err := c.Get("/api/v1/profiles")
		if err != nil {
			return err
		}
		return printJSON(data)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk profile show <name>")
		}
		data, err := c.Get("/api/v1/profiles/" + args[1])
		if err != nil {
			return err
		}
		return printJSON(data)
	case "create":
		fs := flag.NewFlagSet("profile create", flag.ExitOnError)
		name := fs.String("name", "", "Profile name")
		zoneID := fs.Int("zone-id", 0, "Zone ID")
		policy := fs.String("policy", "", "Policy name")
		_ = fs.Parse(args[1:])
		data, err := c.Post("/api/v1/profiles", map[string]any{
			"name": *name, "zone_id": *zoneID, "policy_name": *policy,
		})
		if err != nil {
			return err
		}
		return printJSON(data)
	default:
		return fmt.Errorf("unknown profile command: %s", args[0])
	}
}

func cmdPolicy(c *cli.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk policy <list|show>")
	}
	switch args[0] {
	case "list":
		data, err := c.Get("/api/v1/policies")
		if err != nil {
			return err
		}
		return printJSON(data)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk policy show <name>")
		}
		data, err := c.Get("/api/v1/policies/" + args[1])
		if err != nil {
			return err
		}
		return printJSON(data)
	default:
		return fmt.Errorf("unknown policy command: %s", args[0])
	}
}

func cmdAssign(c *cli.Client, args []string) error {
	fs := flag.NewFlagSet("assign", flag.ExitOnError)
	profile := fs.String("profile", "", "Profile name")
	hostname := fs.String("hostname", "", "Device hostname")
	mac := fs.String("mac", "", "MAC address")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: gk assign <ip> --profile <name> [--hostname <name>] [--mac <addr>]")
	}
	ip := fs.Arg(0)
	data, err := c.Post("/api/v1/assign", map[string]string{
		"ip": ip, "profile": *profile, "hostname": *hostname, "mac": *mac,
	})
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdUnassign(c *cli.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk unassign <ip>")
	}
	data, err := c.Delete("/api/v1/unassign", map[string]string{"ip": args[0]})
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdCommit(c *cli.Client, args []string) error {
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
	data, err := c.Post("/api/v1/config/commit", map[string]string{"message": msg})
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdRollback(c *cli.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk rollback <rev>")
	}
	data, err := c.Post("/api/v1/config/rollback/"+args[0], nil)
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdDiff(c *cli.Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gk diff <rev1> <rev2>")
	}
	rev1, _ := strconv.Atoi(args[0])
	rev2, _ := strconv.Atoi(args[1])
	data, err := c.Get(fmt.Sprintf("/api/v1/config/diff?rev1=%d&rev2=%d", rev1, rev2))
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdExport(c *cli.Client) error {
	data, err := c.Get("/api/v1/config/export")
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdImport(c *cli.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk import <file.json>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	var snap any
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	result, err := c.Post("/api/v1/config/import", snap)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func cmdWG(c *cli.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gk wg <peers|add-peer|remove-peer>")
	}
	switch args[0] {
	case "peers":
		data, err := c.Get("/api/v1/wg/peers")
		if err != nil {
			return err
		}
		return printJSON(data)
	case "add-peer":
		fs := flag.NewFlagSet("wg add-peer", flag.ExitOnError)
		pubKey := fs.String("pubkey", "", "Peer public key")
		allowedIPs := fs.String("allowed-ips", "", "Allowed IPs (e.g. 10.50.0.2/32)")
		name := fs.String("name", "", "Peer name")
		_ = fs.Parse(args[1:])
		if *pubKey == "" || *allowedIPs == "" {
			return fmt.Errorf("usage: gk wg add-peer --pubkey <key> --allowed-ips <cidr> [--name <name>]")
		}
		data, err := c.Post("/api/v1/wg/peers", map[string]string{
			"public_key": *pubKey, "allowed_ips": *allowedIPs, "name": *name,
		})
		if err != nil {
			return err
		}
		return printJSON(data)
	case "remove-peer":
		if len(args) < 2 {
			return fmt.Errorf("usage: gk wg remove-peer <pubkey>")
		}
		data, err := c.Delete("/api/v1/wg/peers/"+args[1], nil)
		if err != nil {
			return err
		}
		return printJSON(data)
	default:
		return fmt.Errorf("unknown wg command: %s", args[0])
	}
}

func cmdLeases(c *cli.Client) error {
	data, err := c.Get("/api/v1/diag/leases")
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdTest(c *cli.Client, args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	srcIP := fs.String("src", "", "Source IP")
	dstIP := fs.String("dst", "", "Destination IP")
	proto := fs.String("proto", "tcp", "Protocol (tcp, udp, icmp)")
	port := fs.Int("port", 0, "Destination port")
	_ = fs.Parse(args)
	if *srcIP == "" || *dstIP == "" {
		return fmt.Errorf("usage: gk test --src <ip> --dst <ip> [--proto tcp] [--port 80]")
	}
	data, err := c.Post("/api/v1/test", map[string]any{
		"src_ip": *srcIP, "dst_ip": *dstIP, "protocol": *proto, "dst_port": *port,
	})
	if err != nil {
		return err
	}
	return printJSON(data)
}

func cmdPing(c *cli.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gk ping <target>")
	}
	data, err := c.Get("/api/v1/diag/ping/" + args[0])
	if err != nil {
		return err
	}
	return printJSON(data)
}

func printJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return nil
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
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
  wg          Manage WireGuard peers (peers, add-peer, remove-peer)
  leases      Show DHCP leases
  test        Test packet path (--src <ip> --dst <ip> [--proto tcp] [--port 80])
  ping        Ping a target host
  version     Show version

Environment:
  GK_API_URL  API base URL (default: http://localhost:8080)
  GK_API_KEY  API key for authentication`)
}

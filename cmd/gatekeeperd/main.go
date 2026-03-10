package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/api"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
	"github.com/gatekeeper-firewall/gatekeeper/internal/mcp"
	"github.com/gatekeeper-firewall/gatekeeper/internal/ops"
	"github.com/gatekeeper-firewall/gatekeeper/internal/plugin"
	"github.com/gatekeeper-firewall/gatekeeper/internal/service"
	"github.com/gatekeeper-firewall/gatekeeper/internal/web"
)

var (
	version     = "dev"
	listen      = flag.String("listen", ":8080", "API listen address")
	dbPath      = flag.String("db", "/var/lib/gatekeeper/gatekeeper.db", "SQLite database path")
	apiKey      = flag.String("api-key", "", "API key for authentication (empty = no auth)")
	rulesetDir  = flag.String("ruleset-dir", "/var/lib/gatekeeper/rulesets", "Directory for nftables rulesets")
	dnsmasqDir  = flag.String("dnsmasq-dir", "/etc/dnsmasq.d", "Directory for dnsmasq config")
	wgInterface = flag.String("wg-interface", "", "WireGuard interface name (empty = disabled)")
	tlsCert     = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey      = flag.String("tls-key", "", "TLS private key file")
	pluginDir   = flag.String("plugin-dir", "/var/lib/gatekeeper/plugins", "Plugin directory")
	enableMCP   = flag.Bool("enable-mcp", false, "Enable MCP (Model Context Protocol) server")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting gatekeeperd", "version", version, "listen", *listen)

	store, err := config.NewStore(*dbPath)
	if err != nil {
		slog.Error("failed to open config store", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	if err := store.Seed(); err != nil {
		slog.Error("failed to seed defaults", "error", err)
		os.Exit(1)
	}

	nft := driver.NewNFTables(store, *rulesetDir)

	// Boot-time safe mode: attempt to apply last known config.
	// On failure, log the error but continue starting the daemon so the
	// operator can fix the config via API/CLI rather than losing access.
	if err := nft.SafeApply(); err != nil {
		slog.Warn("boot-time rule apply failed, starting in safe mode", "error", err)
	}

	dnsmasq := driver.NewDnsmasq(store, *dnsmasqDir)

	var wg *driver.WireGuard
	if *wgInterface != "" {
		wg = driver.NewWireGuard("/etc/wireguard", *wgInterface)
		if err := wg.Init(); err != nil {
			slog.Error("failed to initialize wireguard", "error", err)
			os.Exit(1)
		}
	}

	// Write PID file so the CLI can signal us for applies.
	pidDir := "/run/gatekeeper"
	pidFile := filepath.Join(pidDir, "gatekeeperd.pid")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		slog.Warn("failed to create PID directory", "error", err)
	} else {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			slog.Warn("failed to write PID file", "error", err)
		} else {
			defer os.Remove(pidFile)
		}
	}

	// Initialize the pluggable service manager.
	svcMgr, err := service.NewManager(store.DB())
	if err != nil {
		slog.Error("failed to initialize service manager", "error", err)
		os.Exit(1)
	}

	// Register all available services.
	svcMgr.Register(service.NewDNSFilter(*dnsmasqDir, "/var/cache/gatekeeper/dns"))
	svcMgr.Register(service.NewAvahi("/etc/avahi"))
	svcMgr.Register(service.NewSamba("/etc/samba"))
	svcMgr.Register(service.NewBridge("/etc/systemd/network"))
	svcMgr.Register(service.NewDDNS())
	svcMgr.Register(service.NewUPnP("/etc/miniupnpd"))
	svcMgr.Register(service.NewNTP("/etc/chrony"))
	svcMgr.Register(service.NewCaptivePortal("/var/lib/gatekeeper/captive-portal"))
	svcMgr.Register(service.NewBandwidth("/var/lib/gatekeeper/qos"))
	svcMgr.Register(service.NewEncryptedDNS("/etc/unbound/unbound.conf.d"))
	svcMgr.Register(service.NewIDS("/etc/suricata", "/var/log/suricata"))
	svcMgr.Register(service.NewMultiWAN("/var/lib/gatekeeper/multiwan"))
	svcMgr.Register(service.NewBandwidthMonitor("/var/lib/gatekeeper/bandwidth"))

	// V2 services: VPN legs, VPN providers, FRRouting, certificate store.
	svcMgr.Register(service.NewVPNLegs("/var/lib/gatekeeper/vpn-legs"))
	svcMgr.Register(service.NewVPNProvider())
	svcMgr.Register(service.NewFRRouting("/etc/frr"))
	svcMgr.Register(service.NewCertStore())

	// HA service (wrapped for Service interface compatibility).
	svcMgr.Register(service.NewHAWrapper())

	// IPv6 Router Advertisement service.
	svcMgr.Register(service.NewIPv6RA())

	// Plugin system.
	pluginMgr := plugin.NewManager(logger, false)
	if err := pluginMgr.LoadPlugins(*pluginDir); err != nil {
		slog.Warn("failed to load plugins", "error", err)
	}

	// Start all previously-enabled services.
	svcMgr.StartEnabled()

	// Handle SIGHUP: the CLI sends this after writing a commit/rollback
	// to the DB, signaling the daemon to re-apply the config.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("received SIGHUP, re-applying config")
			if err := nft.Apply(); err != nil {
				slog.Error("SIGHUP apply failed", "error", err)
			} else {
				slog.Info("config applied successfully via SIGHUP")
			}
		}
	}()

	metrics := api.NewMetrics()
	apiHandler := api.NewRouterWithConfig(&api.RouterConfig{
		Store:      store,
		NFT:        nft,
		WG:         wg,
		Dnsmasq:    dnsmasq,
		APIKey:     *apiKey,
		Metrics:    metrics,
		ServiceMgr: svcMgr,
	})
	webHandler := web.Handler(store, svcMgr)

	// MCP server (optional).
	var mcpHandler http.Handler
	if *enableMCP {
		o := ops.New(store)
		mcpSrv := mcp.New(mcp.MCPConfig{
			Ops:        o,
			NFT:        nft,
			WG:         wg,
			Dnsmasq:    dnsmasq,
			ServiceMgr: svcMgr,
		})
		mcpHandler = mcpSrv.Handler()
		slog.Info("MCP server enabled")
	}

	// Combine: /api/* goes to API, /mcp/* to MCP, everything else to web UI.
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	if mcpHandler != nil {
		mux.Handle("/mcp/", mcpHandler)
	}
	// Plugin diagnostic routes.
	for path, handler := range pluginMgr.GetRoutes() {
		mux.Handle(path, handler)
	}
	mux.Handle("/", webHandler)
	router := mux

	srv := &http.Server{
		Addr:              *listen,
		Handler:           router,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if *tlsCert != "" && *tlsKey != "" {
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
			}
			slog.Info("listening (TLS)", "addr", *listen)
			if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "error", err)
				os.Exit(1)
			}
		} else {
			slog.Info("listening", "addr", *listen)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	// Stop all running services gracefully.
	svcMgr.StopAll()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	fmt.Println("gatekeeperd stopped")
}

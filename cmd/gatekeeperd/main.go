package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gatekeeper-firewall/gatekeeper/internal/api"
	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
	"github.com/gatekeeper-firewall/gatekeeper/internal/driver"
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

	metrics := api.NewMetrics()
	apiHandler := api.NewRouterWithConfig(&api.RouterConfig{
		Store:   store,
		NFT:     nft,
		WG:      wg,
		Dnsmasq: dnsmasq,
		APIKey:  *apiKey,
		Metrics: metrics,
	})
	webHandler := web.Handler(store)

	// Combine: /api/* goes to API, everything else to web UI.
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", webHandler)
	router := mux

	srv := &http.Server{
		Addr:              *listen,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if *tlsCert != "" && *tlsKey != "" {
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	fmt.Println("gatekeeperd stopped")
}

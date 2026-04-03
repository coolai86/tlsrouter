package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tlsrouter "github.com/bnnanet/tlsrouter/v2"
)

const (
	name         = "tlsrouter"
	licenseYear  = "2025"
	licenseOwner = "AJ ONeal"
	licenseType  = "MPL-2.0"
)

var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01T00:00:00Z"
)

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(w, "Licensed under the %s license\n", licenseType)
}

func printUsage(fs *flag.FlagSet) {
	printVersion(os.Stdout)
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintf(os.Stdout, "Usage: %s [options] [routes.csv]\n\n", name)
	fmt.Fprintln(os.Stdout, "Options:")
	fs.SetOutput(os.Stdout)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Environment Variables:")
	fmt.Fprintln(os.Stdout, "  IP_DOMAINS     Comma-separated list of IP domains for dynamic routing")
	fmt.Fprintln(os.Stdout, "  NETWORKS       Comma-separated list of allowed CIDR networks")
	fmt.Fprintln(os.Stdout, "  ACME_BACKEND   Global ACME challenge backend (host:port)")
	fmt.Fprintln(os.Stdout, "  ACME_BACKENDS  Per-domain ACME backends (domain1=backend1,domain2=backend2)")
}

func main() {
	// Handle version and help before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			fs := flag.NewFlagSet(name, flag.ContinueOnError)
			defineFlags(fs)
			printUsage(fs)
			os.Exit(0)
		}
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		printUsage(fs)
	}

	cfg := defineFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	if err := loadConfig(fs, cfg); err != nil {
		log.Fatalf("config error: %v", err)
	}

	// Build router
	router, err := buildRouter(cfg)
	if err != nil {
		log.Fatalf("router build error: %v", err)
	}

	// Build cert provider
	var certProvider tlsrouter.CertProvider
	if cfg.Certmagic.Email != "" || cfg.Certmagic.DirectoryURL != "" {
		// Use certmagic for real ACME
		certProvider, err = tlsrouter.NewCertmagicCertProvider(cfg.Certmagic)
		if err != nil {
			log.Fatalf("certmagic error: %v", err)
		}
		log.Printf("using certmagic for ACME (email: %s)", cfg.Certmagic.Email)
	} else {
		// Use mock certs for testing
		certProvider = tlsrouter.NewMockCertProvider()
		log.Printf("using mock certificates (no ACME)")
	}

	// Build handler
	handler := &tlsrouter.Handler{
		Router: router,
		Certs:  certProvider,
		Dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}

	// Set initial config (atomic)
	routerCfg := &tlsrouter.Config{
		StaticRoutes:    cfg.StaticRoutes,
		IPDomains:       cfg.IPDomains,
		Networks:        cfg.Networks,
		ACMEPassthrough: cfg.ACMEPassthrough,
		ACMEBackends:    cfg.ACMEBackends,
		Certmagic:       cfg.Certmagic,
	}
	handler.SetConfig(routerCfg)

	// Build server
	server := tlsrouter.NewServer(cfg.Addr, handler)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	// Note: syscall.SIGTERM = 15, syscall.SIGINT = 2
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("starting %s on %s", name, cfg.Addr)
		serverErr <- server.ListenAndServe()
	}()

	// Wait for signal or error
	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("received signal %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		log.Println("shutdown complete")
	}
}

// config holds all configuration.
type config struct {
	Addr            string
	StaticRoutes    map[string]tlsrouter.StaticRoute
	IPDomains       []string
	Networks        []net.IPNet
	ACMEPassthrough string
	ACMEBackends    map[string]string
	Certmagic       tlsrouter.CertmagicConfig

	// Parsed from flags
	csvPath   string
	acmeEmail string
	acmeDir   string
	acmeAgree bool
}

// defineFlags creates flags and returns config with defaults.
func defineFlags(fs *flag.FlagSet) *config {
	cfg := &config{
		StaticRoutes: make(map[string]tlsrouter.StaticRoute),
		ACMEBackends: make(map[string]string),
		Certmagic: tlsrouter.CertmagicConfig{
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: false,
		},
	}

	fs.StringVar(&cfg.Addr, "addr", ":443", "Address to listen on")
	// -bind is an alias for -addr (kept for backward compatibility)
	fs.StringVar(&cfg.Addr, "bind", ":443", "Address to listen on (alias for addr)")
	// Note: -h is reserved for --human-readable (not --help)
	// Note: -v is reserved for --verbose (not --version)

	fs.StringVar(&cfg.csvPath, "routes", "", "Path to routes CSV file")
	fs.StringVar(&cfg.acmeEmail, "acme-email", "", "Email for ACME registration")
	fs.StringVar(&cfg.acmeDir, "acme-dir", "", "ACME directory URL (default: Let's Encrypt)")
	fs.BoolVar(&cfg.acmeAgree, "acme-agree", false, "Agree to ACME terms")

	return cfg
}

// loadConfig loads configuration from file and environment.
func loadConfig(fs *flag.FlagSet, cfg *config) error {
	// Load static routes from CSV (positional arg takes precedence over -routes flag)
	csvPath := fs.Arg(0)
	if csvPath == "" {
		csvPath = cfg.csvPath
	}
	if csvPath != "" {
		routes, err := loadStaticRoutes(csvPath)
		if err != nil {
			return fmt.Errorf("loading static routes: %w", err)
		}
		maps.Copy(cfg.StaticRoutes, routes)
	}

	// Load dynamic config from env
	if ipDomains := os.Getenv("IP_DOMAINS"); ipDomains != "" {
		cfg.IPDomains = parseStringList(ipDomains)
	}
	if networks := os.Getenv("NETWORKS"); networks != "" {
		nets, err := parseNetworkList(networks)
		if err != nil {
			return fmt.Errorf("parsing networks: %w", err)
		}
		cfg.Networks = nets
	}

	// Load ACME backend from env
	if acmeBackend := os.Getenv("ACME_BACKEND"); acmeBackend != "" {
		cfg.ACMEPassthrough = acmeBackend
	}

	// Load per-domain ACME backends
	if acmeBackends := os.Getenv("ACME_BACKENDS"); acmeBackends != "" {
		// Format: domain1=backend1,domain2=backend2
		for pair := range strings.SplitSeq(acmeBackends, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				cfg.ACMEBackends[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Set certmagic config from flags
	cfg.Certmagic.Email = cfg.acmeEmail
	cfg.Certmagic.DirectoryURL = cfg.acmeDir
	cfg.Certmagic.Agreed = cfg.acmeAgree

	return nil
}

// buildRouter creates the router from config.
func buildRouter(cfg *config) (tlsrouter.Router, error) {
	routers := []tlsrouter.Router{}

	// Add static router if we have static routes
	if len(cfg.StaticRoutes) > 0 {
		routers = append(routers, tlsrouter.NewStaticRouter(cfg.StaticRoutes))
	}

	// Add dynamic router if we have IP domains
	if len(cfg.IPDomains) > 0 && len(cfg.Networks) > 0 {
		dynamicRouter := tlsrouter.NewDynamicRouter(cfg.IPDomains, cfg.Networks)
		routers = append(routers, dynamicRouter)
	}

	// Layer them together
	if len(routers) == 0 {
		return nil, fmt.Errorf("no routes configured")
	}
	if len(routers) == 1 {
		return routers[0], nil
	}

	return &tlsrouter.LayeredRouter{Routers: routers}, nil
}

// parseStringList parses comma-separated string list.
func parseStringList(s string) []string {
	var result []string
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// parseNetworkList parses comma-separated CIDR networks.
func parseNetworkList(s string) ([]net.IPNet, error) {
	var result []net.IPNet
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", item, err)
		}
		result = append(result, *ipNet)
	}
	return result, nil
}

// loadStaticRoutes loads routes from CSV file.
func loadStaticRoutes(path string) (map[string]tlsrouter.StaticRoute, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	routes := make(map[string]tlsrouter.StaticRoute)

	for _, record := range records {
		if len(record) < 4 {
			continue
		}

		domain := strings.TrimSpace(record[0])
		alpn := strings.TrimSpace(record[1])
		backend := strings.TrimSpace(record[2])
		action := strings.TrimSpace(record[3])

		if domain == "" || backend == "" {
			continue
		}

		if alpn == "" {
			alpn = "*"
		}

		routeAction := tlsrouter.ActionTerminate
		if strings.EqualFold(action, "passthrough") || strings.EqualFold(action, "tcp") {
			routeAction = tlsrouter.ActionPassthrough
		}

		key := domain + ">" + alpn
		routes[key] = tlsrouter.StaticRoute{
			Backend: backend,
			Action:  routeAction,
			ALPN:    alpn,
		}
	}

	return routes, nil
}

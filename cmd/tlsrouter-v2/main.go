package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
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

// set by GoReleaser via ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01T00:00:00Z"
)

func printVersion() {
	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

func main() {
	// Define flags first
	addr := flag.String("addr", ":443", "Address to listen on")
	flag.StringVar(addr, "bind", ":443", "Address to listen on (alias for addr)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	showHelp := flag.Bool("help", false, "Show usage")
	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	if *showHelp {
		printVersion()
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options] [routes.csv]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  IP_DOMAINS     Comma-separated list of IP domains for dynamic routing\n")
		fmt.Fprintf(os.Stderr, "  NETWORKS       Comma-separated list of allowed CIDR networks\n")
		os.Exit(0)
	}

	// Parse configuration
	cfg, err := loadConfig(*addr)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// Build router
	router, err := buildRouter(cfg)
	if err != nil {
		log.Fatalf("router build error: %v", err)
	}

	// Build handler
	handler := &tlsrouter.Handler{
		Router: router,
		Certs:  tlsrouter.NewMockCertProvider(), // TODO: switch to certmagic
		Dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}

	// Build server
	server := tlsrouter.NewServer(cfg.Addr, handler)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
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

type config struct {
	Addr        string
	StaticRoutes  map[string]tlsrouter.StaticRoute
	IPDomains    []string
	Networks     []net.IPNet
}

func loadConfig(addr string) (*config, error) {
	cfg := &config{
		Addr:          addr,
		IPDomains:     []string{},
		Networks:      []net.IPNet{},
		StaticRoutes:  make(map[string]tlsrouter.StaticRoute),
	}

	// Load static routes from CSV (first non-flag argument)
	if csvPath := flag.Arg(0); csvPath != "" {
		routes, err := loadStaticRoutes(csvPath)
		if err != nil {
			return nil, fmt.Errorf("loading static routes: %w", err)
		}
		for k, v := range routes {
			cfg.StaticRoutes[k] = v
		}
	}

	// Load dynamic config from env
	if ipDomains := os.Getenv("IP_DOMAINS"); ipDomains != "" {
		cfg.IPDomains = parseStringList(ipDomains)
	}
	if networks := os.Getenv("NETWORKS"); networks != "" {
		nets, err := parseNetworkList(networks)
		if err != nil {
			return nil, fmt.Errorf("parsing networks: %w", err)
		}
		cfg.Networks = nets
	}

	return cfg, nil
}

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

func parseStringList(s string) []string {
	var result []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseNetworkList(s string) ([]net.IPNet, error) {
	var result []net.IPNet
	for _, item := range strings.Split(s, ",") {
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
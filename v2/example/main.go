// Example main showing how to use the clean tlsrouter v2 design.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	tlsrouter "github.com/bnnanet/tlsrouter/v2"
)

func main() {
	// 1. Create static routes
	staticRouter := tlsrouter.NewStaticRouter(map[string]tlsrouter.StaticRoute{
		// Terminate TLS for HTTP traffic
		"myapp.example.com>http/1.1": {
			Backend: "127.0.0.1:3080",
			Action:  tlsrouter.ActionTerminate,
		},
		"myapp.example.com>h2": {
			Backend: "127.0.0.1:3080",
			Action:  tlsrouter.ActionTerminate,
		},
		// Passthrough for raw TLS
		"raw.example.com>h2": {
			Backend: "127.0.0.1:8443",
			Action:  tlsrouter.ActionPassthrough,
		},
		// Wildcard for subdomains
		".example.com>http/1.1": {
			Backend: "127.0.0.1:3080",
			Action:  tlsrouter.ActionTerminate,
		},
	})

	// 2. Create dynamic router for IP-in-hostname routing
	_, network1, _ := net.ParseCIDR("192.168.1.0/24")
	_, network2, _ := net.ParseCIDR("10.0.0.0/8")

	dynamicRouter := tlsrouter.NewDynamicRouter(
		[]string{"vm.example.com", "local.example.net"},
		[]net.IPNet{*network1, *network2},
	)

	// 3. Layer routers: static first, then dynamic
	router := &tlsrouter.LayeredRouter{
		Routers: []tlsrouter.Router{
			staticRouter,
			dynamicRouter,
		},
	}

	// 4. Create certificate provider (implement CertProvider interface)
	certProvider := &simpleCertProvider{
		certs: make(map[string]tlsrouter.Certificate),
	}

	// 5. Create handler
	handler := &tlsrouter.Handler{
		Router: router,
		Certs:  certProvider,
		Dialer: &net.Dialer{},
	}

	// 6. Create and start server
	server := tlsrouter.NewServer(":443", handler)

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Println("Starting TLS router on :443")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// simpleCertProvider implements CertProvider with static certificates.
type simpleCertProvider struct {
	certs map[string]tlsrouter.Certificate
}

func (p *simpleCertProvider) GetCertificate(domain string) (tlsrouter.Certificate, error) {
	cert, ok := p.certs[domain]
	if !ok {
		return tlsrouter.Certificate{}, fmt.Errorf("no certificate for %q", domain)
	}
	return cert, nil
}

func (p *simpleCertProvider) AddCertificate(domain string, cert tlsrouter.Certificate) {
	p.certs[domain] = cert
}

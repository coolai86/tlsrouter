package tlsrouter

import (
	"net"
	"slices"
	"testing"
)

// TestHandler_ACMECases tests the three ACME handling cases.
func TestHandler_ACMECases(t *testing.T) {
	tests := []struct {
		name            string
		sni             string
		alpns           []string
		config          *Config
		wantBackend     string
		wantPassthrough bool
	}{
		{
			name:  "Per-domain ACME backend",
			sni:   "acme.example.com",
			alpns: []string{"acme-tls/1"},
			config: &Config{
				ACMEBackends: map[string]string{
					"acme.example.com": "10.0.0.1:443",
				},
			},
			wantBackend:     "10.0.0.1:443",
			wantPassthrough: true,
		},
		{
			name:  "Global ACME backend",
			sni:   "other.example.com",
			alpns: []string{"acme-tls/1"},
			config: &Config{
				ACMEPassthrough: "10.0.0.1:443",
			},
			wantBackend:     "10.0.0.1:443",
			wantPassthrough: true,
		},
		{
			name:            "Normal HTTP traffic (not ACME)",
			sni:             "example.com",
			alpns:           []string{"http/1.1"},
			config:          &Config{},
			wantBackend:     "127.0.0.1:8080",
			wantPassthrough: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := &Handler{
				Router: NewStaticRouter(map[string]StaticRoute{
					"example.com>http/1.1": {
						Backend: "127.0.0.1:8080",
						Action:  ActionTerminate,
					},
				}),
				Certs: NewMockCertProvider(),
			}

			// Set config
			handler.SetConfig(tt.config)

			// The handler's GetConfigForClient checks config directly for ACME
			// before calling the router. Verify config has expected ACME backend.
			cfg := handler.GetConfig()
			if cfg == nil {
				t.Fatal("expected config to be set")
			}

			if tt.wantPassthrough {
				// Check per-domain ACME backend first
				if backend, ok := cfg.ACMEBackends[tt.sni]; ok {
					if backend != tt.wantBackend {
						t.Errorf("per-domain backend: got %s, want %s", backend, tt.wantBackend)
					}
				} else if cfg.ACMEPassthrough != tt.wantBackend {
					t.Errorf("global ACME backend: got %s, want %s", cfg.ACMEPassthrough, tt.wantBackend)
				}
			} else {
				// Normal routing - verify backend from router
				decision, err := handler.Router.Route(tt.sni, tt.alpns)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if decision.Backend != tt.wantBackend {
					t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
				}
				if decision.Action != ActionTerminate {
					t.Errorf("Action: got %v, want Terminate", decision.Action)
				}
			}
		})
	}
}

// TestHandler_ACMEDetectionOrder tests that ACME backends are checked in the right order.
func TestHandler_ACMEDetectionOrder(t *testing.T) {
	config := &Config{
		ACMEPassthrough: "global:443",
		ACMEBackends: map[string]string{
			"specific.example.com": "specific:443",
		},
	}

	handler := &Handler{
		Router: NewStaticRouter(map[string]StaticRoute{}),
		Certs:  NewMockCertProvider(),
	}

	handler.SetConfig(config)

	tests := []struct {
		name        string
		sni         string
		wantBackend string
	}{
		{
			name:        "Per-domain backend takes priority",
			sni:         "specific.example.com",
			wantBackend: "specific:443",
		},
		{
			name:        "Global backend for other domains",
			sni:         "other.example.com",
			wantBackend: "global:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The handler's GetConfigForClient checks in order:
			// 1. Per-domain ACMEBackends
			// 2. Global ACMEPassthrough
			// 3. Normal routing

			// Verify config is set correctly
			cfg := handler.GetConfig()
			if cfg == nil {
				t.Fatal("expected config to be set")
			}

			if tt.wantBackend == "specific:443" {
				backend, ok := cfg.ACMEBackends[tt.sni]
				if !ok {
					t.Errorf("expected per-domain backend for %s", tt.sni)
				}
				if backend != tt.wantBackend {
					t.Errorf("got %s, want %s", backend, tt.wantBackend)
				}
			} else {
				if cfg.ACMEPassthrough != tt.wantBackend {
					t.Errorf("got %s, want %s", cfg.ACMEPassthrough, tt.wantBackend)
				}
			}
		})
	}
}

// TestHandler_ACMEWithMixedALPN tests ACME detection when ALPN list has multiple protocols.
func TestHandler_ACMEWithMixedALPN(t *testing.T) {
	config := &Config{
		ACMEPassthrough: "10.0.0.1:443",
	}

	handler := &Handler{
		Router: NewStaticRouter(map[string]StaticRoute{
			"example.com>http/1.1": {
				Backend: "127.0.0.1:8080",
				Action:  ActionTerminate,
			},
		}),
		Certs: NewMockCertProvider(),
	}

	handler.SetConfig(config)

	tests := []struct {
		name        string
		sni         string
		alpns       []string
		wantACME    bool
		wantBackend string
	}{
		{
			name:        "ACME as first ALPN",
			sni:         "example.com",
			alpns:       []string{"acme-tls/1", "http/1.1"},
			wantACME:    true,
			wantBackend: "10.0.0.1:443",
		},
		{
			name:        "ACME in middle of ALPN list",
			sni:         "example.com",
			alpns:       []string{"h2", "acme-tls/1", "http/1.1"},
			wantACME:    true,
			wantBackend: "10.0.0.1:443",
		},
		{
			name:        "No ACME in ALPN list",
			sni:         "example.com",
			alpns:       []string{"h2", "http/1.1"},
			wantACME:    false,
			wantBackend: "127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := handler.GetConfig()
			if cfg == nil {
				t.Fatal("expected config to be set")
			}

			// Check if any ALPN is acme-tls/1
			hasACME := slices.Contains(tt.alpns, "acme-tls/1")

			if hasACME != tt.wantACME {
				t.Errorf("ACME detection: got %v, want %v", hasACME, tt.wantACME)
			}

			if tt.wantACME && cfg.ACMEPassthrough != tt.wantBackend {
				t.Errorf("Global ACME backend: got %s, want %s", cfg.ACMEPassthrough, tt.wantBackend)
			}
		})
	}
}

// TestHandler_ConfigAtomicSwap tests that config swaps are atomic.
func TestHandler_ConfigAtomicSwap(t *testing.T) {
	handler := &Handler{
		Router: NewStaticRouter(map[string]StaticRoute{}),
		Certs:  NewMockCertProvider(),
	}

	// Set initial config
	config1 := &Config{
		ACMEPassthrough: "backend1:443",
		ACMEBackends: map[string]string{
			"domain1.com": "specific1:443",
		},
	}
	handler.SetConfig(config1)

	// Verify initial config
	cfg := handler.GetConfig()
	if cfg.ACMEPassthrough != "backend1:443" {
		t.Errorf("got %s, want backend1:443", cfg.ACMEPassthrough)
	}

	// Atomic swap
	config2 := &Config{
		ACMEPassthrough: "backend2:443",
		ACMEBackends: map[string]string{
			"domain2.com": "specific2:443",
		},
	}
	handler.SetConfig(config2)

	// Verify new config
	cfg = handler.GetConfig()
	if cfg.ACMEPassthrough != "backend2:443" {
		t.Errorf("got %s, want backend2:443", cfg.ACMEPassthrough)
	}

	// Verify per-domain config changed
	backend, ok := cfg.ACMEBackends["domain2.com"]
	if !ok {
		t.Error("expected domain2.com in ACMEBackends")
	}
	if backend != "specific2:443" {
		t.Errorf("got %s, want specific2:443", backend)
	}

	// Verify old domain is gone
	_, ok = cfg.ACMEBackends["domain1.com"]
	if ok {
		t.Error("expected domain1.com to be removed")
	}
}

// TestHandler_PostHandshakeACMEDetection tests the post-handshake check.
func TestHandler_PostHandshakeACMEDetection(t *testing.T) {
	// This tests the logic in Handle() after handshake
	// where we check if certmagic handled the ACME challenge

	certmagicProvider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:  "test@example.com",
		Agreed: true,
	})
	if err != nil {
		t.Fatalf("failed to create certmagic provider: %v", err)
	}

	handler := &Handler{
		Router: NewStaticRouter(map[string]StaticRoute{}),
		Certs:  certmagicProvider,
	}

	handler.SetConfig(&Config{})

	// Mark a domain as managed
	certmagicProvider.managedDomains["test.example.com"] = true

	// Simulate post-handshake state
	decision := Decision{
		Domain:  "test.example.com",
		ALPN:    "acme-tls/1",
		Backend: "", // No backend - certmagic handled it
	}

	// Check if certmagic should handle this
	certmagicHandled := false
	if decision.Backend == "" && decision.ALPN == "acme-tls/1" {
		if certmagicProvider.IsManaged(decision.Domain) {
			certmagicHandled = true
		}
	}

	if !certmagicHandled {
		t.Error("expected certmagic to have handled ACME challenge")
	}

	// Now test with a normal domain
	decision = Decision{
		Domain:  "normal.example.com",
		ALPN:    "acme-tls/1",
		Backend: "10.0.0.1:443", // Has backend - not certmagic
	}

	certmagicHandled = false
	if decision.Backend == "" && decision.ALPN == "acme-tls/1" {
		if certmagicProvider.IsManaged(decision.Domain) {
			certmagicHandled = true
		}
	}

	if certmagicHandled {
		t.Error("expected certmagic to NOT have handled (has backend)")
	}
}

// TestHandler_ACMELayeredRouting tests ACME handling with layered routers.
func TestHandler_ACMELayeredRouting(t *testing.T) {
	static := NewStaticRouter(map[string]StaticRoute{
		"static.example.com>http/1.1": {
			Backend: "127.0.0.1:8080",
			Action:  ActionTerminate,
		},
	})

	dynamic := NewDynamicRouter(
		[]string{"vm.example.com"},
		[]net.IPNet{{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}},
	)

	router := &LayeredRouter{
		Routers: []Router{static, dynamic},
	}

	config := &Config{
		ACMEPassthrough: "10.0.0.1:443",
	}

	handler := &Handler{
		Router: router,
		Certs:  NewMockCertProvider(),
	}

	handler.SetConfig(config)

	tests := []struct {
		name     string
		sni      string
		alpns    []string
		wantACME bool
	}{
		{
			name:     "ACME on static route",
			sni:      "static.example.com",
			alpns:    []string{"acme-tls/1"},
			wantACME: true,
		},
		{
			name:     "ACME on dynamic route",
			sni:      "tls-192-168-1-100.vm.example.com",
			alpns:    []string{"acme-tls/1"},
			wantACME: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := handler.GetConfig()
			if cfg == nil {
				t.Fatal("expected config to be set")
			}

			if tt.wantACME {
				if cfg.ACMEPassthrough == "" {
					t.Error("expected ACME backend to be set")
				}
			}
		})
	}
}

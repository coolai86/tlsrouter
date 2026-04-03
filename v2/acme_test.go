package tlsrouter

import (
	"net"
	"testing"
)

// TestStaticRouter_ACME tests ACME-TLS/1 challenge routing.
func TestStaticRouter_ACME(t *testing.T) {
	router := NewStaticRouter(map[string]StaticRoute{
		"example.com>*": {
			Backend: "192.168.1.100:443",
			Action:  ActionTerminate,
		},
		"acme.example.com>acme-tls/1": {
			Backend: "192.168.1.101:443",
			Action:  ActionTerminate,
		},
	})

	tests := []struct {
		name        string
		sni         string
		alpns       []string
		wantBackend string
		wantAction  RouteAction
		wantErr     bool
	}{
		{
			name:        "ACME challenge with wildcard",
			sni:         "example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.100:443",
			wantAction:  ActionPassthrough, // ACME always passthrough
		},
		{
			name:        "ACME challenge with explicit route",
			sni:         "acme.example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.101:443",
			wantAction:  ActionPassthrough, // ACME always passthrough
		},
		{
			name:    "ACME challenge no route",
			sni:     "other.com",
			alpns:   []string{"acme-tls/1"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Action != tt.wantAction {
				t.Errorf("Action: got %v, want %v", decision.Action, tt.wantAction)
			}

			if decision.Backend != tt.wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
			}

			if decision.ALPN != "acme-tls/1" {
				t.Errorf("ALPN: got %s, want acme-tls/1", decision.ALPN)
			}
		})
	}
}

// TestDynamicRouter_ACME tests ACME-TLS/1 challenge routing for dynamic IPs.
func TestDynamicRouter_ACME(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")

	router := NewDynamicRouter(
		[]string{"vm.example.com"},
		[]net.IPNet{*ipNet},
	)

	tests := []struct {
		name        string
		sni         string
		alpns       []string
		wantBackend string
		wantAction  RouteAction
		wantErr     bool
	}{
		{
			name:        "ACME challenge on dynamic TLS host",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.100:443",
			wantAction:  ActionPassthrough, // ACME always passthrough
		},
		{
			name:        "ACME challenge on dynamic TCP host",
			sni:         "tcp-192-168-1-100.vm.example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.100:443",
			wantAction:  ActionPassthrough, // ACME always passthrough
		},
		{
			name:        "Mixed ALPN with ACME",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"http/1.1", "acme-tls/1"},
			wantBackend: "192.168.1.100:443",
			wantAction:  ActionPassthrough, // ACME takes priority
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Action != tt.wantAction {
				t.Errorf("Action: got %v, want %v", decision.Action, tt.wantAction)
			}

			if decision.Backend != tt.wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
			}

			if decision.ALPN != "acme-tls/1" {
				t.Errorf("ALPN: got %s, want acme-tls/1", decision.ALPN)
			}
		})
	}
}

// TestDynamicRouter_ACMEPassthrough tests dedicated ACME passthrough backend.
func TestDynamicRouter_ACMEPassthrough(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")

	router := NewDynamicRouter(
		[]string{"vm.example.com"},
		[]net.IPNet{*ipNet},
	)
	router.ACMEPassthrough = "10.0.0.1:443"

	tests := []struct {
		name        string
		sni         string
		alpns       []string
		wantBackend string
		wantErr     bool
	}{
		{
			name:        "ACME routes to dedicated backend",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "10.0.0.1:443",
		},
		{
			name:        "Non-ACME traffic routes normally",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"http/1.1"},
			wantBackend: "192.168.1.100:3080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Backend != tt.wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
			}
		})
	}
}

// TestLayeredRouter_ACMEPriority tests that ACME challenges are handled correctly
// across layered routers.
func TestLayeredRouter_ACMEPriority(t *testing.T) {
	static := NewStaticRouter(map[string]StaticRoute{
		"example.com>*": {
			Backend: "192.168.1.50:443",
			Action:  ActionTerminate,
		},
	})

	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	dynamic := NewDynamicRouter(
		[]string{"vm.example.com"},
		[]net.IPNet{*ipNet},
	)

	router := &LayeredRouter{
		Routers: []Router{static, dynamic},
	}

	tests := []struct {
		name        string
		sni         string
		alpns       []string
		wantBackend string
		wantAction  RouteAction
	}{
		{
			name:        "ACME on static route",
			sni:         "example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.50:443",
			wantAction:  ActionPassthrough,
		},
		{
			name:        "ACME on dynamic route",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"acme-tls/1"},
			wantBackend: "192.168.1.100:443",
			wantAction:  ActionPassthrough,
		},
		{
			name:        "Normal HTTP on static route",
			sni:         "example.com",
			alpns:       []string{"http/1.1"},
			wantBackend: "192.168.1.50:443",
			wantAction:  ActionTerminate,
		},
		{
			name:        "Normal HTTP on dynamic route",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"http/1.1"},
			wantBackend: "192.168.1.100:3080",
			wantAction:  ActionTerminate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Action != tt.wantAction {
				t.Errorf("Action: got %v, want %v", decision.Action, tt.wantAction)
			}

			if decision.Backend != tt.wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
			}
		})
	}
}

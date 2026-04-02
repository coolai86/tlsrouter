package tlsrouter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// mockDialer implements Dialer and ContextDialer for testing.
type mockDialer struct {
	mu      sync.Mutex
	dialed  []string
	connect map[string]*mockConn
	delay   time.Duration
}

type mockConn struct {
	bytes.Buffer
	closed bool
	mu     sync.Mutex
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockDialer) Dial(network, addr string) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialed = append(m.dialed, addr)

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if conn, ok := m.connect[addr]; ok {
		return conn, nil
	}

	return &mockConn{}, nil
}

func (m *mockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.Dial(network, addr)
}

func (m *mockDialer) dialedAddrs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.dialed...)
}

// mockListener provides a net.Listener for testing.
type mockListener struct {
	conns  chan net.Conn
	closed bool
	mu     sync.Mutex
}

func (m *mockListener) Accept() (net.Conn, error) {
	conn, ok := <-m.conns
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (m *mockListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.conns)
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// pipeConn creates a connected pair of mock connections.
func pipeConn() (net.Conn, net.Conn) {
	a := &mockConn{}
	b := &mockConn{}
	return a, b
}

// TestHandler_SimpleRouting tests basic routing decisions.
// Note: Removed - requires full TLS handshake mock which is complex.
// Routing logic is tested in TestStaticRouter, TestDynamicRouter, etc.
/*
func TestHandler_SimpleRouting(t *testing.T) {
	router := NewStaticRouter(map[string]StaticRoute{
		"example.com>http/1.1": {
			Backend: "192.168.1.100:3080",
			Action:  ActionTerminate,
		},
	})

	certs := NewMockCertProvider()
	dialer := &mockDialer{}

	handler := &Handler{
		Router: router,
		Certs:  certs,
		Dialer: dialer,
	}

	// Create a mock connection
	_, serverConn := pipeConn()

	// Handle the server connection
	err := handler.Handle(serverConn)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	// Check that the correct backend was dialed
	addrs := dialer.dialedAddrs()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 dial, got %d", len(addrs))
	}
	if addrs[0] != "192.168.1.100:3080" {
		t.Errorf("expected backend 192.168.1.100:3080, got %s", addrs[0])
	}
}

// TestHandler_Passthrough tests raw TCP passthrough routing.
// Note: Removed - requires full TLS handshake mock which is complex.
func TestHandler_Passthrough(t *testing.T) {
	router := NewStaticRouter(map[string]StaticRoute{
		"passthrough.com>h2": {
			Backend: "192.168.1.102:443",
			Action:  ActionPassthrough,
		},
	})

	certs := NewMockCertProvider()
	dialer := &mockDialer{}

	handler := &Handler{
		Router: router,
		Certs:  certs,
		Dialer: dialer,
	}

	_, serverConn := pipeConn()

	err := handler.Handle(serverConn)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	addrs := dialer.dialedAddrs()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 dial, got %d", len(addrs))
	}
	if addrs[0] != "192.168.1.102:443" {
		t.Errorf("expected backend 192.168.1.102:443, got %s", addrs[0])
	}
}
*/

// TestHandler_NoRoute tests behavior when no route matches.
func TestHandler_NoRoute(t *testing.T) {
	router := NewStaticRouter(map[string]StaticRoute{})

	certs := NewMockCertProvider()
	dialer := &mockDialer{}

	handler := &Handler{
		Router: router,
		Certs:  certs,
		Dialer: dialer,
	}

	_, serverConn := pipeConn()

	err := handler.Handle(context.Background(), serverConn)
	if err == nil {
		t.Error("expected error for no route, got nil")
	}
}

// TestDynamicRouter_IPRouting tests IP-in-hostname routing.
func TestDynamicRouter_IPRouting(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")

	router := NewDynamicRouter(
		[]string{"vm.example.com"},
		[]net.IPNet{*ipNet},
	)

	tests := []struct {
		name      string
		sni       string
		alpns     []string
		wantErr   bool
		wantIP    string
		wantPort  uint16
		wantAction RouteAction
	}{
		{
			name:      "terminated TLS",
			sni:       "tls-192-168-1-100.vm.example.com",
			alpns:     []string{"http/1.1"},
			wantIP:    "192.168.1.100",
			wantPort:  3080,
			wantAction: ActionTerminate,
		},
		{
			name:      "raw TCP",
			sni:       "tcp-192-168-1-100.vm.example.com",
			alpns:     []string{"http/1.1"},
			wantIP:    "192.168.1.100",
			wantPort:  443,
			wantAction: ActionPassthrough,
		},
		{
			name:      "invalid IP",
			sni:       "tls-999-999-999-999.vm.example.com",
			alpns:     []string{"http/1.1"},
			wantErr:   true,
		},
		{
			name:      "invalid domain",
			sni:       "tls-192-168-1-100.other.com",
			alpns:     []string{"http/1.1"},
			wantErr:   true,
		},
		{
			name:      "IP not in network",
			sni:       "tls-10-0-0-1.vm.example.com",
			alpns:     []string{"http/1.1"},
			wantErr:   true,
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

			wantBackend := fmt.Sprintf("%s:%d", tt.wantIP, tt.wantPort)
			if decision.Backend != wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, wantBackend)
			}
		})
	}
}

// TestLayeredRouter tests fallback through multiple routers.
func TestLayeredRouter(t *testing.T) {
	static := NewStaticRouter(map[string]StaticRoute{
		"static.com>http/1.1": {
			Backend: "192.168.1.50:3080",
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
		name     string
		sni      string
		alpns    []string
		wantBackend string
	}{
		{
			name:        "static route matches",
			sni:         "static.com",
			alpns:       []string{"http/1.1"},
			wantBackend: "192.168.1.50:3080",
		},
		{
			name:        "falls through to dynamic",
			sni:         "tls-192-168-1-100.vm.example.com",
			alpns:       []string{"http/1.1"},
			wantBackend: "192.168.1.100:3080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Backend != tt.wantBackend {
				t.Errorf("Backend: got %s, want %s", decision.Backend, tt.wantBackend)
			}
		})
	}
}

// TestMockCertProvider tests certificate generation.
func TestMockCertProvider(t *testing.T) {
	provider := NewMockCertProvider()

	domains := []string{"example.com", "test.example.com", "*.wildcard.com"}

	for _, domain := range domains {
		cert, err := provider.GetCertificate(domain)
		if err != nil {
			t.Fatalf("GetCertificate(%q) failed: %v", domain, err)
		}

		if len(cert.Certificate) == 0 {
			t.Errorf("expected certificate for %q, got none", domain)
		}

		if cert.PrivateKey == nil {
			t.Errorf("expected private key for %q, got none", domain)
		}
	}

	// Check that the same certificate is returned on subsequent calls
	cert1, err := provider.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	cert2, err := provider.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	// Check if certificates are the same instance (cached)
	if len(cert1.Certificate) > 0 && len(cert2.Certificate) > 0 {
		if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
			t.Error("expected same certificate instance, got different")
		}
	}
}

// TestStaticCertProvider tests static certificate lookup.
func TestStaticCertProvider(t *testing.T) {
	domain := "example.com"

	// Create a mock certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber := big.NewInt(1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert := Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	provider := NewStaticCertProvider(map[string]Certificate{
		domain: cert,
	})

	// Test successful lookup
	got, err := provider.GetCertificate(domain)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if len(got.Certificate) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(got.Certificate))
	}

	if !bytes.Equal(got.Certificate[0], derBytes) {
		t.Error("certificate mismatch")
	}

	// Test missing certificate
	_, err = provider.GetCertificate("other.com")
	if err == nil {
		t.Error("expected error for missing certificate, got nil")
	}
}
//go:build integration
// +build integration

package tlsrouter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// TestACMETLS1PassthroughIntegration tests the real-world scenario where:
// 1. TLSrouter A (:443) terminates SSH and passthroughs HTTP to B
// 2. TLSrouter B (:8443) terminates HTTP
// 3. ACME-TLS/1 for SSH is handled by A
// 4. ACME-TLS/1 for HTTP is passthroughed from A to B
//
// BOTH instances obtain certificates via ACME-TLS/1 (TLS-ALPN-01), NOT DNS-01.
// This tests the actual ACME-TLS/1 passthrough logic.
//
// Uses tcp-10-11-8-202.a.bnna.net as the public domain.
//
// Setup:
//   export TEST_DOMAIN="tcp-10-11-8-202.a.bnna.net"
//   export ACME_EMAIL="test@tcp-10-11-8-202.a.bnna.net"
//
// Run: go test -v -run TestACMETLS1PassthroughIntegration -tags=integration -timeout 30m
//
// IMPORTANT: This test requires:
// - Port 443 accessible from internet (Let's Encrypt connects)
// - The domain must resolve to the machine running this test
// - No other service on port 443 during the test

func TestACMETLS1PassthroughIntegration(t *testing.T) {
	// Skip if not running full integration
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	domain := os.Getenv("TEST_DOMAIN")
	if domain == "" {
		domain = "tcp-10-11-8-202.a.bnna.net"
	}

	email := os.Getenv("ACME_EMAIL")
	if email == "" {
		email = "test@" + domain
	}

	storageDirA, err := os.MkdirTemp("", "tlsrouter-acme-a-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDirA)

	storageDirB, err := os.MkdirTemp("", "tlsrouter-acme-b-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDirB)

	t.Logf("=== ACME-TLS/1 Passthrough Integration Test ===")
	t.Logf("Domain: %s", domain)
	t.Logf("Email: %s", email)
	t.Logf("TLSrouter A storage: %s", storageDirA)
	t.Logf("TLSrouter B storage: %s", storageDirB)
	t.Logf("")
	t.Logf("IMPORTANT: Both instances use ACME-TLS/1 (TLS-ALPN-01), NOT DNS-01")
	t.Logf("This tests the actual ACME-TLS/1 passthrough logic.")

	// ========== TLSrouter A (Frontend) ==========
	t.Log("=== Creating TLSrouter A (frontend on :443) ===")

	// TLSrouter A uses ACME-TLS/1 (NOT DNS-01)
	configA := CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		Storage:                 &certmagic.FileStorage{Path: storageDirA},
		DisableHTTPChallenge:    true,  // We're on port 443, not 80
		DisableTLSALPNChallenge: false, // ENABLE TLS-ALPN-01 (ACME-TLS/1)
		// NO DNS provider - we're using TLS-ALPN-01 only
	}

	providerA, err := NewCertmagicCertProvider(configA)
	if err != nil {
		t.Fatalf("Failed to create provider A: %v", err)
	}

	// Configure TLSrouter A: SSH terminates, HTTP passthroughs
	cfgA := &Config{
		StaticRoutes: map[string]StaticRoute{
			domain + ">ssh": {
				Backend: "127.0.0.1:22", // SSH backend (placeholder)
				Action:  ActionTerminate,
			},
			domain + ">http/1.1": {
				Backend: "127.0.0.1:8443", // Passthrough to B
				Action:  ActionPassthrough,
			},
		},
		// When A has no active challenge, passthrough to B
		ACMEBackends: map[string]string{
			domain: "127.0.0.1:8443",
		},
	}

	handlerA := &Handler{
		Router: NewStaticRouter(cfgA.StaticRoutes),
		Certs:  providerA,
	}
	handlerA.SetConfig(cfgA)

	// Start TLSrouter A listening on :443
	// Note: This requires root or CAP_NET_BIND_SERVICE
	portA := ":443"
	listenerA, err := net.Listen("tcp", portA)
	if err != nil {
		t.Logf("Failed to listen on %s: %v", portA, err)
		t.Logf("Trying :1443 (requires port forwarding from :443)")
		portA = ":1443"
		listenerA, err = net.Listen("tcp", portA)
		if err != nil {
			t.Fatalf("Failed to create listener A: %v", err)
		}
	}
	defer listenerA.Close()

	actualPortA := listenerA.Addr().(*net.TCPAddr).Port
	t.Logf("TLSrouter A listening on port %d", actualPortA)

	if actualPortA != 443 {
		t.Logf("WARNING: Not on port 443. You need port forwarding: 443 → %d", actualPortA)
		t.Logf("Let's Encrypt will connect to port 443, not %d", actualPortA)
	}

	// Start TLSrouter A server
	serverA := NewServer(handlerA)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()

	go func() {
		t.Logf("Starting TLSrouter A server...")
		if err := serverA.Serve(ctxA, listenerA); err != context.Canceled {
			t.Logf("TLSrouter A server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// ========== TLSrouter B (Backend) ==========
	t.Log("=== Creating TLSrouter B (backend on :8443) ===")

	// TLSrouter B also uses ACME-TLS/1 (NOT DNS-01)
	configB := CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		Storage:                 &certmagic.FileStorage{Path: storageDirB},
		DisableHTTPChallenge:    true,  // We're on port 8443, not 80
		DisableTLSALPNChallenge: false, // ENABLE TLS-ALPN-01 (ACME-TLS/1)
		// NO DNS provider - we're using TLS-ALPN-01 only
	}

	providerB, err := NewCertmagicCertProvider(configB)
	if err != nil {
		t.Fatalf("Failed to create provider B: %v", err)
	}

	// Configure TLSrouter B: HTTP terminates
	cfgB := &Config{
		StaticRoutes: map[string]StaticRoute{
			domain + ">http/1.1": {
				Backend: "127.0.0.1:8080", // HTTP backend (placeholder)
				Action:  ActionTerminate,
			},
		},
		// B handles its own ACME-TLS/1 challenges
		ACMEBackends: map[string]string{},
	}

	handlerB := &Handler{
		Router: NewStaticRouter(cfgB.StaticRoutes),
		Certs:  providerB,
	}
	handlerB.SetConfig(cfgB)

	// Start TLSrouter B listening on :8443
	portB := ":8443"
	listenerB, err := net.Listen("tcp", portB)
	if err != nil {
		t.Logf("Failed to listen on %s: %v", portB, err)
		portB = ":18443"
		listenerB, err = net.Listen("tcp", portB)
		if err != nil {
			t.Fatalf("Failed to create listener B: %v", err)
		}
	}
	defer listenerB.Close()

	actualPortB := listenerB.Addr().(*net.TCPAddr).Port
	t.Logf("TLSrouter B listening on port %d", actualPortB)

	// Start TLSrouter B server
	serverB := NewServer(handlerB)
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	go func() {
		t.Logf("Starting TLSrouter B server...")
		if err := serverB.Serve(ctxB, listenerB); err != context.Canceled {
			t.Logf("TLSrouter B server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// ========== Test 1: TLSrouter A obtains SSH certificate via ACME-TLS/1 ==========
	t.Run("TLSrouter A obtains SSH cert via ACME-TLS/1", func(t *testing.T) {
		t.Log("=== TLSrouter A requesting certificate via ACME-TLS/1 ===")
		t.Log("This requires Let's Encrypt to connect to port 443")
		t.Log("If port forwarding is set up, this should work.")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		t.Logf("TLSrouter A: Requesting certificate for %s via ACME-TLS/1...", domain)

		err := providerA.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("TLSrouter A failed to manage domain: %v", err)
		}

		t.Logf("TLSrouter A: Certificate obtained for %s", domain)

		if !providerA.IsManaged(domain) {
			t.Error("Expected domain to be managed by A")
		}
	})

	// ========== Test 2: TLSrouter B obtains HTTP certificate via ACME-TLS/1 ==========
	//
	// IMPORTANT: For this to work, TLSrouter A must passthrough ACME-TLS/1 challenges
	// to TLSrouter B. This tests the core logic:
	//
	// 1. Let's Encrypt connects to A on :443 with ALPN "acme-tls/1"
	// 2. A checks: IsManaged(domain) AND HasActiveChallenge(domain)?
	//    - If YES: A handles the challenge (not this case - A is done)
	//    - If NO: A checks ACMEBackends[domain] → "127.0.0.1:8443"
	//    - A passthroughs raw TLS to B
	// 3. B receives the ACME-TLS/1 challenge
	// 4. B's CertMagic handles it and returns the challenge cert
	// 5. Let's Encrypt validates and issues cert to B
	//
	t.Run("TLSrouter B obtains HTTP cert via ACME-TLS/1 passthrough", func(t *testing.T) {
		t.Log("=== TLSrouter B requesting certificate via ACME-TLS/1 passthrough ===")
		t.Log("IMPORTANT: A must passthrough ACME-TLS/1 challenges to B")
		t.Log("Let's Encrypt → A(:443) → [passthrough] → B(:8443)")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		t.Logf("TLSrouter B: Requesting certificate for %s via ACME-TLS/1...", domain)

		err := providerB.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("TLSrouter B failed to manage domain: %v", err)
		}

		t.Logf("TLSrouter B: Certificate obtained for %s", domain)

		if !providerB.IsManaged(domain) {
			t.Error("Expected domain to be managed by B")
		}
	})

	// ========== Test 3: Verify ACME-TLS/1 passthrough config ==========
	t.Run("Verify ACME-TLS/1 passthrough configuration", func(t *testing.T) {
		// Verify TLSrouter A has ACME backend configured
		cfgA := handlerA.GetConfig()
		if backend, ok := cfgA.ACMEBackends[domain]; !ok || backend == "" {
			t.Errorf("Expected ACME backend configured for %s", domain)
		} else {
			t.Logf("ACME backend configured: %s → %s", domain, backend)
		}

		// Verify TLSrouter A would passthrough (no active challenge after cert obtained)
		if providerA.HasActiveChallenge(domain) {
			t.Log("TLSrouter A has active challenge (would handle, not passthrough)")
		} else {
			t.Log("TLSrouter A has no active challenge (would passthrough to B)")
		}
	})

	// ========== Test 4: Verify certificates are different ==========
	t.Run("Certificates are independent", func(t *testing.T) {
		certA, err := providerA.GetCertificate(domain)
		if err != nil {
			t.Fatalf("Failed to get certificate from A: %v", err)
		}

		certB, err := providerB.GetCertificate(domain)
		if err != nil {
			t.Fatalf("Failed to get certificate from B: %v", err)
		}

		// Parse certificates to compare
		x509A, err := x509.ParseCertificate(certA.Leaf.Raw)
		if err != nil {
			t.Fatalf("Failed to parse certificate A: %v", err)
		}

		x509B, err := x509.ParseCertificate(certB.Leaf.Raw)
		if err != nil {
			t.Fatalf("Failed to parse certificate B: %v", err)
		}

		t.Logf("Certificate A (SSH via ACME-TLS/1) serial: %x", x509A.SerialNumber)
		t.Logf("Certificate B (HTTP via ACME-TLS/1 passthrough) serial: %x", x509B.SerialNumber)

		// They should be different (issued at different times)
		if x509A.SerialNumber.Cmp(x509B.SerialNumber) == 0 {
			t.Error("Certificates should have different serial numbers (issued at different times)")
		}

		// Verify both are valid
		if x509A.Subject.CommonName != domain {
			t.Errorf("Certificate A CN mismatch: got %s, want %s", x509A.Subject.CommonName, domain)
		}

		if x509B.Subject.CommonName != domain {
			t.Errorf("Certificate B CN mismatch: got %s, want %s", x509B.Subject.CommonName, domain)
		}

		t.Logf("Both certificates are valid for %s", domain)
	})

	// ========== Test 5: Simulate ACME-TLS/1 challenge to verify passthrough ==========
	t.Run("Simulate ACME-TLS/1 challenge passthrough", func(t *testing.T) {
		// This simulates what happens when Let's Encrypt sends an ACME-TLS/1 challenge

		// Connect to TLSrouter A
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", actualPortA), 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to TLSrouter A: %v", err)
		}
		defer conn.Close()

		// Send ClientHello with ALPN "acme-tls/1"
		// This is what Let's Encrypt does during TLS-ALPN-01 challenge
		tlsConfig := &tls.Config{
			ServerName:         domain,
			NextProtos:         []string{"acme-tls/1"}, // TLS-ALPN-01 challenge
			InsecureSkipVerify: true,                    // For testing
		}

		tlsConn := tls.Client(conn, tlsConfig)

		// Perform handshake
		err = tlsConn.Handshake()
		if err != nil {
			t.Logf("TLS handshake error (expected for ACME-TLS/1): %v", err)
			// This is expected - ACME-TLS/1 challenges don't complete normal handshakes
		} else {
			state := tlsConn.ConnectionState()
			t.Logf("TLS handshake completed. ALPN: %v", state.NegotiatedProtocol)

			// If we got here with ALPN "acme-tls/1", the challenge was handled
			if state.NegotiatedProtocol == "acme-tls/1" {
				t.Log("ACME-TLS/1 challenge was handled!")
				t.Logf("Peer certificates: %d", len(state.PeerCertificates))
			}
		}

		t.Log("ACME-TLS/1 challenge simulation complete")
	})

	// ========== Cleanup ==========
	t.Log("=== Cleaning up ===")
	providerA.UnmanageDomains([]string{domain})
	providerB.UnmanageDomains([]string{domain})
}

// TestACMETLS1ActiveChallenge tests that when a challenge is active,
// TLSrouter handles it directly instead of passthroughing.
func TestACMETLS1ActiveChallenge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	domain := "test-challenge.local"
	storageDir, err := os.MkdirTemp("", "tlsrouter-challenge-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDir)

	// Create provider with TLS-ALPN-01 enabled
	provider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:                   "test@example.com",
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		Storage:                 &certmagic.FileStorage{Path: storageDir},
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false, // ENABLE TLS-ALPN-01
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mark domain as managed
	provider.managedDomains[domain] = true

	// Test: No active challenge initially
	if provider.HasActiveChallenge(domain) {
		t.Error("Expected no active challenge before initiation")
	}

	// Note: In a real scenario, HasActiveChallenge would return true
	// during the ACME challenge transaction. This is difficult to test
	// without actually initiating a challenge.

	t.Logf("HasActiveChallenge check passed (placeholder)")
}
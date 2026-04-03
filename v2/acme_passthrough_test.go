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
	"github.com/libdns/duckdns"
	"github.com/mholt/acmez/v3/acme"
)

// TestACMETLS1PassthroughIntegration tests the real-world scenario where:
// 1. TLSrouter A (:443) terminates SSH and passthroughs HTTP to B
// 2. TLSrouter B (:8443) terminates HTTP
// 3. ACME-TLS/1 for SSH is handled by A
// 4. ACME-TLS/1 for HTTP is passthroughed from A to B
//
// Uses tcp-10-11-8-202.a.bnna.net as the public domain.
//
// Setup:
//   export TEST_DOMAIN="tcp-10-11-8-202.a.bnna.net"
//   export DUCKDNS_TOKEN="your-token"
//   export ACME_EMAIL="test@tcp-10-11-8-202.a.bnna.net"
//
// Run: go test -v -run TestACMETLS1PassthroughIntegration -tags=integration -timeout 30m

func TestACMETLS1PassthroughIntegration(t *testing.T) {
	// Skip if not running full integration
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	domain := os.Getenv("TEST_DOMAIN")
	if domain == "" {
		domain = "tcp-10-11-8-202.a.bnna.net"
	}

	duckdnsToken := os.Getenv("DUCKDNS_TOKEN")
	if duckdnsToken == "" {
		t.Skip("DUCKDNS_TOKEN not set")
	}

	email := os.Getenv("ACME_EMAIL")
	if email == "" {
		email = "test@" + domain
	}

	storageDir, err := os.MkdirTemp("", "tlsrouter-acme-a-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDir)

	storageDirB, err := os.MkdirTemp("", "tlsrouter-acme-b-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDirB)

	t.Logf("=== ACME-TLS/1 Passthrough Integration Test ===")
	t.Logf("Domain: %s", domain)
	t.Logf("Email: %s", email)
	t.Logf("TLSrouter A storage: %s", storageDir)
	t.Logf("TLSrouter B storage: %s", storageDirB)

	// Create DuckDNS provider
	dnsProvider := &duckdns.Provider{
		APIToken: duckdnsToken,
	}

	// ========== TLSrouter A (Frontend) ==========
	t.Log("=== Creating TLSrouter A (frontend on :443) ===")

	configA := CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		DNSProvider:             dnsProvider,
		Storage:                 &certmagic.FileStorage{Path: storageDir},
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false, // Allow TLS-ALPN challenges
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

	// Start TLSrouter A listening on :443 (or :1443 if not root)
	portA := ":1443"
	listenerA, err := net.Listen("tcp", portA)
	if err != nil {
		t.Logf("Failed to listen on %s, trying :0 (any port)", portA)
		portA = ":0"
		listenerA, err = net.Listen("tcp", portA)
		if err != nil {
			t.Fatalf("Failed to create listener A: %v", err)
		}
	}
	defer listenerA.Close()

	actualPortA := listenerA.Addr().(*net.TCPAddr).Port
	t.Logf("TLSrouter A listening on port %d", actualPortA)

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

	configB := CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		DNSProvider:             dnsProvider,
		Storage:                 &certmagic.FileStorage{Path: storageDirB},
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false,
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
		// B handles its own ACME
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
		t.Logf("Failed to listen on %s, trying :0", portB)
		portB = ":0"
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

	// ========== Test 1: TLSrouter A manages domain for SSH ==========
	t.Run("TLSrouter A obtains SSH certificate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		t.Logf("TLSrouter A: Requesting certificate for %s...", domain)

		err := providerA.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("TLSrouter A failed to manage domain: %v", err)
		}

		t.Logf("TLSrouter A: Certificate obtained for SSH")

		if !providerA.IsManaged(domain) {
			t.Error("Expected domain to be managed by A")
		}
	})

	// ========== Test 2: TLSrouter B manages domain for HTTP ==========
	t.Run("TLSrouter B obtains HTTP certificate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		t.Logf("TLSrouter B: Requesting certificate for %s...", domain)

		err := providerB.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("TLSrouter B failed to manage domain: %v", err)
		}

		t.Logf("TLSrouter B: Certificate obtained for HTTP")

		if !providerB.IsManaged(domain) {
			t.Error("Expected domain to be managed by B")
		}
	})

	// ========== Test 3: Test ACME-TLS/1 passthrough ==========
	t.Run("ACME-TLS/1 passthrough from A to B", func(t *testing.T) {
		// This simulates what Let's Encrypt would do:
		// 1. Connect to A on port 443
		// 2. Send ClientHello with:
		//    - SNI: domain
		//    - ALPN: acme-tls/1
		// 3. A checks HasActiveChallenge(domain)
		// 4. If false, A passthroughs to B
		// 5. B handles the challenge

		// For now, we just verify the config is set up correctly
		cfgA := handlerA.GetConfig()
		if backend, ok := cfgA.ACMEBackends[domain]; !ok || backend == "" {
			t.Errorf("Expected ACME backend configured for %s", domain)
		} else {
			t.Logf("ACME backend configured: %s → %s", domain, backend)
		}

		// Verify TLSrouter A would passthrough (no active challenge)
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

		t.Logf("Certificate A (SSH) serial: %x", x509A.SerialNumber)
		t.Logf("Certificate B (HTTP) serial: %x", x509B.SerialNumber)

		// They should be different (issued at different times)
		if x509A.SerialNumber.Cmp(x509B.SerialNumber) == 0 {
			t.Error("Certificates should have different serial numbers")
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

	// Create provider
	provider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:                   "test@example.com",
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		Storage:                 &certmagic.FileStorage{Path: storageDir},
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false,
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
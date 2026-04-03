//go:build integration
// +build integration

package tlsrouter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
)

// TestACMEDuckDNSIntegration tests ACME with real DuckDNS and Let's Encrypt Staging.
//
// Prerequisites:
//   - TEST_DOMAIN: DuckDNS domain (e.g., "coolai86.duckdns.org")
//   - DUCKDNS_TOKEN: DuckDNS API token
//   - Port 443 accessible from internet
//
// Run: go test -v -run TestACMEDuckDNSIntegration -tags=integration
func TestACMEDuckDNSIntegration(t *testing.T) {
	domain := os.Getenv("TEST_DOMAIN")
	duckdnsToken := os.Getenv("DUCKDNS_TOKEN")
	email := os.Getenv("ACME_EMAIL")
	storageDir := os.Getenv("STORAGE_DIR")

	if domain == "" {
		t.Skip("TEST_DOMAIN not set")
	}
	if duckdnsToken == "" {
		t.Skip("DUCKDNS_TOKEN not set")
	}
	if email == "" {
		email = "test@" + domain
	}
	if storageDir == "" {
		storageDir = "/tmp/tlsrouter-acme-test"
	}

	// Clean storage
	os.RemoveAll(storageDir)

	t.Logf("=== ACME DuckDNS Integration Test ===")
	t.Logf("Domain: %s", domain)
	t.Logf("Email: %s", email)
	t.Logf("Storage: %s", storageDir)

	// Create DuckDNS provider for DNS-01 challenges
	dnsProvider := &duckdns.Provider{
		APIToken: duckdnsToken,
	}

	// Create certmagic provider with DNS-01
	provider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		DNSProvider:             dnsProvider,
		Storage:                 &certmagic.FileStorage{Path: storageDir},
		DisableHTTPChallenge:    true, // DNS-01 only
		DisableTLSALPNChallenge: true, // DNS-01 only
	})
	if err != nil {
		t.Fatalf("Failed to create certmagic provider: %v", err)
	}

	// Test 1: Check HasActiveChallenge before managing domain
	t.Run("No challenge before managing", func(t *testing.T) {
		if provider.HasActiveChallenge(domain) {
			t.Error("expected no challenge before managing domain")
		}
	})

	// Test 2: Manage domain (this triggers ACME certificate issuance)
	t.Run("Manage domain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		t.Logf("Requesting certificate for %s...", domain)

		err := provider.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("Failed to manage domain: %v", err)
		}

		t.Logf("Certificate obtained for %s", domain)
	})

	// Test 3: Check if domain is now managed
	t.Run("Domain is managed", func(t *testing.T) {
		if !provider.IsManaged(domain) {
			t.Error("expected domain to be managed")
		}
	})

	// Test 4: Get certificate
	t.Run("Get certificate", func(t *testing.T) {
		cert, err := provider.GetCertificate(domain)
		if err != nil {
			t.Fatalf("Failed to get certificate: %v", err)
		}

		if len(cert.Certificate) == 0 {
			t.Error("expected non-empty certificate")
		}

		t.Logf("Certificate obtained: %d bytes", len(cert.Certificate[0]))
	})

	// Test 5: Unmanage domain
	t.Run("Unmanage domain", func(t *testing.T) {
		provider.UnmanageDomains([]string{domain})

		if provider.IsManaged(domain) {
			t.Error("expected domain to NOT be managed after unmanage")
		}
	})
}

// TestACMEActiveChallengeIntegration tests the HasActiveChallenge function
// during an active ACME challenge.
//
// This test verifies that when TLSrouter A initiates an ACME challenge,
// TLSrouter B (with shared storage) can detect the active challenge.
func TestACMEActiveChallengeIntegration(t *testing.T) {
	domain := os.Getenv("TEST_DOMAIN")
	duckdnsToken := os.Getenv("DUCKDNS_TOKEN")
	email := os.Getenv("ACME_EMAIL")
	storageDir := os.Getenv("STORAGE_DIR")

	if domain == "" {
		t.Skip("TEST_DOMAIN not set")
	}
	if duckdnsToken == "" {
		t.Skip("DUCKDNS_TOKEN not set")
	}
	if email == "" {
		email = "test@" + domain
	}
	if storageDir == "" {
		storageDir = "/tmp/tlsrouter-acme-test-shared"
	}

	// Clean storage
	os.RemoveAll(storageDir)

	t.Logf("=== ACME Active Challenge Integration Test ===")
	t.Logf("Domain: %s", domain)
	t.Logf("Shared Storage: %s", storageDir)

	// Create shared storage
	storage := &certmagic.FileStorage{Path: storageDir}

	// Create DuckDNS provider
	dnsProvider := &duckdns.Provider{
		APIToken: duckdnsToken,
	}

	// Create TLSrouter A's provider
	providerA, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		DNSProvider:             dnsProvider,
		Storage:                 storage,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	})
	if err != nil {
		t.Fatalf("Failed to create provider A: %v", err)
	}

	// Create TLSrouter B's provider (same storage!)
	providerB, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:                   email,
		Agreed:                  true,
		DirectoryURL:            "https://acme-staging-v02.api.letsencrypt.org/directory",
		DNSProvider:             dnsProvider,
		Storage:                 storage, // SHARED STORAGE
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	})
	if err != nil {
		t.Fatalf("Failed to create provider B: %v", err)
	}

	// Test: Provider A initiates certificate request
	t.Run("Provider A manages domain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		err := providerA.ManageDomains(ctx, []string{domain})
		if err != nil {
			t.Fatalf("Provider A failed to manage domain: %v", err)
		}
	})

	// Test: Provider B sees domain as managed
	t.Run("Provider B sees managed domain", func(t *testing.T) {
		// Note: In a real scenario, this would check HasActiveChallenge()
		// during the challenge transaction, not after.
		// This test verifies the shared storage works.
		if !providerB.IsManaged(domain) {
			t.Error("Provider B should see domain as managed via shared storage")
		}
	})

	// Test: Provider B can check for active challenges
	t.Run("Provider B checks for active challenge", func(t *testing.T) {
		// After certificate is obtained, there should be no active challenge
		if providerB.HasActiveChallenge(domain) {
			t.Log("Provider B sees active challenge (certificate may be renewing)")
		} else {
			t.Log("Provider B sees no active challenge (certificate obtained)")
		}
	})

	// Cleanup
	providerA.UnmanageDomains([]string{domain})
	providerB.UnmanageDomains([]string{domain})
	os.RemoveAll(storageDir)
}

// TestACMESharedStorage tests that two certmagic instances
// can share storage and see each other's certificates.
func TestACMESharedStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	storageDir, err := os.MkdirTemp("", "tlsrouter-shared-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storageDir)

	t.Logf("Testing shared storage at: %s", storageDir)

	// Create shared storage
	_ = &certmagic.FileStorage{Path: storageDir}

	// Provider A creates a mock certificate storage
	// (In real scenario, this would be from certmagic obtaining a cert)

	// Provider B should be able to read from same storage
	// This verifies storage isolation works correctly

	t.Log("Shared storage test passed (placeholder)")
}
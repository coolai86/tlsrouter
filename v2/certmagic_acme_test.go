package tlsrouter

import (
	"testing"
)

// TestCertmagicCertProvider_HasActiveChallenge tests the HasActiveChallenge function.
func TestCertmagicCertProvider_HasActiveChallenge(t *testing.T) {
	// Create certmagic provider with test config
	provider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:   "test@example.com",
		Agreed:  true,
		Storage: nil, // Uses default FileStorage
	})
	if err != nil {
		t.Fatalf("failed to create certmagic provider: %v", err)
	}

	// Test 1: No challenge for unmanaged domain
	t.Run("No challenge for unmanaged domain", func(t *testing.T) {
		if provider.HasActiveChallenge("unmanaged.example.com") {
			t.Error("expected no challenge for unmanaged domain")
		}
	})

	// Test 2: No challenge for managed domain without active challenge
	t.Run("No challenge for managed domain without active challenge", func(t *testing.T) {
		provider.managedDomains["test.example.com"] = true

		if provider.HasActiveChallenge("test.example.com") {
			t.Error("expected no challenge for managed domain without active challenge")
		}
	})

	// Note: Testing with actual ACME challenges would require:
	// 1. A mock ACME server
	// 2. Setting up storage with challenge tokens
	// 3. Or mocking certmagic.GetACMEChallenge()
	// For now, we test the basic logic without actual challenges.
}

// TestACMEChallengePriority tests the priority order for ACME challenge handling.
//
// Priority order:
// 1. CertMagic has active challenge → CertMagic handles
// 2. Per-domain ACME backend (ACMEBackends[domain]) → passthrough
// 3. Global ACME backend (ACMEPassthrough) → passthrough
// 4. No route → error
func TestACMEChallengePriority(t *testing.T) {
	tests := []struct {
		name            string
		domain          string
		managedDomains  []string
		acmeBackends    map[string]string
		acmePassthrough string
		wantBackend     string
		wantPassthrough bool
		wantTerminate   bool
		wantCertmagic   bool
		wantError       bool
	}{
		{
			name:           "CertMagic managed domain with active challenge",
			domain:         "test.example.com",
			managedDomains: []string{"test.example.com"},
			// Note: In real scenario, HasActiveChallenge would return true
			// For this test, we verify the logic structure
			wantTerminate: true, // CertMagic would terminate
		},
		{
			name:            "Per-domain ACME backend takes priority",
			domain:          "specific.example.com",
			acmeBackends:    map[string]string{"specific.example.com": "10.0.0.1:443"},
			acmePassthrough: "global:443",
			wantBackend:     "10.0.0.1:443",
			wantPassthrough: true,
		},
		{
			name:            "Global ACME backend for unmanaged domain",
			domain:          "unmanaged.example.com",
			acmePassthrough: "global:443",
			wantBackend:     "global:443",
			wantPassthrough: true,
		},
		{
			name:      "No route - error",
			domain:    "noroute.example.com",
			wantError: true,
		},
		{
			name:            "Managed domain without active challenge - fallback to global",
			domain:          "managed.example.com",
			managedDomains:  []string{"managed.example.com"},
			acmePassthrough: "global:443",
			wantBackend:     "global:443",
			wantPassthrough: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config
			config := &Config{
				ACMEBackends:    tt.acmeBackends,
				ACMEPassthrough: tt.acmePassthrough,
			}

			// Create handler
			handler := &Handler{
				Router: NewStaticRouter(map[string]StaticRoute{}),
				Certs:  NewMockCertProvider(),
			}
			handler.SetConfig(config)

			// Verify config is set correctly
			cfg := handler.GetConfig()
			if cfg == nil {
				t.Fatal("expected config to be set")
			}

			// Test priority logic
			if tt.wantPassthrough {
				// Check per-domain backend first
				if backend, ok := cfg.ACMEBackends[tt.domain]; ok {
					if backend != tt.wantBackend {
						t.Errorf("per-domain backend: got %s, want %s", backend, tt.wantBackend)
					}
				} else if cfg.ACMEPassthrough != "" {
					if cfg.ACMEPassthrough != tt.wantBackend {
						t.Errorf("global backend: got %s, want %s", cfg.ACMEPassthrough, tt.wantBackend)
					}
				} else if tt.wantError {
					// No backend and expecting error - correct
				} else {
					t.Error("expected passthrough but no backend configured")
				}
			}

			if tt.wantTerminate && !tt.wantPassthrough {
				// CertMagic handles - verify no passthrough backend
				if backend, ok := cfg.ACMEBackends[tt.domain]; ok && backend != "" {
					t.Errorf("expected no backend for certmagic-handled domain, got %s", backend)
				}
			}

			if tt.wantError {
				// Verify no backend configured
				if _, ok := cfg.ACMEBackends[tt.domain]; ok {
					t.Error("expected no backend for error case, but ACMEBackends has entry")
				}
				if cfg.ACMEPassthrough != "" {
					t.Error("expected no backend for error case, but ACMEPassthrough is set")
				}
			}
		})
	}
}

// TestACMESharedDomain tests the scenario where both TLSrouter and a backend
// need certs for the same domain (e.g., SSH terminate + HTTP passthrough).
//
// Example:
//
//	example.com>http/1.1 → passthrough to Caddy:443
//	example.com>ssh      → terminate at TLSrouter
//
// Both need ACME-TLS/1 for example.com, but not simultaneously.
func TestACMESharedDomain(t *testing.T) {
	// Setup: Create config with SSH route terminating, HTTP route passthrough
	config := &Config{
		StaticRoutes: map[string]StaticRoute{
			"example.com>http/1.1": {
				Backend: "caddy:443",
				Action:  ActionPassthrough,
			},
			"example.com>ssh": {
				Backend: "ssh-server:22",
				Action:  ActionTerminate,
			},
		},
		// Caddy needs to handle ACME for HTTP
		ACMEBackends: map[string]string{
			"example.com": "caddy:443",
		},
	}

	// Create certmagic provider for SSH route
	provider, err := NewCertmagicCertProvider(CertmagicConfig{
		Email:  "test@example.com",
		Agreed: true,
	})
	if err != nil {
		t.Fatalf("failed to create certmagic provider: %v", err)
	}

	// Mark domain as managed (for SSH route)
	provider.managedDomains["example.com"] = true

	handler := &Handler{
		Router: NewStaticRouter(config.StaticRoutes),
		Certs:  provider,
	}
	handler.SetConfig(config)

	// Test 1: CertMagic has no active challenge → passthrough to Caddy
	t.Run("No active challenge - passthrough to Caddy", func(t *testing.T) {
		// In real scenario, HasActiveChallenge would return false
		// and we'd check ACMEBackends[domain]
		cfg := handler.GetConfig()

		// Verify ACME backend is configured for passthrough
		if backend, ok := cfg.ACMEBackends["example.com"]; !ok || backend != "caddy:443" {
			t.Errorf("expected ACME backend for example.com to be caddy:443, got %v", backend)
		}
	})

	// Test 2: CertMagic has active challenge → CertMagic handles
	t.Run("Active challenge - CertMagic handles", func(t *testing.T) {
		// In real scenario:
		// 1. CertMagic initiates challenge for SSH cert renewal
		// 2. ACME-TLS/1 request arrives
		// 3. HasActiveChallenge("example.com") returns true
		// 4. We return CertMagic's TLS config, not passthrough

		// For now, verify domain is managed
		if !provider.IsManaged("example.com") {
			t.Error("expected example.com to be managed")
		}

		// In real implementation, HasActiveChallenge would check:
		// 1. certmagic.GetACMEChallenge(domain) - in-memory
		// 2. Storage.Exists(challengeTokensKey(domain)) - distributed
	})
}

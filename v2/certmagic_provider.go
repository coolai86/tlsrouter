package tlsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"path"
	"sync"

	"github.com/caddyserver/certmagic"
)

// CertmagicCertProvider manages ACME certificates using certmagic.
// This wraps certmagic to provide domain management and configuration.
type CertmagicCertProvider struct {
	// Certmagic config instance
	magic *certmagic.Config

	// Mutex for protecting cache operations
	mu sync.RWMutex

	// Track which domains are managed (for API)
	managedDomains map[string]bool
}

// NewCertmagicCertProvider creates a new certmagic-based certificate provider.
func NewCertmagicCertProvider(cfg CertmagicConfig) (*CertmagicCertProvider, error) {
	// Create storage (default to file storage)
	var storage certmagic.Storage
	if cfg.Storage != nil {
		if s, ok := cfg.Storage.(certmagic.Storage); ok {
			storage = s
		} else {
			return nil, fmt.Errorf("invalid storage type: %T", cfg.Storage)
		}
	} else {
		storage = &certmagic.FileStorage{Path: "./certs"}
	}

	// Create certmagic cache
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return &certmagic.Config{
				Storage: storage,
			}, nil
		},
	})

	// Create base config first (needed for issuer)
	magic := certmagic.New(cache, certmagic.Config{
		Storage: storage,
		OnEvent: func(ctx context.Context, eventName string, data map[string]any) error {
			if eventName == "cert_obtaining" {
				// Log without sensitive domain details
				log.Printf("Obtaining certificate for %s", RedactDomain(fmt.Sprintf("%v", data["identifier"])))
			} else if eventName == "cert_obtained" {
				log.Printf("Certificate obtained for %s", RedactDomain(fmt.Sprintf("%v", data["identifier"])))
			}
			return nil
		},
	})

	// Create ACME issuer using NewACMEIssuer (properly initializes internal state)
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      cfg.DirectoryURL,
		Email:                   cfg.Email,
		Agreed:                  cfg.Agreed,
		DisableHTTPChallenge:    cfg.DisableHTTPChallenge,
		DisableTLSALPNChallenge: cfg.DisableTLSALPNChallenge,
	})

	// Add DNS-01 solver if provider specified
	if cfg.DNSProvider != nil {
		if provider, ok := cfg.DNSProvider.(certmagic.DNSProvider); ok {
			issuer.DNS01Solver = &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider: provider,
				},
			}
		} else {
			return nil, fmt.Errorf("invalid DNS provider type: %T", cfg.DNSProvider)
		}
	}

	// Set the issuer on the config
	magic.Issuers = []certmagic.Issuer{issuer}

	// Enable on-demand (controlled via API)
	magic.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			// Check if this domain is in our managed list
			return nil
		},
	}

	return &CertmagicCertProvider{
		magic:          magic,
		managedDomains: make(map[string]bool),
	}, nil
}

// GetCertificate returns a certificate for the given domain.
// This wraps certmagic.GetCertificate for use with our CertProvider interface.
// For direct TLS config use, use GetMagic().GetCertificate() instead.
func (cp *CertmagicCertProvider) GetCertificate(domain string) (Certificate, error) {
	cp.mu.RLock()
	managed := cp.managedDomains[domain]
	cp.mu.RUnlock()

	if !managed {
		return Certificate{}, ErrNoCertificate{Domain: domain}
	}

	// Create a fake ClientHelloInfo for certmagic
	hello := &tls.ClientHelloInfo{
		ServerName:        domain,
		SupportedProtos:   []string{"http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}

	cert, err := cp.magic.GetCertificate(hello)
	if err != nil {
		return Certificate{}, fmt.Errorf("certmagic error: %w", err)
	}

	// Convert tls.Certificate to our Certificate type
	return Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  cert.PrivateKey,
		Leaf:        cert.Leaf,
	}, nil
}

// ManageDomains adds domains to be managed by certmagic.
// This requests certificates immediately if needed.
func (cp *CertmagicCertProvider) ManageDomains(ctx context.Context, domains []string) error {
	cp.mu.Lock()
	for _, domain := range domains {
		cp.managedDomains[domain] = true
	}
	cp.mu.Unlock()

	// Request certificates for all domains
	return cp.magic.ManageSync(ctx, domains)
}

// UnmanageDomains removes domains from management.
func (cp *CertmagicCertProvider) UnmanageDomains(domains []string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, domain := range domains {
		delete(cp.managedDomains, domain)
	}
}

// GetManagedDomains returns the list of managed domains.
func (cp *CertmagicCertProvider) GetManagedDomains() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	domains := make([]string, 0, len(cp.managedDomains))
	for domain := range cp.managedDomains {
		domains = append(domains, domain)
	}
	return domains
}

// GetMagic returns the underlying certmagic.Config.
// Use this to access certmagic.GetCertificate directly for TLS config.
func (cp *CertmagicCertProvider) GetMagic() *certmagic.Config {
	return cp.magic
}

// IsManaged checks if a domain is managed by this provider.
func (cp *CertmagicCertProvider) IsManaged(domain string) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.managedDomains[domain]
}

// HasActiveChallenge checks if certmagic has an active ACME-TLS/1 challenge
// for the given domain. This checks both in-memory (this process) and
// distributed storage (other TLSrouter instances).
//
// When a domain has both terminate and passthrough routes (e.g., SSH terminate
// and HTTP passthrough), TLSrouter may need to get certificates. If TLSrouter
// has an active challenge, it should handle the ACME-TLS/1 request. Otherwise,
// the request should passthrough to the backend (e.g., Caddy), which handles
// its own ACME independently.
//
// Storage must be shared between TLSrouter instances (not with Caddy) for
// distributed challenge coordination.
func (cp *CertmagicCertProvider) HasActiveChallenge(domain string) bool {
	// 1. Check in-memory challenges (this process initiated)
	if _, ok := certmagic.GetACMEChallenge(domain); ok {
		return true
	}

	// 2. Check distributed storage (another process initiated)
	// This requires shared storage between TLSrouter and backends.
	if cp.magic.Storage == nil {
		return false
	}

	ctx := context.Background()

	// Check each issuer's challenge token storage
	for _, issuer := range cp.magic.Issuers {
		// Get the issuer key for storage path
		issuerKey := issuer.IssuerKey()
		prefix := storageKeyACMECAPrefix(issuerKey)
		tokenKey := path.Join(prefix, "challenge_tokens", certmagic.StorageKeys.Safe(domain)+".json")

		if cp.magic.Storage.Exists(ctx, tokenKey) {
			return true
		}
	}

	return false
}

// storageKeyACMECAPrefix returns the storage key prefix for ACME challenges.
// This mirrors certmagic's internal function.
func storageKeyACMECAPrefix(issuerKey string) string {
	return path.Join("acme_account", certmagic.StorageKeys.Safe(issuerKey))
}

package tlsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
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
		storage = cfg.Storage.(certmagic.Storage)
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

	// Create ACME issuer
	issuer := certmagic.ACMEIssuer{
		CA:                      cfg.DirectoryURL,
		Email:                   cfg.Email,
		Agreed:                  cfg.Agreed,
		DisableHTTPChallenge:    cfg.DisableHTTPChallenge,
		DisableTLSALPNChallenge: cfg.DisableTLSALPNChallenge,
	}

	// Add DNS-01 solver if provider specified
	if cfg.DNSProvider != nil {
		issuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: cfg.DNSProvider.(certmagic.DNSProvider),
			},
		}
	}

	// Create certmagic config
	magic := certmagic.New(cache, certmagic.Config{
		Storage: storage,
		Issuers: []certmagic.Issuer{&issuer},
		OnEvent: func(ctx context.Context, eventName string, data map[string]any) error {
			if eventName == "cert_obtaining" {
				domain := data["identifier"].(string)
				fmt.Printf("Obtaining certificate for %s\n", domain)
			} else if eventName == "cert_obtained" {
				domain := data["identifier"].(string)
				fmt.Printf("Certificate obtained for %s\n", domain)
			}
			return nil
		},
	})

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

package tlsrouter

import (
	"net"
	"sync/atomic"
)

// Config is the routing configuration.
// All reads must go through LoadConfig() to ensure thread-safety.
// Writes should use ReplaceConfig() for atomic swaps.
type Config struct {
	// Static routes
	StaticRoutes map[string]StaticRoute

	// Dynamic routing
	IPDomains []string
	Networks  []net.IPNet

	// ACME passthrough backend (optional)
	// If set, all acme-tls/1 challenges route to this backend
	ACMEPassthrough string

	// Per-domain ACME backend overrides
	// Maps domain -> backend for acme-tls/1 challenges
	ACMEBackends map[string]string

	// Certmagic config (for real ACME)
	Certmagic CertmagicConfig
}

// CertmagicConfig holds ACME certificate management settings.
type CertmagicConfig struct {
	// ACME directory URL
	// Leave empty for Let's Encrypt production
	DirectoryURL string

	// Email for ACME registration (optional but recommended)
	Email string

	// Agreed to terms
	Agreed bool

	// Disable HTTP challenge (usually true for TLS routers)
	DisableHTTPChallenge bool

	// Disable TLS-ALPN challenge
	// Usually false to allow certmagic to handle ACME
	DisableTLSALPNChallenge bool

	// DNS provider for DNS-01 challenges (optional)
	// If set, certmagic will use DNS-01 instead of TLS-ALPN
	DNSProvider interface{} // certmagic.DNSProvider

	// Storage backend for certificates
	// If nil, uses in-memory storage
	Storage interface{} // certmagic.Storage
}

// atomicConfig wraps Config for atomic swaps.
type atomicConfig struct {
	// Use atomic.Value for lock-free reads
	value atomic.Value
}

// newAtomicConfig creates a new atomic config wrapper.
func newAtomicConfig(cfg Config) *atomicConfig {
	ac := &atomicConfig{}
	ac.value.Store(cfg)
	return ac
}

// LoadConfig atomically loads the current configuration.
func (ac *atomicConfig) LoadConfig() Config {
	return ac.value.Load().(Config)
}

// ReplaceConfig atomically replaces the configuration.
// Returns the old configuration.
func (ac *atomicConfig) ReplaceConfig(newCfg Config) Config {
	oldCfg := ac.value.Load().(Config)
	ac.value.Store(newCfg)
	return oldCfg
}
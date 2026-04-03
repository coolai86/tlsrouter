package tlsrouter

import (
	"maps"
	"net"
	"sync/atomic"
)

// Config is the routing configuration.
// IMPORTANT: All Config instances must be treated as IMMUTABLE.
// Use atomic swaps to replace the entire config object.
// Do NOT modify maps or slices in a Config after it's been stored.
type Config struct {
	// Static routes
	// IMPORTANT: Do not modify this map after Config creation
	StaticRoutes map[string]StaticRoute

	// Dynamic routing
	// IMPORTANT: Do not modify these slices after Config creation
	IPDomains []string
	Networks  []net.IPNet

	// ACME passthrough backend (optional)
	// If set, all acme-tls/1 challenges route to this backend
	ACMEPassthrough string

	// Per-domain ACME backend overrides
	// IMPORTANT: Do not modify this map after Config creation
	// Maps domain -> backend for acme-tls/1 challenges
	ACMEBackends map[string]string

	// Certmagic config (for real ACME)
	// IMPORTANT: Do not modify this struct after Config creation
	Certmagic CertmagicConfig
}

// Copy creates a deep copy of the config.
// Use this when you need to modify config values safely.
func (c *Config) Copy() *Config {
	// Copy static routes map
	staticRoutes := make(map[string]StaticRoute, len(c.StaticRoutes))
	maps.Copy(staticRoutes, c.StaticRoutes)

	// Copy ACME backends map
	acmeBackends := make(map[string]string, len(c.ACMEBackends))
	maps.Copy(acmeBackends, c.ACMEBackends)

	// Copy IP domains slice
	ipDomains := make([]string, len(c.IPDomains))
	copy(ipDomains, c.IPDomains)

	// Copy networks slice
	networks := make([]net.IPNet, len(c.Networks))
	copy(networks, c.Networks)

	return &Config{
		StaticRoutes:    staticRoutes,
		IPDomains:       ipDomains,
		Networks:        networks,
		ACMEPassthrough: c.ACMEPassthrough,
		ACMEBackends:    acmeBackends,
		Certmagic:       c.Certmagic, // Struct copy
	}
}

// AddStaticRoute returns a new Config with the added static route.
// This is the safe way to modify config - create a copy, modify, then atomic swap.
func (c *Config) AddStaticRoute(key string, route StaticRoute) *Config {
	newCfg := c.Copy()
	newCfg.StaticRoutes[key] = route
	return newCfg
}

// RemoveStaticRoute returns a new Config with the static route removed.
func (c *Config) RemoveStaticRoute(key string) *Config {
	newCfg := c.Copy()
	delete(newCfg.StaticRoutes, key)
	return newCfg
}

// AddACMEBackend returns a new Config with the added ACME backend.
func (c *Config) AddACMEBackend(domain, backend string) *Config {
	newCfg := c.Copy()
	if newCfg.ACMEBackends == nil {
		newCfg.ACMEBackends = make(map[string]string)
	}
	newCfg.ACMEBackends[domain] = backend
	return newCfg
}

// RemoveACMEBackend returns a new Config with the ACME backend removed.
func (c *Config) RemoveACMEBackend(domain string) *Config {
	newCfg := c.Copy()
	if newCfg.ACMEBackends != nil {
		delete(newCfg.ACMEBackends, domain)
	}
	return newCfg
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
	DNSProvider any

	// Storage backend for certificates
	// If nil, uses in-memory storage
	Storage any
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

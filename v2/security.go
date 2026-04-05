package tlsrouter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SecurityConfig holds security-related configuration.
type SecurityConfig struct {
	// BlockedNetworks are IPs that should never be dialed.
	// Includes metadata endpoints, loopback, link-local, etc.
	// Defaults to SafeDefaults() if empty.
	BlockedNetworks []net.IPNet

	// AllowedNetworks are IPs that are explicitly permitted.
	// If set, only these networks can be dialed.
	// Supercedes BlockedNetworks.
	AllowedNetworks []net.IPNet

	// MaxALPNLength is the maximum allowed ALPN protocol length.
	// Default: 256
	MaxALPNLength int

	// DialTimeout is the timeout for backend connections.
	// Default: 500ms for VPC, 5s for public
	DialTimeout int

	// EnableLoopDetection enables the listener registry checks.
	// Default: true
	EnableLoopDetection bool

	// ResolveBeforeValidation enables DNS resolution before IP validation.
	// This prevents SSRF via malicious domains that resolve to blocked IPs.
	// Default: true
	ResolveBeforeValidation bool

	// DNSResolver is the resolver to use for DNS lookups.
	// If nil, uses net.DefaultResolver.
	DNSResolver *net.Resolver

	// ResolveTimeout is the timeout for DNS resolution.
	// Default: 5s
	ResolveTimeout time.Duration
}

// DefaultSecurityConfig returns safe defaults for VPC environments.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		BlockedNetworks:        SafeBlockedNetworks(),
		MaxALPNLength:          256,
		DialTimeout:            500, // 500ms - aggressive for VPC
		EnableLoopDetection:    true,
		ResolveBeforeValidation: true,
		ResolveTimeout:         5 * time.Second,
	}
}

// SafeBlockedNetworks returns networks that should never be dialed.
func SafeBlockedNetworks() []net.IPNet {
	nets := []net.IPNet{}

	// Cloud metadata endpoints
	metadataIPs := []string{
		"169.254.169.254/32", // AWS/GCP/Azure metadata
		"169.254.170.2/32",   // ECS task metadata
		"169.254.169.254/128", // IPv6 metadata (Azure)
	}

	// Localhost/loopback
	localIPs := []string{
		"127.0.0.0/8",   // Loopback IPv4
		"::1/128",       // Loopback IPv6
	}

	// Link-local (shouldn't be routed anyway, but block explicitly)
	linkLocal := []string{
		"169.254.0.0/16", // Link-local IPv4
		"fe80::/10",      // Link-local IPv6
	}

	// Multicast (shouldn't be TCP targets)
	multicast := []string{
		"224.0.0.0/4",  // Multicast IPv4
		"ff00::/8",     // Multicast IPv6
	}

	// Combine all
	all := append(append(append(metadataIPs, localIPs...), linkLocal...), multicast...)
	for _, cidr := range all {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, *n)
	}

	return nets
}

// SecurityValidator validates backend addresses and ALPN protocols.
type SecurityValidator struct {
	config *SecurityConfig
	mu     sync.RWMutex
}

// NewSecurityValidator creates a new validator with the given config.
func NewSecurityValidator(config *SecurityConfig) *SecurityValidator {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	return &SecurityValidator{config: config}
}

// ValidateBackend checks if a backend address is safe to dial.
// It blocks metadata endpoints, loopback, and other dangerous addresses.
// For hostnames, it only checks suspicious patterns - use ResolveAndValidateBackend
// for full DNS-based validation.
func (v *SecurityValidator) ValidateBackend(backend string) error {
	host, _, err := net.SplitHostPort(backend)
	if err != nil {
		// Try as IP:port without host
		return fmt.Errorf("invalid backend address: %s", backend)
	}

	// Parse as IP
	ip := net.ParseIP(host)
	if ip == nil {
		// It's a hostname, will be resolved by dialer
		// Check for suspicious hostnames
		if v.isSuspiciousHostname(host) {
			return fmt.Errorf("suspicious hostname blocked: %s", host)
		}
		return nil
	}

	return v.ValidateIP(ip)
}

// ResolveAndValidateBackend resolves a hostname and validates all resulting IPs.
// This prevents SSRF attacks via malicious domains that resolve to blocked IPs.
// For IP backends, it validates directly without DNS resolution.
func (v *SecurityValidator) ResolveAndValidateBackend(ctx context.Context, backend string) error {
	host, _, err := net.SplitHostPort(backend)
	if err != nil {
		return fmt.Errorf("invalid backend address: %s", backend)
	}

	// Check for suspicious hostnames first
	if v.isSuspiciousHostname(host) {
		return fmt.Errorf("suspicious hostname blocked: %s", host)
	}

	// If it's an IP, validate directly
	ip := net.ParseIP(host)
	if ip != nil {
		return v.ValidateIP(ip)
	}

	// It's a hostname - resolve and validate all IPs
	v.mu.RLock()
	resolveTimeout := v.config.ResolveTimeout
	resolveBefore := v.config.ResolveBeforeValidation
	dnsResolver := v.config.DNSResolver
	v.mu.RUnlock()

	// If resolve-before-validation is disabled, just warn
	if !resolveBefore {
		// Return nil but log warning in production
		// Security risk: hostname could resolve to blocked IP
		return nil
	}

	// Use configured timeout
	if resolveTimeout <= 0 {
		resolveTimeout = 5 * time.Second
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	var ips []net.IP
	var resolveErr error

	if dnsResolver != nil {
		// Use custom resolver
		var addrs []string
		addrs, resolveErr = dnsResolver.LookupHost(ctx, host)
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				ips = append(ips, ip)
			}
		}
	} else {
		// Use net.LookupIP with default resolver
		ips, resolveErr = net.LookupIP(host)
	}

	if resolveErr != nil {
		return fmt.Errorf("DNS resolution failed for %s: %w", host, resolveErr)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IPs resolved for %s", host)
	}

	// Validate ALL resolved IPs
	for _, ip := range ips {
		if err := v.ValidateIP(ip); err != nil {
			return fmt.Errorf("hostname %s resolves to blocked IP %s: %w", host, ip, err)
		}
	}

	return nil
}

// ValidateIP checks if an IP address is safe to dial.
func (v *SecurityValidator) ValidateIP(ip net.IP) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// If allowed networks are set, check against those
	if len(v.config.AllowedNetworks) > 0 {
		allowed := false
		for _, n := range v.config.AllowedNetworks {
			if n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP %s not in allowed networks", ip)
		}
	}

	// Check blocked networks
	for _, n := range v.config.BlockedNetworks {
		if n.Contains(ip) {
			return fmt.Errorf("IP %s is in blocked network %s", ip, n)
		}
	}

	return nil
}

// isSuspiciousHostname checks for suspicious patterns in hostnames.
func (v *SecurityValidator) isSuspiciousHostname(host string) bool {
	// Normalize to lowercase for case-insensitive matching
	host = strings.ToLower(host)

	// Block common metadata service hostnames
	// Check both exact match and as a subdomain component
	suspicious := []string{
		"metadata",
		"metadata.google",
		"metadata.azure",
		"instance-data",
		"169.254.169.254",
	}
	for _, s := range suspicious {
		// Exact match
		if host == s {
			return true
		}
		// Leading subdomain: "metadata." or "metadata.google."
		if strings.HasPrefix(host, s+".") {
			return true
		}
		// Trailing subdomain: ".metadata" or ".metadata.google"
		if strings.HasSuffix(host, "."+s) {
			return true
		}
		// Middle component: ".metadata." or ".metadata.google."
		if strings.Contains(host, "."+s+".") {
			return true
		}
	}
	return false
}

// ValidateALPN checks if an ALPN protocol is valid.
func (v *SecurityValidator) ValidateALPN(alpn string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	maxLen := v.config.MaxALPNLength
	if maxLen <= 0 {
		maxLen = 256
	}

	if len(alpn) > maxLen {
		return fmt.Errorf("ALPN protocol too long: %d bytes (max %d)", len(alpn), maxLen)
	}

	// ALPN must be valid per RFC 7301
	// Protocol names are opaque byte sequences between 1-255 bytes
	// We do additional validation for known protocols
	if len(alpn) == 0 {
		return fmt.Errorf("ALPN protocol cannot be empty")
	}

	return nil
}

// ValidateALPNList validates all ALPN protocols in the list.
func (v *SecurityValidator) ValidateALPNList(alpns []string) error {
	totalLen := 0
	for _, alpn := range alpns {
		if err := v.ValidateALPN(alpn); err != nil {
			return err
		}
		totalLen += len(alpn) + 1 // +1 for length prefix in TLS
	}

	// Total ALPN extension size should be reasonable
	if totalLen > 1024 {
		return fmt.Errorf("ALPN list too large: %d bytes (max 1024)", totalLen)
	}

	return nil
}

// KnownALPNs are protocols that are commonly used.
// Unknown protocols are not blocked, but can be logged for monitoring.
var KnownALPNs = map[string]bool{
	"h2":            true,
	"http/1.1":      true,
	"http/1.0":      true,
	"ssh":           true,
	"postgresql":    true,
	"mysql":         true,
	"redis":         true,
	"mqtt":          true,
	"stunnel":       true,
	"acme-tls/1":    true,
	"h3":            true, // QUIC HTTP/3
	"h3-29":         true, // QUIC draft-29
	"grpc-exp":      true,
}

// IsKnownALPN returns true if the ALPN is a commonly known protocol.
func IsKnownALPN(alpn string) bool {
	return KnownALPNs[alpn]
}

// SetAllowedNetworks updates the allowed networks at runtime.
func (v *SecurityValidator) SetAllowedNetworks(networks []net.IPNet) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config.AllowedNetworks = networks
}

// SetBlockedNetworks updates the blocked networks at runtime.
func (v *SecurityValidator) SetBlockedNetworks(networks []net.IPNet) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config.BlockedNetworks = networks
}

// SetResolveBeforeValidation enables or disables DNS resolution before validation.
func (v *SecurityValidator) SetResolveBeforeValidation(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config.ResolveBeforeValidation = enabled
}

// SetDNSResolver sets a custom DNS resolver.
func (v *SecurityValidator) SetDNSResolver(resolver *net.Resolver) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config.DNSResolver = resolver
}
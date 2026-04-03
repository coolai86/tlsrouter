package tlsrouter

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// DNSCache resolves domain names with TTL caching.
// Supports CNAME chains (up to 2 levels) and SRV records with zone validation.
type DNSCache struct {
	minTTL time.Duration
	maxTTL  time.Duration
	maxDepth int

	// Cache entries
	entries sync.Map // hostname -> *dnsCacheEntry

	// Resolver
	resolver *net.Resolver
}

type dnsCacheEntry struct {
	ips        []net.IP
	port       uint16 // For SRV records
	expiresAt  time.Time
	resolvedAt time.Time
	mu         sync.RWMutex
}

// DNSCacheOption configures the DNS cache.
type DNSCacheOption func(*DNSCache)

// WithMinTTL sets the minimum TTL for cache entries.
func WithMinTTL(ttl time.Duration) DNSCacheOption {
	return func(c *DNSCache) { c.minTTL = ttl }
}

// WithMaxTTL sets the maximum TTL for cache entries.
func WithMaxTTL(ttl time.Duration) DNSCacheOption {
	return func(c *DNSCache) { c.maxTTL = ttl }
}

// WithResolver sets a custom resolver.
func WithResolver(r *net.Resolver) DNSCacheOption {
	return func(c *DNSCache) { c.resolver = r }
}

// NewDNSCache creates a new DNS cache with TTL limits.
func NewDNSCache(opts ...DNSCacheOption) *DNSCache {
	c := &DNSCache{
		minTTL:   15 * time.Second,
		maxTTL:   5 * time.Minute,
		maxDepth: 2,
		resolver: net.DefaultResolver,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ResolveResult contains the resolved IP addresses and optional port.
type ResolveResult struct {
	IPs    []net.IP
	Port   uint16   // 0 if not from SRV
	Target string   // SRV target hostname (for validation)
	TTL    time.Duration
}

// Resolve resolves a hostname to IP addresses.
// For direct IPs, returns immediately. For hostnames, follows CNAME chains.
func (c *DNSCache) Resolve(ctx context.Context, hostname string) (*ResolveResult, error) {
	// Check if it's already an IP
	if ip := net.ParseIP(hostname); ip != nil {
		return &ResolveResult{
			IPs: []net.IP{ip},
			TTL: c.maxTTL, // IPs don't expire
		}, nil
	}

	// Check cache
	if entry, ok := c.load(hostname); ok {
		if time.Now().Before(entry.expiresAt) {
			entry.mu.RLock()
			defer entry.mu.RUnlock()
			return &ResolveResult{
				IPs:  entry.ips,
				Port: entry.port,
				TTL:  time.Until(entry.expiresAt),
			}, nil
		}
	}

	// Resolve with CNAME following
	result, err := c.resolveWithCNAME(ctx, hostname, 0)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.store(hostname, result.IPs, result.Port, result.TTL)

	return result, nil
}

// ResolveSRV resolves an SRV record and validates zone constraints.
// The target must be a subdomain of the original domain.
func (c *DNSCache) ResolveSRV(ctx context.Context, service, proto, domain string) (*ResolveResult, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("_%s._%s.%s", service, proto, domain)
	if entry, ok := c.load(cacheKey); ok {
		if time.Now().Before(entry.expiresAt) {
			entry.mu.RLock()
			defer entry.mu.RUnlock()
			return &ResolveResult{
				IPs:  entry.ips,
				Port: entry.port,
				TTL:  time.Until(entry.expiresAt),
			}, nil
		}
	}

	// Lookup SRV record
	_, srvs, err := c.resolver.LookupSRV(ctx, service, proto, domain)
	if err != nil {
		return nil, fmt.Errorf("SRV lookup failed: %w", err)
	}

	if len(srvs) == 0 {
		return nil, fmt.Errorf("no SRV records for %s", cacheKey)
	}

	// Sort by priority (lower is preferred), then weight
	slices.SortFunc(srvs, func(a, b *net.SRV) int {
		if a.Priority != b.Priority {
			return int(a.Priority - b.Priority)
		}
		return int(a.Weight - b.Weight)
	})

	// Take the first (highest priority, lowest value)
	srv := srvs[0]
	target := strings.TrimSuffix(srv.Target, ".")

	// Validate zone constraint: target must be within domain
	if !c.isSubdomain(target, domain) {
		return nil, fmt.Errorf("SRV target %s is not a subdomain of %s", target, domain)
	}

	// Resolve target to IPs
	ips, err := c.resolveTarget(ctx, target, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SRV target %s: %w", target, err)
	}

	// Use min TTL since net.SRV doesn't include TTL
	// (would need raw DNS lookup for actual TTL)
	ttl := c.minTTL

	// Store in cache
	c.store(cacheKey, ips, uint16(srv.Port), ttl)

	return &ResolveResult{
		IPs:    ips,
		Port:   uint16(srv.Port),
		Target: target,
		TTL:    ttl,
	}, nil
}

// resolveWithCNAME follows CNAME chains up to maxDepth.
func (c *DNSCache) resolveWithCNAME(ctx context.Context, hostname string, depth int) (*ResolveResult, error) {
	if depth >= c.maxDepth {
		return nil, fmt.Errorf("CNAME chain too deep (max %d)", c.maxDepth)
	}

	// Try to resolve as A/AAAA
	ips, err := c.resolver.LookupIPAddr(ctx, hostname)
	if err == nil && len(ips) > 0 {
		ttl := c.clampTTL(c.minTTL) // Use min TTL for direct resolution
		return &ResolveResult{
			IPs:  ipAddrsToIPs(ips),
			TTL:  ttl,
		}, nil
	}

	// Try CNAME lookup
	cname, err := c.resolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}

	// CNAME points to itself or same name - return error
	if cname == hostname || strings.TrimSuffix(cname, ".") == strings.TrimSuffix(hostname, ".") {
		return nil, fmt.Errorf("CNAME loop detected: %s", hostname)
	}

	// Recursively resolve CNAME target
	return c.resolveWithCNAME(ctx, cname, depth+1)
}

// resolveTarget resolves a hostname to IPs, following CNAME chains.
func (c *DNSCache) resolveTarget(ctx context.Context, hostname string, depth int) ([]net.IP, error) {
	if depth >= c.maxDepth {
		return nil, fmt.Errorf("CNAME chain too deep")
	}

	ips, err := c.resolver.LookupIPAddr(ctx, hostname)
	if err == nil && len(ips) > 0 {
		return ipAddrsToIPs(ips), nil
	}

	// Try CNAME
	cname, err := c.resolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return nil, err
	}

	return c.resolveTarget(ctx, cname, depth+1)
}

// isSubdomain checks if child is a subdomain of parent.
func (c *DNSCache) isSubdomain(child, parent string) bool {
	child = strings.TrimSuffix(strings.ToLower(child), ".")
	parent = strings.TrimSuffix(strings.ToLower(parent), ".")

	// Exact match
	if child == parent {
		return true
	}

	// Child must end with .parent
	return strings.HasSuffix(child, "."+parent)
}

// clampTTL ensures TTL is within min/max bounds.
func (c *DNSCache) clampTTL(ttl time.Duration) time.Duration {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

// load retrieves a cached entry.
func (c *DNSCache) load(hostname string) (*dnsCacheEntry, bool) {
	v, ok := c.entries.Load(hostname)
	if !ok {
		return nil, false
	}
	return v.(*dnsCacheEntry), true
}

// store saves a result in the cache.
func (c *DNSCache) store(hostname string, ips []net.IP, port uint16, ttl time.Duration) {
	now := time.Now()
	entry := &dnsCacheEntry{
		ips:        ips,
		port:       port,
		expiresAt:  now.Add(ttl),
		resolvedAt: now,
	}
	c.entries.Store(hostname, entry)
}

// ipAddrsToIPs converts net.IPAddr slice to net.IP slice.
func ipAddrsToIPs(addrs []net.IPAddr) []net.IP {
	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}
	return ips
}

// Clear removes all cached entries.
func (c *DNSCache) Clear() {
	c.entries.Range(func(key, value any) bool {
		c.entries.Delete(key)
		return true
	})
}

// Size returns the number of cached entries.
func (c *DNSCache) Size() int {
	count := 0
	c.entries.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// Prune removes expired entries from the cache.
func (c *DNSCache) Prune() int {
	now := time.Now()
	count := 0
	c.entries.Range(func(key, value any) bool {
		entry := value.(*dnsCacheEntry)
		entry.mu.RLock()
		expired := now.After(entry.expiresAt)
		entry.mu.RUnlock()
		if expired {
			c.entries.Delete(key)
			count++
		}
		return true
	})
	return count
}

// ResolveDirectIPDomain resolves a hostname that may be a CNAME/SRV
// pointing to a direct IP domain (e.g., tls-192-168-1-100.vm.example.com).
//
// Resolution order:
// 1. If hostname is already a direct IP domain (tls-* or tcp-*), extract IP
// 2. Try SRV lookup for _alpn._tcp.hostname
// 3. Try CNAME resolution
// 4. Return resolved IP or error
//
// SRV targets must be valid direct IP domains with matching ports.
func (c *DNSCache) ResolveDirectIPDomain(ctx context.Context, hostname, alpn string, ipDomains []string, networks []net.IPNet, terminated bool) (net.IP, uint16, error) {
	hostname = strings.ToLower(hostname)

	// Check if it's already a direct IP domain
	if ip, port, ok := ParseDirectIPDomain(hostname, ipDomains); ok {
		// Validate IP is in allowed networks
		if !ipInNetworks(ip, networks) {
			return nil, 0, fmt.Errorf("IP %s not in allowed networks", ip)
		}
		return ip, port, nil
	}

	// Try SRV lookup: _alpn._tcp.hostname
	// e.g., for alpn "ssh", look up _ssh._tcp.hostname
	svc := alpn
	if svc == "http/1.1" {
		svc = "http"
	}
	if svc == "h2c" {
		svc = "h2"
	}

	srvResult, err := c.ResolveSRV(ctx, svc, "tcp", hostname)
	if err == nil && srvResult.Target != "" {
		// SRV target must be a direct IP domain
		// Example: tls-10-11-0-101.vms.tlsrouter.net.app.example.com
		targetIP, _, ok := ParseDirectIPDomain(srvResult.Target, ipDomains)
		if !ok {
			return nil, 0, fmt.Errorf("SRV target %s is not a valid direct IP domain", srvResult.Target)
		}

		// Validate IP is in allowed networks
		if !ipInNetworks(targetIP, networks) {
			return nil, 0, fmt.Errorf("SRV target IP %s not in allowed networks", targetIP)
		}

		// Validate the port matches expected ports for this ALPN
		// SRV port must be one of the valid ports for this ALPN
		validPorts := ValidPortsForALPN(alpn, terminated)
		if len(validPorts) > 0 {
			portValid := false
			for _, p := range validPorts {
				if srvResult.Port == p {
					portValid = true
					break
				}
			}
			if !portValid {
				return nil, 0, fmt.Errorf("SRV port %d not valid for ALPN %s (expected one of %v)", srvResult.Port, alpn, validPorts)
			}
		}

		return targetIP, srvResult.Port, nil
	}

	// Try CNAME resolution
	result, err := c.Resolve(ctx, hostname)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}

	// Check if CNAME target is a direct IP domain
	for _, ip := range result.IPs {
		if ipInNetworks(ip, networks) {
			return ip, 0, nil
		}
	}

	return nil, 0, fmt.Errorf("no valid IP found for %s", hostname)
}

// ParseDirectIPDomain extracts IP and port from a direct IP domain.
// Returns (nil, 0, false) if not a direct IP domain.
func ParseDirectIPDomain(hostname string, ipDomains []string) (net.IP, uint16, bool) {
	hostname = strings.ToLower(hostname)

	// Check prefix: tls- or tcp-
	terminate := strings.HasPrefix(hostname, "tls-")
	prefix := "tls-"
	if !terminate {
		if !strings.HasPrefix(hostname, "tcp-") {
			return nil, 0, false
		}
		terminate = false
		prefix = "tcp-"
	}

	// Extract IP label
	labelEnd := strings.IndexByte(hostname, '.')
	if labelEnd == -1 {
		return nil, 0, false
	}
	ipLabel := hostname[len(prefix):labelEnd]
	sld := hostname[labelEnd+1:]

	// Check domain matches
	found := false
	for _, domain := range ipDomains {
		if domain == sld {
			found = true
			break
		}
	}
	if !found {
		return nil, 0, false
	}

	// Parse IP
	ipStr := strings.ReplaceAll(ipLabel, "-", ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, 0, false
	}

	return ip, 0, true
}

// ipInNetworks checks if an IP is in any of the allowed networks.
func ipInNetworks(ip net.IP, networks []net.IPNet) bool {
	if len(networks) == 0 {
		return true // No network restrictions
	}
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
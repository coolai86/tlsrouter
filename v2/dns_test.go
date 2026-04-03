package tlsrouter

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDNSCache_ResolveDirectIP(t *testing.T) {
	cache := NewDNSCache()

	// Direct IP should return immediately
	result, err := cache.Resolve(context.Background(), "192.168.1.1")
	if err != nil {
		t.Fatalf("Resolve(IP) failed: %v", err)
	}
	if len(result.IPs) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(result.IPs))
	}
	if !result.IPs[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected 192.168.1.1, got %s", result.IPs[0])
	}
}

func TestDNSCache_TTLClamping(t *testing.T) {
	cache := NewDNSCache(
		WithMinTTL(15*time.Second),
		WithMaxTTL(5*time.Minute),
	)

	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"below min", 5 * time.Second, 15 * time.Second},
		{"within bounds", 2 * time.Minute, 2 * time.Minute},
		{"above max", 10 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.clampTTL(tt.input)
			if got != tt.expected {
				t.Errorf("clampTTL(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDNSCache_Caching(t *testing.T) {
	cache := NewDNSCache(WithMinTTL(10 * time.Second))

	hostname := "test.example.com"

	// Store in cache
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	cache.store(hostname, ips, 0, 30*time.Second)

	// Should retrieve from cache
	entry, ok := cache.load(hostname)
	if !ok {
		t.Fatal("Expected cache entry")
	}

	entry.mu.RLock()
	if len(entry.ips) != 1 || !entry.ips[0].Equal(ips[0]) {
		t.Errorf("Cached IP mismatch")
	}
	if entry.port != 0 {
		t.Errorf("Expected port 0, got %d", entry.port)
	}
	entry.mu.RUnlock()

	// Test cache size
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Clear and verify
	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("Expected empty cache after clear")
	}
}

func TestDNSCache_Prune(t *testing.T) {
	cache := NewDNSCache(WithMinTTL(1 * time.Second))

	// Store entries with different TTLs
	cache.store("short.example.com", []net.IP{net.ParseIP("192.168.1.1")}, 0, 1*time.Second)
	cache.store("long.example.com", []net.IP{net.ParseIP("192.168.1.2")}, 0, 5*time.Minute)

	// Both should be present
	if cache.Size() != 2 {
		t.Errorf("Expected 2 entries, got %d", cache.Size())
	}

	// Wait for short to expire
	time.Sleep(2 * time.Second)

	// Prune expired
	pruned := cache.Prune()
	if pruned != 1 {
		t.Errorf("Expected 1 pruned entry, got %d", pruned)
	}

	// Only long should remain
	if cache.Size() != 1 {
		t.Errorf("Expected 1 entry after prune, got %d", cache.Size())
	}
}

func TestDNSCache_IsSubdomain(t *testing.T) {
	cache := NewDNSCache()

	tests := []struct {
		parent string
		child  string
		want   bool
	}{
		{"example.com", "sub.example.com", true},
		{"example.com", "deep.sub.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"example.com", "notexample.com", false},
		{"example.com.", "sub.example.com", true},
		{"example.com", "sub.example.com.", true},
	}

	for _, tt := range tests {
		t.Run(tt.parent+"_"+tt.child, func(t *testing.T) {
			got := cache.isSubdomain(tt.child, tt.parent)
			if got != tt.want {
				t.Errorf("isSubdomain(%q, %q) = %v, want %v", tt.child, tt.parent, got, tt.want)
			}
		})
	}
}

func TestParseDirectIPDomain(t *testing.T) {
	ipDomains := []string{"vm.example.com", "internal.local"}

	tests := []struct {
		hostname string
		wantIP   string
		wantOK   bool
	}{
		{"tls-192-168-1-100.vm.example.com", "192.168.1.100", true},
		{"tcp-10-0-0-1.vm.example.com", "10.0.0.1", true},
		{"tls-256-0-0-1.vm.example.com", "", false}, // Invalid IP
		{"tls-192-168-1-100.other.com", "", false}, // Domain not in list
		{"not-a-direct-domain.com", "", false},      // No prefix
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			ip, _, ok := ParseDirectIPDomain(tt.hostname, ipDomains)
			if ok != tt.wantOK {
				t.Errorf("ParseDirectIPDomain(%q) ok = %v, want %v", tt.hostname, ok, tt.wantOK)
				return
			}
			if tt.wantOK && !ip.Equal(net.ParseIP(tt.wantIP)) {
				t.Errorf("ParseDirectIPDomain(%q) IP = %v, want %v", tt.hostname, ip, tt.wantIP)
			}
		})
	}
}

func TestIPInNetworks(t *testing.T) {
	_, net1, _ := net.ParseCIDR("192.168.0.0/16")
	_, net2, _ := net.ParseCIDR("10.0.0.0/8")
	networks := []net.IPNet{*net1, *net2}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := ipInNetworks(ip, networks)
			if result != tt.expected {
				t.Errorf("ipInNetworks(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestDNSCache_ResolveDirectIPDomain_InvalidDomain(t *testing.T) {
	cache := NewDNSCache()
	_, network, _ := net.ParseCIDR("192.168.0.0/16")

	ip, port, err := cache.ResolveDirectIPDomain(context.Background(), "not-a-direct-domain.com", "ssh", []string{"vm.example.com"}, []net.IPNet{*network}, false)
	if err == nil {
		t.Error("Expected error for invalid domain, got nil")
	}
	_ = ip
	_ = port
}
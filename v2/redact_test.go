package tlsrouter

import (
	"strings"
	"testing"
)

func TestRedactDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		contains string
	}{
		{"empty", "", "[empty]"},
		{"short", "ab", "ab..."},
		{"medium", "example", "exam..."},
		{"long", "internal-api.example.com", "inte"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactDomain(tt.domain)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("RedactDomain(%q) = %q, want to contain %q", tt.domain, result, tt.contains)
			}
			// Verify hash suffix for long domains
			if len(tt.domain) > 8 {
				if !strings.Contains(result, "...") {
					t.Errorf("RedactDomain(%q) should contain '...' for identification", tt.domain)
				}
			}
		})
	}
}

func TestRedactBackend(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		contains string
	}{
		{"empty", "", "[empty]"},
		{"with_port", "10.0.0.1:8080", ":8080"},
		{"no_port", "example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactBackend(tt.backend)
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("RedactBackend(%q) = %q, want to contain %q", tt.backend, result, tt.contains)
			}
		})
	}
}

func TestRedactIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		contains string
	}{
		{"empty", "", "[empty]"},
		{"ipv4", "192.168.1.1", "ip:"},
		{"ipv6", "::1", "ip:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactIP(tt.ip)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("RedactIP(%q) = %q, want to contain %q", tt.ip, result, tt.contains)
			}
		})
	}
}

func TestRedactionConsistency(t *testing.T) {
	// Same input should produce same output
	domain := "secret.example.com"
	result1 := RedactDomain(domain)
	result2 := RedactDomain(domain)
	if result1 != result2 {
		t.Errorf("RedactDomain not consistent: %q != %q", result1, result2)
	}

	// Different inputs should produce different outputs
	domain2 := "different.example.com"
	result3 := RedactDomain(domain2)
	if result1 == result3 {
		t.Errorf("Different domains should produce different redactions")
	}
}
package tlsrouter

import (
	"net"
	"testing"
)

func TestSecurityValidator_ValidateBackend(t *testing.T) {
	v := NewSecurityValidator(nil) // Use defaults

	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"valid IP", "192.168.1.100:443", false},
		{"valid hostname", "example.com:443", false},
		{"metadata blocked", "169.254.169.254:80", true},
		{"loopback blocked", "127.0.0.1:443", true},
		{"link-local blocked", "169.254.1.1:443", true},
		{"suspicious hostname", "metadata.google:80", true},
		{"valid IPv6", "[::ffff:192.168.1.1]:443", false},
		{"loopback IPv6 blocked", "[::1]:443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateBackend(tt.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBackend(%q) = %v, want error=%v", tt.backend, err, tt.wantErr)
			}
		})
	}
}

func TestSecurityValidator_ValidateIP(t *testing.T) {
	v := NewSecurityValidator(nil)

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid private", "192.168.1.1", false},
		{"valid public", "8.8.8.8", false},
		{"metadata blocked", "169.254.169.254", true},
		{"loopback blocked", "127.0.0.1", true},
		{"link-local blocked", "169.254.100.1", true},
		{"multicast blocked", "224.0.0.1", true},
		{"valid IPv6", "2001:db8::1", false},
		{"loopback IPv6 blocked", "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			err := v.ValidateIP(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIP(%s) = %v, want error=%v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestSecurityValidator_ValidateALPN(t *testing.T) {
	v := NewSecurityValidator(nil)

	tests := []struct {
		name    string
		alpn    string
		wantErr bool
	}{
		{"valid h2", "h2", false},
		{"valid http/1.1", "http/1.1", false},
		{"valid acme-tls/1", "acme-tls/1", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 300)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateALPN(tt.alpn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateALPN(%q) = %v, want error=%v", tt.alpn, err, tt.wantErr)
			}
		})
	}
}

func TestSecurityValidator_AllowedNetworks(t *testing.T) {
	_, vpc1, _ := net.ParseCIDR("10.0.0.0/8")
	_, vpc2, _ := net.ParseCIDR("192.168.0.0/16")

	v := NewSecurityValidator(&SecurityConfig{
		AllowedNetworks: []net.IPNet{*vpc1, *vpc2},
	})

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"allowed 10.x", "10.0.0.1", false},
		{"allowed 192.168.x", "192.168.1.1", false},
		{"blocked public", "8.8.8.8", true},
		{"blocked metadata", "169.254.169.254", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			err := v.ValidateIP(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIP(%s) = %v, want error=%v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestSafeBlockedNetworks(t *testing.T) {
	nets := SafeBlockedNetworks()

	// Check that key networks are included
	checks := []struct {
		name string
		ip   string
		want bool
	}{
		{"metadata", "169.254.169.254", true},
		{"loopback", "127.0.0.1", true},
		{"link-local", "169.254.100.1", true},
		{"multicast", "224.0.0.1", true},
		{"public", "8.8.8.8", false},
	}

	for _, tt := range checks {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			blocked := false
			for _, n := range nets {
				if n.Contains(ip) {
					blocked = true
					break
				}
			}
			if blocked != tt.want {
				t.Errorf("IP %s blocked=%v, want %v", tt.ip, blocked, tt.want)
			}
		})
	}
}

func TestIsKnownALPN(t *testing.T) {
	known := []string{"h2", "http/1.1", "ssh", "acme-tls/1"}
	unknown := []string{"weird-protocol", "custom-app"}

	for _, alpn := range known {
		if !IsKnownALPN(alpn) {
			t.Errorf("IsKnownALPN(%q) = false, want true", alpn)
		}
	}

	for _, alpn := range unknown {
		if IsKnownALPN(alpn) {
			t.Errorf("IsKnownALPN(%q) = true, want false", alpn)
		}
	}
}
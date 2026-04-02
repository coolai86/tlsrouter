package tlsrouter

import (
	"testing"
)

func TestStaticRouter(t *testing.T) {
	router := NewStaticRouter(map[string]StaticRoute{
		"example.com>http/1.1": {
			Backend: "192.168.1.100:3080",
			Action:  ActionTerminate,
		},
		"example.com>ssh": {
			Backend: "192.168.1.100:22",
			Action:  ActionTerminate,
		},
		".example.com>http/1.1": {
			Backend: "192.168.1.101:3080",
			Action:  ActionTerminate,
		},
		"passthrough.example.com>h2": {
			Backend: "192.168.1.102:443",
			Action:  ActionPassthrough,
		},
	})

	tests := []struct {
		name     string
		sni      string
		alpns    []string
		wantErr  bool
		expected Decision
	}{
		{
			name:  "exact match",
			sni:   "example.com",
			alpns: []string{"h2", "http/1.1"},
			expected: Decision{
				Action:  ActionTerminate,
				Backend: "192.168.1.100:3080",
				Domain:  "example.com",
				ALPN:    "http/1.1",
			},
		},
		{
			name:  "ssh match",
			sni:   "example.com",
			alpns: []string{"ssh"},
			expected: Decision{
				Action:  ActionTerminate,
				Backend: "192.168.1.100:22",
				Domain:  "example.com",
				ALPN:    "ssh",
			},
		},
		{
			name:  "wildcard subdomain",
			sni:   "sub.example.com",
			alpns: []string{"http/1.1"},
			expected: Decision{
				Action:  ActionTerminate,
				Backend: "192.168.1.101:3080",
				Domain:  "sub.example.com",
				ALPN:    "http/1.1",
			},
		},
		{
			name:  "passthrough",
			sni:   "passthrough.example.com",
			alpns: []string{"h2"},
			expected: Decision{
				Action:  ActionPassthrough,
				Backend: "192.168.1.102:443",
				Domain:  "passthrough.example.com",
				ALPN:    "h2",
			},
		},
		{
			name:    "no match",
			sni:     "other.com",
			alpns:   []string{"http/1.1"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := router.Route(tt.sni, tt.alpns)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if decision.Action != tt.expected.Action {
				t.Errorf("Action: got %v, want %v", decision.Action, tt.expected.Action)
			}
			if decision.Backend != tt.expected.Backend {
				t.Errorf("Backend: got %v, want %v", decision.Backend, tt.expected.Backend)
			}
			if decision.ALPN != tt.expected.ALPN {
				t.Errorf("ALPN: got %v, want %v", decision.ALPN, tt.expected.ALPN)
			}
		})
	}
}
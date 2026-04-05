package tlsrouter

import (
	"testing"
)

func TestValidateHeaderValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"empty", "", false},
		{"normal", "example.com", false},
		{"with hyphen", "my-domain.example.com", false},
		{"CRLF injection", "example.com\r\nX-Injected: evil", true},
		{"LF only", "example.com\nX-Injected: evil", true},
		{"CR only", "example.com\rX-Injected: evil", true},
		{"embedded CRLF", "exam\r\nple.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaderValue(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHeaderValue(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal", "example.com", "example.com"},
		{"CRLF", "example.com\r\nX-Injected: evil", "example.comX-Injected: evil"},
		{"LF only", "a\nb", "ab"},
		{"CR only", "a\rb", "ab"},
		{"multiple", "a\r\nb\r\nc", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeHeaderValue(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeHeaderValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"empty", "", false},
		{"valid domain", "example.com", false},
		{"valid subdomain", "api.example.com", false},
		{"wildcard", "*.example.com", false},
		{"CRLF injection", "example.com\r\nX-Injected: evil", true},
		{"LF only", "example.com\nevil", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestValidateALPN(t *testing.T) {
	tests := []struct {
		name    string
		alpn    string
		wantErr bool
	}{
		{"empty", "", false},
		{"h2", "h2", false},
		{"http/1.1", "http/1.1", false},
		{"CRLF injection", "h2\r\nX-Injected: evil", true},
		{"null byte", "h2\x00evil", true},
		{"control char", "h2\x01", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateALPN(tt.alpn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateALPN(%q) error = %v, wantErr %v", tt.alpn, err, tt.wantErr)
			}
		})
	}
}
package tlsrouter

import (
	"errors"
	"net/http"
	"strings"
)

// Header injection characters that indicate CRLF injection attempts.
var headerInjectionChars = "\r\n"

// ErrHeaderInjection is returned when a header value contains injection characters.
var ErrHeaderInjection = errors.New("header value contains forbidden characters")

// ValidateHeaderValue checks that a header value is safe to set.
// It rejects values containing CR or LF characters which could enable
// header injection attacks.
func ValidateHeaderValue(value string) error {
	if strings.ContainsAny(value, headerInjectionChars) {
		return ErrHeaderInjection
	}
	return nil
}

// SafeHeaderSet sets a header value after validating it's safe.
// Returns an error if the value contains injection characters.
func SafeHeaderSet(h http.Header, key, value string) error {
	if err := ValidateHeaderValue(value); err != nil {
		return err
	}
	h.Set(key, value)
	return nil
}

// SanitizeHeaderValue removes CRLF characters from a header value.
// Use this when you need to accept potentially unsafe input.
// Prefer ValidateHeaderValue when you can reject invalid input.
func SanitizeHeaderValue(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1 // remove
		}
		return r
	}, value)
}

// ValidateDomain validates a domain name for use in headers.
// Returns an error if the domain contains unsafe characters.
func ValidateDomain(domain string) error {
	if domain == "" {
		return nil // empty is ok
	}
	// Check for injection characters
	if strings.ContainsAny(domain, headerInjectionChars) {
		return ErrHeaderInjection
	}
	// Additional domain validation could go here
	// For now, we trust the TLS handshake to provide valid SNI
	return nil
}

// ValidateALPN validates an ALPN protocol name for use in headers.
// Returns an error if the protocol name contains unsafe characters.
func ValidateALPN(alpn string) error {
	if alpn == "" {
		return nil // empty is ok
	}
	// Check for injection characters
	if strings.ContainsAny(alpn, headerInjectionChars) {
		return ErrHeaderInjection
	}
	// ALPN should be ASCII printable without spaces/control chars
	for _, r := range alpn {
		if r < 32 || r > 126 {
			return errors.New("ALPN contains non-printable characters")
		}
	}
	return nil
}
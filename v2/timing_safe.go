package tlsrouter

import (
	"crypto/subtle"
)

// ConstantTimeCompare compares two byte slices in constant time.
// This is a wrapper around subtle.ConstantTimeCompare that prevents timing attacks.
//
// IMPORTANT: Both inputs must be the same length for timing-safety guarantees.
// Use HMAC-SHA256 or similar to ensure fixed-length inputs.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeStringCompare compares two strings in constant time.
// WARNING: This leaks length information if strings differ in length.
// Use HMAC-SHA256 to hash both strings before comparing.
func ConstantTimeStringCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// TIMING SAFETY NOTE:
//
// The upstream github.com/therootcompany/golib/auth/csvauth package uses
// bytes.Equal() for credential comparison, which is NOT timing-safe.
// However, credentials are hashed with SHA-256 before comparison, so:
//   - Both inputs are always 32 bytes (fixed length)
//   - Comparison is on hashes, not raw passwords
//   - Attackers must guess 256-bit hash values, making timing attacks impractical
//
// The correct fix is to use subtle.ConstantTimeCompare upstream.
// Issue filed: https://github.com/therootcompany/golib/issues/XXX
//
// This package provides timing-safe comparison utilities for future use
// and serves as documentation of the issue.
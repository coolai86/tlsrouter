package tlsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RedactDomain masks sensitive domain names in logs.
// Returns first 4 chars + "..." + hash prefix for identification.
// Example: "internal-api.example.com" -> "inte...a1b2c3"
func RedactDomain(domain string) string {
	if domain == "" {
		return "[empty]"
	}
	
	// Short domains are less sensitive
	if len(domain) <= 8 {
		return domain[:min(4, len(domain))] + "..."
	}
	
	// Hash the domain for consistent identification
	h := sha256.Sum256([]byte(domain))
	hashPrefix := hex.EncodeToString(h[:3])[:6]
	
	// Return prefix + "..." + hash
	return domain[:4] + "..." + hashPrefix
}

// RedactBackend masks backend addresses in logs.
// Shows port and hash prefix for identification.
// Example: "10.0.0.1:8080" -> ":8080 a1b2c3"
func RedactBackend(backend string) string {
	if backend == "" {
		return "[empty]"
	}
	
	// Split host:port
	host, port := backend, ""
	if idx := strings.LastIndex(backend, ":"); idx > 0 {
		host = backend[:idx]
		port = backend[idx:] // includes ":"
	}
	
	// Hash the host for identification
	h := sha256.Sum256([]byte(host))
	hashPrefix := hex.EncodeToString(h[:3])[:6]
	
	// Return port + hash
	if port != "" {
		return port + " " + hashPrefix
	}
	return hashPrefix
}

// RedactIP masks IP addresses in logs.
// Shows hash prefix only.
// Example: "192.168.1.1" -> "ip:a1b2c3"
func RedactIP(ip string) string {
	if ip == "" {
		return "[empty]"
	}
	
	h := sha256.Sum256([]byte(ip))
	hashPrefix := hex.EncodeToString(h[:3])[:6]
	return "ip:" + hashPrefix
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
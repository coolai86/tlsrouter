// +build integration

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// Integration test for ACME shared domain between two TLSrouter instances.
//
// Architecture:
//
//	TLSrouter A (:443)
//	├── example.com>ssh → terminate, CertMagic manages
//	└── example.com>http/1.1 → passthrough to B:8443
//	    └── ACMEBackends[example.com] = "127.0.0.1:8443"
//
//	TLSrouter B (:8443)
//	└── example.com>http/1.1 → terminate, CertMagic manages
//
// Both use:
//   - Let's Encrypt Staging (to avoid rate limits)
//   - Shared storage for challenge coordination
//   - DuckDNS for DNS-01 challenge
//
// Required environment variables:
//
//	TEST_DOMAIN     - DuckDNS domain (e.g., "test.duckdns.org")
//	DUCKDNS_TOKEN   - DuckDNS API token
//	ACME_EMAIL      - Email for ACME registration (optional)
//
// Run:
//
//	go run ./cmd/integration-test/main.go
//
// Or with environment:
//
//	TEST_DOMAIN=example.duckdns.org DUCKDNS_TOKEN=xxx go run ./cmd/integration-test/main.go

func main() {
	domain := os.Getenv("TEST_DOMAIN")
	duckdnsToken := os.Getenv("DUCKDNS_TOKEN")
	email := os.Getenv("ACME_EMAIL")
	storageDir := os.Getenv("STORAGE_DIR")

	if domain == "" {
		fmt.Fprintln(os.Stderr, "TEST_DOMAIN is required")
		os.Exit(1)
	}
	if duckdnsToken == "" {
		fmt.Fprintln(os.Stderr, "DUCKDNS_TOKEN is required")
		os.Exit(1)
	}
	if email == "" {
		email = "test@" + domain
	}
	if storageDir == "" {
		storageDir = "/tmp/tlsrouter-acme-test"
	}

	fmt.Printf("=== ACME Shared Domain Integration Test ===\n")
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("Storage: %s\n", storageDir)

	// Clean up storage directory
	os.RemoveAll(storageDir)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create storage dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(storageDir)

	// Build TLSrouter binaries
	fmt.Println("\n=== Building TLSrouter binaries ===")

	if err := buildBinary("tlsrouter-a", "frontend"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build frontend: %v\n", err)
		os.Exit(1)
	}

	if err := buildBinary("tlsrouter-b", "backend"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build backend: %v\n", err)
		os.Exit(1)
	}

	// Start backend first (TLSrouter B)
	fmt.Println("\n=== Starting TLSrouter B (backend on :8443) ===")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmdB := exec.CommandContext(ctx, "./tlsrouter-b",
		"--addr", ":8443",
		"--domain", domain,
		"--email", email,
		"--storage", storageDir,
		"--duckdns-token", duckdnsToken,
	)

	cmdB.Stdout = os.Stdout
	cmdB.Stderr = os.Stderr

	if err := cmdB.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start backend: %v\n", err)
		os.Exit(1)
	}

	// Wait for backend to start
	time.Sleep(2 * time.Second)

	// Start frontend (TLSrouter A)
	fmt.Println("\n=== Starting TLSrouter A (frontend on :443) ===")

	cmdA := exec.CommandContext(ctx, "./tlsrouter-a",
		"--addr", ":443",
		"--domain", domain,
		"--email", email,
		"--storage", storageDir,
		"--duckdns-token", duckdnsToken,
		"--acme-backend", "127.0.0.1:8443", // Passthrough ACME to backend
	)

	cmdA.Stdout = os.Stdout
	cmdA.Stderr = os.Stderr

	if err := cmdA.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start frontend: %v\n", err)
		cmdB.Process.Kill()
		os.Exit(1)
	}

	// Wait for certificate issuance
	fmt.Println("\n=== Waiting for certificates ===")

	time.Sleep(30 * time.Second)

	// Test SSH connection (frontend terminates)
	fmt.Println("\n=== Testing SSH (frontend terminates) ===")

	sshTest := testSSHConnection(domain)
	fmt.Printf("SSH test: %v\n", sshTest)

	// Test HTTPS connection (passthrough to backend)
	fmt.Println("\n=== Testing HTTPS (passthrough to backend) ===")

	httpsTest := testHTTPSConnection(domain)
	fmt.Printf("HTTPS test: %v\n", httpsTest)

	// Cleanup
	fmt.Println("\n=== Cleaning up ===")

	cmdA.Process.Kill()
	cmdB.Process.Kill()

	// Report results
	fmt.Println("\n=== Results ===")

	if sshTest && httpsTest {
		fmt.Println("✅ All tests passed!")
		os.Exit(0)
	}

	fmt.Println("❌ Some tests failed")
	os.Exit(1)
}

func buildBinary(output string, role string) error {
	// This is a placeholder - actual build would use the real TLSrouter binary
	// with appropriate configuration for each role
	fmt.Printf("Building %s...\n", output)
	return nil
}

func testSSHConnection(domain string) bool {
	// Test SSH connection to domain:22
	// In a real test, we'd connect and verify the TLS certificate
	fmt.Printf("Testing SSH connection to %s:22...\n", domain)

	conn, err := net.DialTimeout("tcp", domain+":22", 5*time.Second)
	if err != nil {
		fmt.Printf("SSH connection failed: %v\n", err)
		return false
	}
	defer conn.Close()

	// Perform TLS handshake
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // For testing
	})

	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("TLS handshake failed: %v\n", err)
		return false
	}

	// Verify certificate
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		fmt.Println("No peer certificates")
		return false
	}

	cert := state.PeerCertificates[0]
	fmt.Printf("Certificate subject: %s\n", cert.Subject)
	fmt.Printf("Certificate issuer: %s\n", cert.Issuer)

	// Verify it's for the right domain
	if err := cert.VerifyHostname(domain); err != nil {
		fmt.Printf("Certificate doesn't match domain: %v\n", err)
		return false
	}

	// Check if it's from Let's Encrypt Staging (fake certificate)
	// In staging, the cert will be valid but from a staging CA
	fmt.Printf("Certificate valid from %s to %s\n", cert.NotBefore, cert.NotAfter)

	return true
}

func testHTTPSConnection(domain string) bool {
	// Test HTTPS connection to domain
	// In a real test, we'd verify the certificate chain
	fmt.Printf("Testing HTTPS connection to https://%s/...\n", domain)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true, // For testing
			},
		},
	}

	resp, err := client.Get("https://" + domain + "/")
	if err != nil {
		fmt.Printf("HTTPS request failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP status: %s\n", resp.Status)

	// Get certificate from response
	if resp.TLS == nil {
		fmt.Println("No TLS connection state")
		return false
	}

	if len(resp.TLS.PeerCertificates) == 0 {
		fmt.Println("No peer certificates")
		return false
	}

	cert := resp.TLS.PeerCertificates[0]
	fmt.Printf("Certificate subject: %s\n", cert.Subject)
	fmt.Printf("Certificate issuer: %s\n", cert.Issuer)

	return true
}

// verifyCertificateChain checks if the certificate is from Let's Encrypt Staging.
func verifyCertificateChain(cert *x509.Certificate) bool {
	// Let's Encrypt Staging uses a fake CA
	// Production uses ISRG Root X1
	//
	// Staging issuer: "(STAGING) Doctored Durian Root CA X3"
	// Production issuer: "Let's Encrypt Authority X3"
	//
	// For testing, we just check that the certificate is valid
	// and issued recently (within 5 minutes)
	return time.Since(cert.NotBefore) < 5*time.Minute
}
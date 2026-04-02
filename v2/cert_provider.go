package tlsrouter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// MockCertProvider provides self-signed certificates for testing.
// For production, use CertmagicCertProvider with real ACME.
type MockCertProvider struct {
	certs map[string]*tls.Certificate
	mu    sync.RWMutex
}

// NewMockCertProvider creates a new mock certificate provider.
func NewMockCertProvider() *MockCertProvider {
	return &MockCertProvider{
		certs: make(map[string]*tls.Certificate),
	}
}

// GetCertificate returns a self-signed certificate for the domain.
// If one doesn't exist, it creates one on the fly.
func (m *MockCertProvider) GetCertificate(domain string) (Certificate, error) {
	m.mu.RLock()
	cert, exists := m.certs[domain]
	m.mu.RUnlock()

	if exists {
		return Certificate{
			Certificate: cert.Certificate,
			PrivateKey:  cert.PrivateKey,
			Leaf:        cert.Leaf,
		}, nil
	}

	// Generate a new self-signed certificate
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring lock
	if cert, exists := m.certs[domain]; exists {
		return Certificate{
			Certificate: cert.Certificate,
			PrivateKey:  cert.PrivateKey,
			Leaf:        cert.Leaf,
		}, nil
	}

	tlsCert, err := m.generateSelfSigned(domain)
	if err != nil {
		return Certificate{}, err
	}

	m.certs[domain] = tlsCert

	return Certificate{
		Certificate: tlsCert.Certificate,
		PrivateKey:  tlsCert.PrivateKey,
		Leaf:        tlsCert.Leaf,
	}, nil
}

// generateSelfSigned creates a self-signed certificate for testing.
func (m *MockCertProvider) generateSelfSigned(domain string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"tlsrouter mock"},
			CommonName:   domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        &x509.Certificate{},
	}

	cert.Leaf, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// PEMCertificate returns a PEM-encoded certificate for the domain.
// Useful for debugging.
func (m *MockCertProvider) PEMCertificate(domain string) (string, error) {
	m.mu.RLock()
	cert, exists := m.certs[domain]
	m.mu.RUnlock()

	if !exists || len(cert.Certificate) == 0 {
		return "", nil
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	}

	return string(pem.EncodeToMemory(block)), nil
}

// StaticCertProvider provides certificates from a static map.
// Useful when you have pre-generated certificates.
type StaticCertProvider struct {
	certs map[string]Certificate
}

// NewStaticCertProvider creates a new static certificate provider.
func NewStaticCertProvider(certs map[string]Certificate) *StaticCertProvider {
	return &StaticCertProvider{
		certs: certs,
	}
}

// GetCertificate returns a certificate for the domain.
func (s *StaticCertProvider) GetCertificate(domain string) (Certificate, error) {
	cert, ok := s.certs[domain]
	if !ok {
		return Certificate{}, ErrNoCertificate{Domain: domain}
	}
	return cert, nil
}

// ErrNoCertificate is returned when no certificate is available.
type ErrNoCertificate struct {
	Domain string
}

func (e ErrNoCertificate) Error() string {
	return fmt.Sprintf("no certificate available for domain %q", e.Domain)
}
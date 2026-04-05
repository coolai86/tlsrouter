// Package tlsrouter provides TLS reverse proxy routing based on SNI and ALPN.
package tlsrouter

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// RouteAction tells the handler what to do with a connection.
type RouteAction int

const (
	// ActionNone means no action was set (deny by default).
	// This is the zero value for safety - uninitialized structs deny access.
	ActionNone RouteAction = iota
	// ActionTerminate means TLS should be terminated and traffic proxied as HTTP.
	ActionTerminate
	// ActionPassthrough means raw TCP should be tunneled to backend.
	ActionPassthrough
)

// Decision is the routing decision made by a Router.
type Decision struct {
	Action  RouteAction
	Backend string // "host:port" to proxy/tunnel to
	Domain  string // SNI from ClientHello (for logging/certs)
	ALPN    string // Selected ALPN protocol
	// PROXYProto enables PROXY protocol header for backend connections.
	// 1 = PROXY protocol v1 (text), 2 = PROXY protocol v2 (binary)
	// 0 = disabled (default)
	PROXYProto int
}

// ErrPassthrough is returned by GetConfigForClient when routing decides
// to pass through raw TLS traffic without termination.
var ErrPassthrough = errors.New("passthrough")

// Router decides where traffic should go based on SNI and ALPN.
type Router interface {
	// Route returns a routing decision for the given SNI and ALPN list.
	// Returns ErrPassthrough if the connection should be tunneled raw.
	// Returns an error if no route matches.
	Route(sni string, alpns []string) (Decision, error)
}

// ContextDialer creates backend connections with context support.
type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer creates backend connections.
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// CertProvider provides TLS certificates for domains.
type CertProvider interface {
	// GetCertificate returns a certificate for the given domain.
	// Returns an error if no certificate is available.
	GetCertificate(domain string) (Certificate, error)
}

// Certificate wraps tls.Certificate for interface flexibility.
type Certificate struct {
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey
	Leaf        *x509.Certificate
}

// TLSCertificate converts to tls.Certificate for use with crypto/tls.
func (c Certificate) TLSCertificate() (tls.Certificate, error) {
	cert := tls.Certificate{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		Leaf:        c.Leaf,
	}

	// Parse certificates if Leaf is nil
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		var err error
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	return cert, nil
}

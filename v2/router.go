// Package tlsrouter provides TLS reverse proxy routing based on SNI and ALPN.
package tlsrouter

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
)

// RouteAction tells the handler what to do with a connection.
type RouteAction int

const (
	// ActionTerminate means TLS should be terminated and traffic proxied as HTTP.
	ActionTerminate RouteAction = iota
	// ActionPassthrough means raw TCP should be tunneled to backend.
	ActionPassthrough
)

// Decision is the routing decision made by a Router.
type Decision struct {
	Action  RouteAction
	Backend string // "host:port" to proxy/tunnel to
	Domain  string // SNI from ClientHello (for logging/certs)
	ALPN    string // Selected ALPN protocol
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
	PrivateKey  any
	Leaf        *x509.Certificate
}
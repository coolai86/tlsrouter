package tlsrouter

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Handler handles incoming TLS connections and routes them.
type Handler struct {
	Router Router
	Certs  CertProvider
	Dialer Dialer

	// Optional: TLS config defaults
	TLSConfig *tls.Config

	// Optional: Logger
	Logger Logger
}

// Logger is a simple logging interface.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// Handle handles a single connection.
// It performs TLS handshake with routing and then proxies traffic.
func (h *Handler) Handle(conn net.Conn) error {
	defer conn.Close()

	// Track bytes read for passthrough
	tracking := newTrackingConn(conn)

	// The decision from GetConfigForClient
	var decision Decision
	var decisionErr error

	// TLS server with routing callback
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Make routing decision
			decision, decisionErr = h.Router.Route(hello.ServerName, hello.SupportedProtos)
			if decisionErr != nil {
				return nil, decisionErr
			}

			// Store domain for later use
			decision.Domain = hello.ServerName

			// Handle passthrough
			if decision.Action == ActionPassthrough {
				return nil, ErrPassthrough
			}

			// Return TLS config for termination
			cert, err := h.Certs.GetCertificate(decision.Domain)
			if err != nil {
				return nil, err
			}

			return &tls.Config{
				Certificates: []tls.Certificate{{
					Certificate: cert.Certificate,
					PrivateKey:  cert.PrivateKey,
				}},
				NextProtos: []string{decision.ALPN},
			}, nil
		},
	}

	if h.TLSConfig != nil {
		tlsConfig = h.TLSConfig.Clone()
		// Preserve the GetConfigForClient callback
		baseGetConfig := tlsConfig.GetConfigForClient
		tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if baseGetConfig != nil {
				if cfg, err := baseGetConfig(hello); err != nil || cfg != nil {
					return cfg, err
				}
			}
			// Default routing callback
			decision, decisionErr = h.Router.Route(hello.ServerName, hello.SupportedProtos)
			if decisionErr != nil {
				return nil, decisionErr
			}
			decision.Domain = hello.ServerName
			if decision.Action == ActionPassthrough {
				return nil, ErrPassthrough
			}
			cert, err := h.Certs.GetCertificate(decision.Domain)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{{
					Certificate: cert.Certificate,
					PrivateKey:  cert.PrivateKey,
				}},
				NextProtos: []string{decision.ALPN},
			}, nil
		}
	}

	tlsConn := tls.Server(tracking, tlsConfig)

	// Handshake
	err := tlsConn.Handshake()
	if err != nil {
		if err == ErrPassthrough {
			// Tunnel raw TCP
			return h.tunnelTCP(tracking, decision.Backend)
		}
		h.logError("handshake failed", "error", err, "domain", decision.Domain)
		return err
	}

	// Proxy HTTP (terminated)
	return h.proxyHTTP(tlsConn, decision.Backend)
}

func (h *Handler) tunnelTCP(tracking *trackingConn, backend string) error {
	// Dial backend
	beConn, err := h.dial(backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", backend)
		return err
	}
	defer beConn.Close()

	// Copy peeked bytes first
	if tracking.peeked != nil && len(tracking.peeked) > 0 {
		if _, err := beConn.Write(tracking.peeked); err != nil {
			return err
		}
	}

	// Bidirectional copy
	return h.copyBidirectional(tracking.Conn, beConn)
}

func (h *Handler) proxyHTTP(tlsConn *tls.Conn, backend string) error {
	// Dial backend
	beConn, err := h.dial(backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", backend)
		return err
	}
	defer beConn.Close()

	// For terminated TLS, we proxy the plaintext HTTP
	// This is a simple TCP tunnel - HTTP parsing would be done by an HTTP proxy
	return h.copyBidirectional(tlsConn, beConn)
}

func (h *Handler) dial(addr string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer.Dial("tcp", addr)
	}
	return net.Dial("tcp", addr)
}

func (h *Handler) copyBidirectional(a, b net.Conn) error {
	var wg sync.WaitGroup
	var errA2B, errB2A error

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errA2B = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, errB2A = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()

	if errA2B != nil {
		return errA2B
	}
	return errB2A
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func (h *Handler) logError(msg string, args ...any) {
	if h.Logger != nil {
		h.Logger.Error(msg, args...)
	}
}

// trackingConn wraps a net.Conn to track bytes read.
// It also stores peeked bytes from the TLS handshake.
type trackingConn struct {
	net.Conn
	peeked   []byte
	read     atomic.Int64
	written  atomic.Int64
}

func newTrackingConn(conn net.Conn) *trackingConn {
	return &trackingConn{Conn: conn}
}

func (tc *trackingConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	tc.read.Add(int64(n))
	return n, err
}

func (tc *trackingConn) Write(b []byte) (int, error) {
	n, err := tc.Conn.Write(b)
	tc.written.Add(int64(n))
	return n, err
}

// BytesRead returns total bytes read.
func (tc *trackingConn) BytesRead() int64 {
	return tc.read.Load()
}

// BytesWritten returns total bytes written.
func (tc *trackingConn) BytesWritten() int64 {
	return tc.written.Load()
}
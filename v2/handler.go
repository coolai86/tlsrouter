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

	// Config is the current configuration (atomic)
	// Used for dynamic config access during routing
	config atomic.Value // Stores *Config
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

	// Load current config (used later for certmagic check)
	_ = h.GetConfig()

	// The decision from GetConfigForClient
	var decision Decision
	var decisionErr error
	var certmagicHandledACME bool

	// TLS server with routing callback
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Load latest config
			var currentCfg *Config
			if v := h.config.Load(); v != nil {
				currentCfg = v.(*Config)
			}

			// Check for ACME-TLS/1 challenge with dedicated backend
			for _, alpn := range hello.SupportedProtos {
				if alpn == "acme-tls/1" && currentCfg != nil {
					// Check per-domain ACME backend first
					if backend, ok := currentCfg.ACMEBackends[hello.ServerName]; ok {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: backend,
							Domain:  hello.ServerName,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					// Check global ACME backend
					if currentCfg.ACMEPassthrough != "" {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: currentCfg.ACMEPassthrough,
							Domain:  hello.ServerName,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}
				}
			}

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

			// Check if we have certmagic - it handles ACME automatically
			if cmp, ok := h.Certs.(*CertmagicCertProvider); ok {
				if cmp.IsManaged(hello.ServerName) {
					// Use certmagic's GetCertificate directly
					// It will automatically handle ACME-TLS/1 challenges
					return &tls.Config{
						GetCertificate: cmp.GetMagic().GetCertificate,
						NextProtos:     []string{decision.ALPN},
					}, nil
				}
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
		baseGetConfig := tlsConfig.GetConfigForClient
		tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if baseGetConfig != nil {
				if cfg, err := baseGetConfig(hello); err != nil || cfg != nil {
					return cfg, err
				}
			}

			// Load latest config
			var currentCfg *Config
			if v := h.config.Load(); v != nil {
				currentCfg = v.(*Config)
			}

			// Check for ACME-TLS/1 challenge with dedicated backend
			for _, alpn := range hello.SupportedProtos {
				if alpn == "acme-tls/1" && currentCfg != nil {
					if backend, ok := currentCfg.ACMEBackends[hello.ServerName]; ok {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: backend,
							Domain:  hello.ServerName,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					if currentCfg.ACMEPassthrough != "" {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: currentCfg.ACMEPassthrough,
							Domain:  hello.ServerName,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}
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

			// Check if we have certmagic
			if cmp, ok := h.Certs.(*CertmagicCertProvider); ok {
				if cmp.IsManaged(hello.ServerName) {
					return &tls.Config{
						GetCertificate: cmp.GetMagic().GetCertificate,
						NextProtos:     []string{decision.ALPN},
					}, nil
				}
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

	// Check if certmagic handled ACME challenge
	// This happens when handshake succeeded but no backend was selected
	// (certmagic completed the TLS-ALPN challenge internally)
	if decision.Backend == "" && decision.ALPN == "acme-tls/1" {
		if cmp, ok := h.Certs.(*CertmagicCertProvider); ok {
			if cmp.IsManaged(decision.Domain) {
				h.logInfo("ACME challenge handled by certmagic", "domain", decision.Domain)
				certmagicHandledACME = true
			}
		}
	}

	if certmagicHandledACME {
		// Certmagic handled the challenge, just close cleanly
		return nil
	}

	// Proxy HTTP (terminated)
	return h.proxyHTTP(tlsConn, decision.Backend)
}

func (h *Handler) tunnelTCP(tracking *trackingConn, backend string) error {
	beConn, err := h.dial(backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", backend)
		return err
	}
	defer beConn.Close()

	// Copy peeked bytes first (multiple buffers, like original)
	buffers := tracking.Passthru()
	for _, buf := range buffers {
		if _, err := beConn.Write(buf); err != nil {
			return err
		}
	}

	// Bidirectional copy
	return h.copyBidirectional(tracking.Conn, beConn)
}

func (h *Handler) proxyHTTP(tlsConn *tls.Conn, backend string) error {
	beConn, err := h.dial(backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", backend)
		return err
	}
	defer beConn.Close()

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

func (h *Handler) logInfo(msg string, args ...any) {
	if h.Logger != nil {
		h.Logger.Info(msg, args...)
	}
}

// SetConfig atomically replaces the handler's configuration.
func (h *Handler) SetConfig(cfg *Config) {
	h.config.Store(cfg)
}

// GetConfig returns the current configuration.
func (h *Handler) GetConfig() *Config {
	if v := h.config.Load(); v != nil {
		return v.(*Config)
	}
	return nil
}

// trackingConn wraps a net.Conn to track bytes read.
// It also stores peeked bytes from the TLS handshake.
type trackingConn struct {
	net.Conn
	peeked   [][]byte // Multiple buffers for peeked data (like original)
	mu       sync.Mutex
	read     atomic.Int64
	written  atomic.Int64
}

func newTrackingConn(conn net.Conn) *trackingConn {
	return &trackingConn{Conn: conn}
}

func (tc *trackingConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	tc.read.Add(int64(n))

	// Store peeked data if this is the first read (before tunneling)
	if tc.read.Load() <= int64(n) {
		tc.mu.Lock()
		if len(tc.peeked) == 0 {
			// Store a copy of the peeked data
			peek := make([]byte, n)
			copy(peek, b[:n])
			tc.peeked = append(tc.peeked, peek)
		}
		tc.mu.Unlock()
	}

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

// Passthru returns the peeked bytes for tunneling.
// Matches the original wrappedConn.Passthru() interface.
func (tc *trackingConn) Passthru() [][]byte {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Return a copy of the peeked data
	result := make([][]byte, len(tc.peeked))
	for i, buf := range tc.peeked {
		result[i] = append([]byte{}, buf...)
	}

	return result
}

package tlsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
// ctx is used for cancellation and timeouts throughout the request.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	// Track bytes read for passthrough
	tracking := newTrackingConn(conn)

	// Load current config (used later for certmagic check)
	_ = h.GetConfig()

	// The decision from GetConfigForClient
	var decision Decision
	var decisionErr error
	var certmagicHandledACME bool

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TLS server with routing callback
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Load latest config
			var currentCfg *Config
			if v := h.config.Load(); v != nil {
				currentCfg = v.(*Config)
			}

			// Check for ACME-TLS/1 challenge
			for _, alpn := range hello.SupportedProtos {
				if alpn == "acme-tls/1" && currentCfg != nil {
					domain := hello.ServerName

					// Priority 1: Check if certmagic has an ACTIVE challenge for this domain.
					// This handles the case where both TLSrouter and a passthrough backend
					// (e.g., Caddy) need certs for the same domain. When TLSrouter has an
					// active challenge, it handles it. Otherwise, passthrough to backend.
					if cmp, ok := h.Certs.(*CertmagicCertProvider); ok && cmp.IsManaged(domain) {
						if cmp.HasActiveChallenge(domain) {
							// TLSrouter's certmagic handles this challenge
							// Return a TLS config that will complete the handshake
							// Post-handshake detection will close cleanly
							decision = Decision{
								Action: ActionTerminate,
								Domain: domain,
								ALPN:   "acme-tls/1",
							}
							return &tls.Config{
								GetCertificate: cmp.GetMagic().GetCertificate,
								NextProtos:     []string{"acme-tls/1"},
							}, nil
						}
					}

					// Priority 2: Check per-domain ACME backend (passthrough)
					if backend, ok := currentCfg.ACMEBackends[domain]; ok {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: backend,
							Domain:  domain,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					// Priority 3: Check global ACME backend (passthrough)
					if currentCfg.ACMEPassthrough != "" {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: currentCfg.ACMEPassthrough,
							Domain:  domain,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					// Priority 4: No route - error
					return nil, fmt.Errorf("no ACME route for %q", domain)
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

			// Check for ACME-TLS/1 challenge
			for _, alpn := range hello.SupportedProtos {
				if alpn == "acme-tls/1" && currentCfg != nil {
					domain := hello.ServerName

					// Priority 1: Check if certmagic has an ACTIVE challenge
					if cmp, ok := h.Certs.(*CertmagicCertProvider); ok && cmp.IsManaged(domain) {
						if cmp.HasActiveChallenge(domain) {
							decision = Decision{
								Action: ActionTerminate,
								Domain: domain,
								ALPN:   "acme-tls/1",
							}
							return &tls.Config{
								GetCertificate: cmp.GetMagic().GetCertificate,
								NextProtos:     []string{"acme-tls/1"},
							}, nil
						}
					}

					// Priority 2: Check per-domain ACME backend (passthrough)
					if backend, ok := currentCfg.ACMEBackends[domain]; ok {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: backend,
							Domain:  domain,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					// Priority 3: Check global ACME backend (passthrough)
					if currentCfg.ACMEPassthrough != "" {
						decision = Decision{
							Action:  ActionPassthrough,
							Backend: currentCfg.ACMEPassthrough,
							Domain:  domain,
							ALPN:    "acme-tls/1",
						}
						return nil, ErrPassthrough
					}

					// Priority 4: No route - error
					return nil, fmt.Errorf("no ACME route for %q", domain)
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
			return h.tunnelTCP(ctx, tracking, decision.Backend)
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
	return h.proxyHTTP(ctx, tlsConn, decision.Backend)
}

func (h *Handler) tunnelTCP(ctx context.Context, tracking *trackingConn, backend string) error {
	beConn, err := h.dialContext(ctx, backend)
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

	// Bidirectional copy with context
	return h.copyBidirectionalWithContext(ctx, tracking.Conn, beConn)
}

func (h *Handler) proxyHTTP(ctx context.Context, tlsConn *tls.Conn, backend string) error {
	beConn, err := h.dialContext(ctx, backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", backend)
		return err
	}
	defer beConn.Close()

	return h.copyBidirectionalWithContext(ctx, tlsConn, beConn)
}

func (h *Handler) dial(addr string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer.Dial("tcp", addr)
	}
	return net.Dial("tcp", addr)
}

func (h *Handler) dialContext(ctx context.Context, addr string) (net.Conn, error) {
	if h.Dialer != nil {
		// Try ContextDialer first
		if cd, ok := h.Dialer.(ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		// Fall back to regular Dialer
		return h.Dialer.Dial("tcp", addr)
	}
	return net.DialTimeout("tcp", addr, 30*time.Second)
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

func (h *Handler) copyBidirectionalWithContext(ctx context.Context, a, b net.Conn) error {
	var wg sync.WaitGroup
	var errA2B, errB2A error
	var done = make(chan struct{})

	// Copy a -> b
	wg.Go(func() {
		err := copyWithContext(ctx, a, b)
		if err != nil {
			h.logError("copy a->b error", "error", err)
			errA2B = err
		}
		closeWrite(b)
	})

	// Copy b -> a
	wg.Go(func() {
		err := copyWithContext(ctx, b, a)
		if err != nil {
			h.logError("copy b->a error", "error", err)
			errB2A = err
		}
		closeWrite(a)
	})

	// Wait for completion or context cancellation
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if errA2B != nil {
			return errA2B
		}
		return errB2A
	case <-ctx.Done():
		return ctx.Err()
	}
}

// copyWithContext copies data with context cancellation support.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, err := dst.Write(buf[0:nr])
			if err != nil {
				return err
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
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
	peeked  [][]byte // Multiple buffers for peeked data (like original)
	mu      sync.Mutex
	read    atomic.Int64
	written atomic.Int64
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

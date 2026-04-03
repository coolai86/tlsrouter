package tlsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bnnanet/tlsrouter/v2/proxyproto"
	"github.com/bnnanet/tlsrouter/v2/tun"
	"github.com/google/uuid"
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

	// DialTimeout is the timeout for backend connections.
	// Default: 5 seconds
	DialTimeout time.Duration

	// KeepAliveConfig for backend connections.
	// Default: enabled with 15s idle, 15s interval, 2 probes
	KeepAlive KeepAliveConfig

	// Stats tracks connection statistics.
	// If nil, stats are not tracked.
	Stats *StatsRegistry

	// Listeners tracks listening addresses for loop detection.
	// If nil, loop detection is disabled.
	Listeners *ListenerRegistry
}

// KeepAliveConfig configures TCP keepalive for backend connections.
type KeepAliveConfig struct {
	Enable   bool
	Idle     time.Duration
	Interval time.Duration
	Count    int
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

	// Generate connection ID and start tracking
	connID := uuid.New().String()
	ctx = ContextWithStatsID(ctx, connID)
	if h.Stats != nil {
		h.Stats.TrackConnection(connID, conn.RemoteAddr(), conn.LocalAddr())
	}

	// Track bytes read for passthrough
	tracking := newTrackingConn(conn)
	tracking.statsID = connID
	tracking.stats = h.Stats

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

	// Build base TLS config with MinVersion
	baseTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // SECURITY: Require TLS 1.2+
	}
	if h.TLSConfig != nil {
		baseTLSConfig = h.TLSConfig.Clone()
		if baseTLSConfig.MinVersion < tls.VersionTLS12 || baseTLSConfig.MinVersion == 0 {
			baseTLSConfig.MinVersion = tls.VersionTLS12
		}
	}

	// TLS server with routing callback
	tlsConfig := &tls.Config{
		MinVersion: baseTLSConfig.MinVersion,
		MaxVersion: baseTLSConfig.MaxVersion,
		CipherSuites: baseTLSConfig.CipherSuites,
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
								MinVersion:    tls.VersionTLS12,
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
						MinVersion:    tls.VersionTLS12,
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
				MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{{
					Certificate: cert.Certificate,
					PrivateKey:  cert.PrivateKey,
				}},
				NextProtos: []string{decision.ALPN},
			}, nil
		},
	}

	tlsConn := tls.Server(tracking, tlsConfig)

	// Handshake
	err := tlsConn.Handshake()
	if err != nil {
		if err == ErrPassthrough {
			// Tunnel raw TCP
			// Record stats for passthrough
			if h.Stats != nil {
				routeType := RouteTypeStatic
				if decision.Backend != "" {
					// Check if it's ACME passthrough
					for _, alpn := range []string{"acme-tls/1"} {
						if decision.ALPN == alpn {
							routeType = RouteTypeACMEPassthrough
							break
						}
					}
				}
				h.Stats.SetRouteInfo(connID, decision, routeType, false, decision.Backend, 0, 0)
			}
			return h.tunnelTCP(ctx, tracking, decision)
		}
		h.logError("handshake failed", "error", err, "domain", decision.Domain)
		// Record error close
		if h.Stats != nil {
			h.Stats.CloseConnection(connID, CloseReasonError)
		}
		return err
	}

	// Get TLS connection state
	tlsState := tlsConn.ConnectionState()

	// Record stats for terminated connection
	if h.Stats != nil && !certmagicHandledACME {
		h.Stats.SetRouteInfo(connID, decision, RouteTypeStatic, true, decision.Backend, tlsState.Version, tlsState.CipherSuite)
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

	// Proxy HTTP (terminated) with proper X-Forwarded headers
	return h.proxyHTTP(ctx, tlsConn, decision)
}

func (h *Handler) tunnelTCP(ctx context.Context, tracking *trackingConn, decision Decision) error {
	// Loop detection: check if backend is one of our listeners
	if h.Listeners != nil {
		if err := h.Listeners.CheckLoop(decision.Backend, "", 0); err != nil {
			h.logError("loop detected", "error", err, "backend", decision.Backend)
			if h.Stats != nil {
				h.Stats.CloseConnection(tracking.statsID, CloseReasonError)
			}
			return err
		}
	}

	start := time.Now()
	beConn, err := h.dialContext(ctx, decision.Backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", decision.Backend)
		// Record backend error
		if h.Stats != nil {
			h.Stats.CloseConnection(tracking.statsID, CloseReasonError)
		}
		return err
	}
	defer beConn.Close()

	// Record backend latency
	if h.Stats != nil {
		h.Stats.SetBackendLatency(tracking.statsID, time.Since(start))
	}

	// Write PROXY protocol header if configured
	if decision.PROXYProto > 0 {
		if err := h.writeProxyProto(beConn, tracking.Conn.RemoteAddr(), decision.PROXYProto); err != nil {
			h.logError("PROXY protocol write failed", "error", err)
			return err
		}
	}

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

// proxyHTTP proxies a terminated TLS connection to an HTTP backend.
// For HTTP ALPNs, this uses httputil.ReverseProxy with proper X-Forwarded headers.
func (h *Handler) proxyHTTP(ctx context.Context, tlsConn *tls.Conn, decision Decision) error {
	// Loop detection: check if backend is one of our listeners
	if h.Listeners != nil {
		if err := h.Listeners.CheckLoop(decision.Backend, "", 0); err != nil {
			h.logError("loop detected", "error", err, "backend", decision.Backend)
			return err
		}
	}

	// For HTTP ALPNs, use proper HTTP proxy with X-Forwarded headers
	if decision.ALPN == "http/1.1" || decision.ALPN == "h2" || decision.ALPN == "h2c" {
		return h.proxyHTTPWithForwardedHeaders(ctx, tlsConn, decision)
	}

	// For non-HTTP ALPNs, use direct TCP proxy
	start := time.Now()
	beConn, err := h.dialContext(ctx, decision.Backend)
	if err != nil {
		h.logError("backend dial failed", "error", err, "backend", decision.Backend)
		return err
	}
	defer beConn.Close()

	// Record backend latency
	if h.Stats != nil && ctx.Value(StatsContextKey{}) != nil {
		connID := ctx.Value(StatsContextKey{}).(string)
		h.Stats.SetBackendLatency(connID, time.Since(start))
	}

	// Write PROXY protocol header if configured
	if decision.PROXYProto > 0 {
		if err := h.writeProxyProto(beConn, tlsConn.RemoteAddr(), decision.PROXYProto); err != nil {
			h.logError("PROXY protocol write failed", "error", err)
			return err
		}
	}

	return h.copyBidirectionalWithContext(ctx, tlsConn, beConn)
}

// proxyHTTPWithForwardedHeaders uses httputil.ReverseProxy to properly handle
// X-Forwarded-* headers for HTTP traffic.
func (h *Handler) proxyHTTPWithForwardedHeaders(ctx context.Context, tlsConn *tls.Conn, decision Decision) error {
	// Create a tunnel listener that accepts the injected connection
	ln := tun.NewListener(ctx)

	// Create the reverse proxy
	backendURL, err := url.Parse(fmt.Sprintf("http://%s", decision.Backend))
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendURL)
			r.Out.Host = r.In.Host

			// Set X-Forwarded headers
			r.SetXForwarded()

			// Add X-Forwarded-Proto header
			r.Out.Header.Set("X-Forwarded-Proto", "https")

			// Add X-Forwarded-SNI for backend to know which certificate was used
			if decision.Domain != "" {
				r.Out.Header.Set("X-Forwarded-SNI", decision.Domain)
			}

			// Add X-Forwarded-ALPN for backend to know negotiated protocol
			if decision.ALPN != "" {
				r.Out.Header.Set("X-Forwarded-ALPN", decision.ALPN)
			}

			// Add loop detection headers
			if h.Listeners != nil {
				// Parse incoming hop info
				incoming := ParseHopInfo(r.In.Header)
				// Check for loop before proxying
				if err := h.Listeners.CheckLoop(decision.Backend, incoming.ID, incoming.Hops); err != nil {
					h.logError("loop detected in HTTP proxy", "error", err, "backend", decision.Backend)
					// The error will be handled by ErrorHandler
					r.Out.Header.Set(HeaderTLSrouterID, "loop-detected")
					return
				}
				// Add hop headers
				r.Out.Header.Set(HeaderTLSrouterID, string(h.Listeners.InstanceID()))
				hops := incoming.Hops + 1
				r.Out.Header.Set(HeaderTLSrouterHops, intToStr(hops))
				// Propagate Via chain
				via := incoming.Via
				via = append(via, h.Listeners.InstanceID())
				viaStr := ""
				for i, id := range via {
					if i > 0 {
						viaStr += ","
					}
					viaStr += string(id)
				}
				r.Out.Header.Set(HeaderTLSrouterVia, viaStr)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logError("proxy error", "error", err, "backend", decision.Backend)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Create HTTP server with appropriate timeouts
	httpServer := &http.Server{
		Handler:           proxy,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start HTTP server in background, serving from the tunnel listener
	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Inject the TLS connection into the tunnel listener
	if err := ln.Inject(tlsConn); err != nil {
		httpServer.Close()
		return fmt.Errorf("inject connection: %w", err)
	}

	// Wait for either completion or context cancellation
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	}
}

// writeProxyProto writes a PROXY protocol header to the connection.
func (h *Handler) writeProxyProto(conn net.Conn, srcAddr net.Addr, version int) error {
	var v proxyproto.Version
	switch version {
	case 1:
		v = proxyproto.V1
	case 2:
		v = proxyproto.V2
	default:
		return fmt.Errorf("unsupported PROXY protocol version: %d", version)
	}

	header, err := proxyproto.NewHeader(v, srcAddr, conn.LocalAddr(), proxyproto.TCPv4)
	if err != nil {
		return err
	}

	_, err = header.WriteTo(conn)
	return err
}

func (h *Handler) dial(addr string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer.Dial("tcp", addr)
	}
	return net.Dial("tcp", addr)
}

// dialContext creates a backend connection with proper timeouts and keepalive.
func (h *Handler) dialContext(ctx context.Context, addr string) (net.Conn, error) {
	if h.Dialer != nil {
		// Try ContextDialer first
		if cd, ok := h.Dialer.(ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		// Fall back to regular Dialer
		return h.Dialer.Dial("tcp", addr)
	}

	// Default: Use proper Dialer with timeout and keepalive
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	keepAlive := h.KeepAlive
	if keepAlive.Idle <= 0 {
		keepAlive = KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 15 * time.Second,
			Count:    2,
		}
	}

	d := net.Dialer{
		Timeout:       timeout,
		FallbackDelay: 300 * time.Millisecond,
		KeepAlive:     keepAlive.Idle,
	}

	if keepAlive.Enable {
		d.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepAlive.Idle,
			Interval: keepAlive.Interval,
			Count:    keepAlive.Count,
		}
	}

	return d.DialContext(ctx, "tcp", addr)
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

	// Stats tracking
	statsID string        // Connection ID in stats registry
	stats   *StatsRegistry // Stats registry (may be nil)
}

func newTrackingConn(conn net.Conn) *trackingConn {
	return &trackingConn{Conn: conn}
}

func (tc *trackingConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	tc.read.Add(int64(n))

	// Update stats
	if tc.stats != nil && tc.statsID != "" {
		tc.stats.UpdateBytes(tc.statsID, int64(n), 0, 0, 0)
	}

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

	// Update stats
	if tc.stats != nil && tc.statsID != "" {
		tc.stats.UpdateBytes(tc.statsID, 0, int64(n), 0, 0)
	}

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
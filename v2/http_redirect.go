package tlsrouter

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPRedirectServer handles HTTP (port 80) requests.
// Primary use: redirect to HTTPS, with optional ACME HTTP-01 challenge support.
type HTTPRedirectServer struct {
	// Addr is the address to listen on (e.g., ":80")
	Addr string

	// HTTPSAddr is the HTTPS address to redirect to (e.g., ":443")
	// If empty, uses the same hostname with HTTPS
	HTTPSAddr string

	// ACMEHandler is called for ACME HTTP-01 challenge paths.
	// If nil, all requests are redirected to HTTPS.
	// Path format: /.well-known/acme-challenge/{token}
	// Should return the key authorization or "" to fall through to redirect.
	ACMEHandler func(token string) string

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. Default: 5s
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. Default: 5s
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. Default: 60s
	IdleTimeout time.Duration

	listener net.Listener
	server   *http.Server
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewHTTPRedirectServer creates a new HTTP redirect server.
func NewHTTPRedirectServer(addr string) *HTTPRedirectServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &HTTPRedirectServer{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// WithHTTPSAddr sets the HTTPS address for redirects.
func (s *HTTPRedirectServer) WithHTTPSAddr(addr string) *HTTPRedirectServer {
	s.HTTPSAddr = addr
	return s
}

// WithACMEHandler sets the ACME HTTP-01 challenge handler.
func (s *HTTPRedirectServer) WithACMEHandler(handler func(token string) string) *HTTPRedirectServer {
	s.ACMEHandler = handler
	return s
}

// ListenAndServe starts the HTTP server.
func (s *HTTPRedirectServer) ListenAndServe() error {
	var err error
	s.listener, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	// ACME HTTP-01 challenge path
	if s.ACMEHandler != nil {
		mux.HandleFunc("/.well-known/acme-challenge/", s.handleACME)
	}

	// Redirect everything else to HTTPS
	mux.HandleFunc("/", s.handleRedirect)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  s.ReadTimeout,
		WriteTimeout: s.WriteTimeout,
		IdleTimeout:  s.IdleTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return s.ctx
		},
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.server.Serve(s.listener)
	}()

	return nil
}

// handleACME handles ACME HTTP-01 challenge requests.
func (s *HTTPRedirectServer) handleACME(w http.ResponseWriter, r *http.Request) {
	// Extract token from path
	path := r.URL.Path
	if !strings.HasPrefix(path, "/.well-known/acme-challenge/") {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	token := strings.TrimPrefix(path, "/.well-known/acme-challenge/")
	if token == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Call the handler
	if s.ACMEHandler == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	keyAuth := s.ACMEHandler(token)
	if keyAuth == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Return the key authorization
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(keyAuth))
}

// handleRedirect redirects HTTP requests to HTTPS.
func (s *HTTPRedirectServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Build HTTPS URL
	httpsAddr := s.HTTPSAddr
	if httpsAddr == "" {
		httpsAddr = ":443"
	}

	// Add port if non-standard
	if httpsAddr != ":443" {
		host = host + httpsAddr
	}

	httpsURL := "https://" + host + r.URL.RequestURI()

	// Permanent redirect
	http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
}

// Shutdown gracefully shuts down the HTTP server.
func (s *HTTPRedirectServer) Shutdown(ctx context.Context) error {
	s.cancel()

	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close immediately closes the server.
func (s *HTTPRedirectServer) Close() error {
	s.cancel()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
package tlsrouter

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// Server is a TLS routing server.
type Server struct {
	Handler   *Handler
	Addr      string
	Listeners *ListenerRegistry // Loop detection

	listener net.Listener
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewServer creates a new TLS routing server.
func NewServer(addr string, handler *Handler) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		Handler: handler,
		Addr:    addr,
		ctx:     ctx,
		cancel:  cancel,
	}
	// Create listener registry if handler doesn't have one
	if handler.Listeners == nil {
		handler.Listeners = NewListenerRegistry()
	}
	s.Listeners = handler.Listeners
	return s
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	var err error
	s.listener, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer s.listener.Close()

	// Register this listener for loop detection
	actualAddr := s.listener.Addr().String()
	s.Listeners.Register(actualAddr)

	log.Printf("tlsrouter listening on %s (instance: %s)", actualAddr, s.Listeners.InstanceID())

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // shutdown
			default:
				return err
			}
		}

		s.wg.Go(func() {

			// Create a per-connection context from server context
			// Each connection gets a 5-minute timeout
			connCtx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
			defer cancel()

			if err := s.Handler.Handle(connCtx, conn); err != nil {
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) && !IsLoopError(err) {
					log.Printf("connection error: %v", err)
				}
			}
		})
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	if s.listener != nil {
		// Unregister listener
		if s.Listeners != nil && s.listener != nil {
			s.Listeners.Unregister(s.listener.Addr().String())
		}
		_ = s.listener.Close()
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

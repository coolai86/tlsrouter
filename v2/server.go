package tlsrouter

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
)

// Server is a TLS routing server.
type Server struct {
	Handler *Handler
	Addr    string

	listener net.Listener
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewServer creates a new TLS routing server.
func NewServer(addr string, handler *Handler) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		Handler: handler,
		Addr:    addr,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	var err error
	s.listener, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer s.listener.Close()

	log.Printf("tlsrouter listening on %s", s.Addr)

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

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.Handler.Handle(conn); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("connection error: %v", err)
				}
			}
		}()
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	if s.listener != nil {
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
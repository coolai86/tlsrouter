// Package tun provides a faux net.Listener that accepts injected connections.
// This enables building HTTP proxies where connections are "offered" to a
// standard library HTTP server via httputil.ReverseProxy.
package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// ErrListenerClosed is returned when operations are performed on a closed Listener.
var ErrListenerClosed = fmt.Errorf("tun: listener closed: %w", net.ErrClosed)

// InjectListener is a net.Listener that can have connections injected into it.
type InjectListener interface {
	net.Listener
	// Inject inserts a connection into the listener's accept queue.
	// It blocks until the connection is Accept()ed or the listener is closed.
	Inject(conn net.Conn) error
}

// Listener implements net.Listener, accepting connections fed in via Inject.
type Listener struct {
	conns     chan net.Conn
	ctx       context.Context
	ctxCancel context.CancelFunc
	closed    atomic.Bool
}

// NewListener creates a new injectable listener bound to the given context.
func NewListener(ctx context.Context) InjectListener {
	ctx, cancel := context.WithCancel(ctx)
	return &Listener{
		conns:     make(chan net.Conn, 1), // Buffer of 1 to allow one pending connection
		ctx:       ctx,
		ctxCancel: cancel,
	}
}

// Inject receives a connection and blocks until it is Accept()ed.
func (ln *Listener) Inject(conn net.Conn) error {
	if ln.closed.Load() {
		return ErrListenerClosed
	}

	select {
	case <-ln.ctx.Done():
		return ErrListenerClosed
	case ln.conns <- conn:
		return nil
	}
}

// Accept blocks and waits for a new net.Conn injected via Offer.
func (ln *Listener) Accept() (net.Conn, error) {
	select {
	case <-ln.ctx.Done():
		return nil, ErrListenerClosed
	case conn, ok := <-ln.conns:
		if !ok {
			return nil, io.EOF
		}
		return conn, nil
	}
}

// Close closes the listener.
func (ln *Listener) Close() error {
	prevClosed := ln.closed.Swap(true)
	if !prevClosed {
		ln.ctxCancel()
		close(ln.conns)
	}
	return nil
}

// Addr returns a dummy address to satisfy the net.Listener interface.
func (ln *Listener) Addr() net.Addr {
	return dummyAddr{}
}

// dummyAddr is a minimal net.Addr implementation.
type dummyAddr struct{}

func (d dummyAddr) Network() string { return "tun" }
func (d dummyAddr) String() string  { return "tun:inject-listener" }

var (
	_ InjectListener = (*Listener)(nil)
)
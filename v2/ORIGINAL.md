# Original tlsrouter.go Analysis

**Source:** `/root/dev/projects/tlsrouter/main/tlsrouter.go`
**Purpose:** Document patterns from the original implementation for v2 reference

---

## TLS Security Handling

### TLS Config Creation

The original creates TLS configs dynamically in `GetConfigForClient`:

```go
tlsConn := tls.Server(wconn, &tls.Config{
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        // Dynamic routing logic
        return &tls.Config{
            GetCertificate: magic.GetCertificate,
            NextProtos:     []string{snialpn.ALPN()},
        }, nil
    },
})
```

**Key observations:**
- **No explicit MinVersion** - Relies on Go's defaults (TLS 1.2+ since Go 1.18)
- **Dynamic NextProtos** - Set based on routing decision
- **CertMagic integration** - Uses `magic.GetCertificate` for ACME

**v2 Gap:** v2's `handler.go` also doesn't set `MinVersion`. Should add:
```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,  // Add this
    GetConfigForClient: ...
}
```

---

## HTTP Reverse Proxy (Tunnel Pattern)

### Internal Tunnel Listener

The original uses a clever pattern for HTTP backends:

```go
// In Backend struct
type Backend struct {
    HTTPTunnel    tun.InjectListener `json:"-"`
    // ...
}

// During config setup
backend.HTTPTunnel = tun.NewListener(lc.Context)

// Create ReverseProxy targeting the tunnel
proxy := &httputil.ReverseProxy{
    Rewrite: func(r *httputil.ProxyRequest) {
        r.SetURL(target)
        r.Out.Host = r.In.Host
        r.SetXForwarded()
        r.Out.Header["X-Forwarded-Proto"] = []string{"https"}
    },
}

// Start HTTP server on the tunnel
proxyServer := &http.Server{
    Handler: proxy,
    Protocols: protocols,
}
go proxyServer.Serve(backend.HTTPTunnel)
```

### The Injection Flow

```
Client → TLSrouter:443
       → TLS handshake (terminated)
       → backend.HTTPTunnel.Inject(plainConn)  // Inject decrypted connection
       → httputil.ReverseProxy handles it
       → Backend:3080 (or other terminate port)
```

**Key files:**
- `net/tun/tun.go` - The `InjectListener` implementation

**v2 Gap:** v2 doesn't have HTTP tunnel/ReverseProxy support yet. The `handler.go` only does:
- `tunnelTCP()` - Raw TCP passthrough
- `proxyHTTP()` - Direct connection to backend (no ReverseProxy)

---

## PROXY Protocol Support

### Header Creation

```go
if backend.PROXYProto == 1 || backend.PROXYProto == 2 {
    header := &proxyproto.Header{
        Version:           byte(backend.PROXYProto),
        Command:           proxyproto.PROXY,
        TransportProtocol: proxyproto.TCPv4,
        SourceAddr:        tlsConn.RemoteAddr().(*net.TCPAddr),
        DestinationAddr:   beConn.LocalAddr().(*net.TCPAddr),
    }
    if _, err := header.WriteTo(beConn); err != nil {
        return ..., err
    }
}
```

**Backend config:**
```go
type Backend struct {
    PROXYProto int `json:"proxy_protocol,omitempty"` // 1 or 2 for v1/v2
}
```

**v2 Gap:** v2 doesn't have PROXY protocol support yet. Need to:
1. Add `PROXYProto` to `StaticRoute` / `Decision`
2. Write header before tunneling data

---

## Connection Tracking

### wrappedConn Pattern

```go
type wrappedConn struct {
    net.Conn
    passthru     bool
    buffers      [][]byte      // Peeked data from TLS handshake
    SNIALPN      SNIALPN        // Routing decision
    PlainConn    *PlainConn     // For terminated connections
    Connected    time.Time
    BytesRead    atomic.Uint64
    BytesWritten atomic.Uint64
    LastRead     atomic.Int64
    LastWrite    atomic.Int64
    wg           sync.WaitGroup
    once         sync.Once
}

func (wconn *wrappedConn) Read(b []byte) (int, error) {
    n, err := wconn.Conn.Read(b)
    wconn.BytesRead.Add(uint64(n))
    wconn.LastRead.Store(time.Now().UnixMilli())

    if !wconn.passthru {
        wconn.buffers = append(wconn.buffers, b[0:n])
    }
    return n, err
}
```

### Connection Registry

```go
type ListenConfig struct {
    Conns sync.Map  // Active connections by ID
    // ...
}

// Store connection
lc.Conns.Store(wconn.ConnID(), wconn)

// List connections (API)
lc.Conns.Range(func(_, v any) bool {
    wconn := v.(*wrappedConn)
    pconn := WConnToPConn(wconn)
    list = append(list, pconn)
    return true
})
```

**v2 Gap:** v2 has `trackingConn` for byte tracking but:
- No connection registry for API listing
- No connection closing API
- No `LastRead`/`LastWrite` timing for idle detection

---

## Backend Connection Dialing

### Original Dialer

```go
d := net.Dialer{
    Timeout:       400 * time.Millisecond,  // Fast fail
    FallbackDelay: 300 * time.Millisecond,
    KeepAliveConfig: net.KeepAliveConfig{
        Enable:   true,
        Idle:     15 * time.Second,
        Interval: 15 * time.Second,
        Count:    2,  // 2 probes, ~30s total
    },
}

return d.DialContext(ctx, "tcp", backendAddr)
```

**Key settings:**
- **400ms timeout** - Very aggressive, fails fast
- **KeepAlive enabled** - 15s idle, 15s interval
- **Context aware** - Uses `DialContext`

**v2 Gap:** v2 uses:
```go
func (h *Handler) dial(addr string) (net.Conn, error) {
    return net.Dial("tcp", addr)  // NO TIMEOUT!
}
```

---

## HTTP/80 Redirect

### Separate listener for HTTP

```go
func ListenAndRedirectPlainHTTP(addr string) error {
    mux := http.NewServeMux()
    mux.HandleFunc("/", HandleHTTPSRedirect)

    srv := &http.Server{
        Addr:         addr,
        Handler:      mux,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 5 * time.Second,
        IdleTimeout:  15 * time.Second,
    }
    return srv.ListenAndServe()
}
```

**v2 Gap:** Not implemented. This is on the TODO list in STATUS.md.

---

## Graceful Shutdown

### Context-based shutdown

```go
func (lc *ListenConfig) Shutdown(ctx context.Context) {
    _ = lc.netLn.Close()
    _ = lc.adminServer.Shutdown(ctx)
    lc.done <- ctx
}

// In ListenAndProxy:
for {
    select {
    case conn := <-ch:
        go lc.proxy(conn)
    case <-lc.Context.Done():
        lc.done <- context.Background()
    case <-lc.done:
        _ = lc.netLn.Close()
        _ = lc.adminServer.Close()
        return net.ErrClosed
    }
}
```

**v2 has this pattern** - `server.go` uses `context.Context` with cancel.

---

## Config Management

### Atomic Config Swaps

```go
type ListenConfig struct {
    config                atomic.Value
    newConfig             atomic.Pointer[Config]
    newMu                 sync.Mutex
    // ...
}

func (lc *ListenConfig) StoreConfig(conf Config) {
    lc.config.Store(conf)
}

func (lc *ListenConfig) LoadConfig() Config {
    return lc.config.Load().(Config)
}
```

**v2 has similar pattern** - Both use `atomic.Value` for lock-free reads.

---

## ACME Challenge Handling

### Three-Way ACME Dispatch

```go
if alpns[0] == acmez.ACMETLS1Protocol {
    // Priority 1: Certmagic has active challenge
    magic := lc.certmagicConfMap[domain]
    if magic == nil {
        lc.slowConfigMu.RLock()
        _, ok := lc.slowCertmagicConfMap[domain]
        if ok {
            magic = lc.certmagicTLSALPNOnly
        } else {
            backend = lc.slowACMETLS1ByDomain[domain]
        }
        lc.slowConfigMu.RUnlock()
        if backend != nil {
            // Passthrough to backend
            beConn, err = getBackendConn(lc.Context, backend.Host)
            return nil, ErrDoNotTerminate
        }
    }
    
    // Priority 2: TLS-ALPN only config
    if magic == lc.certmagicTLSALPNOnly {
        return magic.TLSConfig(), nil
    }
    
    // Priority 3: Fall through to error
}
```

**v2 matches this logic** - See `handler.go` ACME priority chain.

---

## Key Patterns to Port to v2

| Pattern | Original | v2 Status |
|---------|----------|-----------|
| TLS MinVersion | Not set | **Missing** - Add |
| Connection registry | `sync.Map` of wrappedConn | **Missing** - Need for API |
| HTTP tunnel (ReverseProxy) | `tun.InjectListener` | **Missing** - Need for HTTP backends |
| PROXY Protocol | `proxyproto.Header.WriteTo()` | **Missing** - Need for backend info |
| Dial timeout | 400ms + KeepAlive | **Missing** - v2 has no timeout |
| HTTP/80 redirect | Separate server | **Planned** - STATUS.md TODO |
| Connection close API | `RouteCloseRemotes` | **Missing** - Need for admin API |

---

## Security Recommendations for v2

Based on original analysis:

### 1. Add TLS MinVersion (HIGH)
```go
// v2 handler.go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    // ...
}
```

### 2. Add Dial Timeout (MEDIUM)
```go
// v2 handler.go
func (h *Handler) dialContext(ctx context.Context, addr string) (net.Conn, error) {
    d := net.Dialer{
        Timeout:       400 * time.Millisecond,
        FallbackDelay: 300 * time.Millisecond,
        KeepAliveConfig: net.KeepAliveConfig{
            Enable:   true,
            Idle:     15 * time.Second,
            Interval: 15 * time.Second,
            Count:    2,
        },
    }
    return d.DialContext(ctx, "tcp", addr)
}
```

### 3. Add PROXY Protocol Support (MEDIUM)
- Add `PROXYProto int` to `StaticRoute` and `Decision`
- Write header before tunneling to backend

### 4. Add HTTP Tunnel Support (MEDIUM)
- Need `tun.InjectListener` pattern for terminated HTTP backends
- Allows using `httputil.ReverseProxy` with proper forwarding headers

### 5. Add Connection Tracking (LOW)
- Registry of active connections for admin API
- Idle timeout detection via `LastRead`/`LastWrite`

---

## Dial Timeout Analysis

**Original:** 400ms is very aggressive. This is intentional for:
- Fast failover to next backend
- Quick error response to client
- But may cause issues on high-latency networks

**Recommendation for v2:** Make it configurable:
```go
type Handler struct {
    DialTimeout time.Duration  // Default 5s
    // ...
}
```
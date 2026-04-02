# tlsrouter v2 - Clean Room Design

## Design Goals

1. **Separation of Concerns**: Routing, TLS handshake, and proxying are separate
2. **No Hidden State Mutations**: All state changes are explicit
3. **Testable Components**: Each piece can be unit tested
4. **Minimal Sentinel Errors**: Use where necessary (Go TLS library constraint)

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Server                                │
│                                                            │
│  Accept loop → Handler.Handle(conn)                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────┐
│                      Handler                               │
│                                                            │
│  1. Wrap connection (track bytes)                          │
│  2. Create TLS server with GetConfigForClient              │
│  3. Call Handshake()                                       │
│  4. Route based on result:                                 │
│     - ErrPassthrough → tunnel raw TCP                      │
│     - Success → proxy HTTP                                 │
│     - Error → close connection                             │
│                                                            │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────┐
│                      Router                                │
│                                                            │
│  Route(sni, alpns) → Decision                             │
│                                                            │
│  Decision:                                                 │
│  - Action: Terminate | Passthrough                         │
│  - Backend: host:port                                      │
│  - Domain: for logging                                     │
│  - ALPN: negotiated protocol                               │
│                                                            │
│  Implementations:                                          │
│  - StaticRouter: config-file based routing                 │
│  - DynamicRouter: DNS-based routing (IP-in-hostname)       │
│  - LayeredRouter: try static, then dynamic                 │
│                                                            │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────┐
│                   CertProvider                            │
│                                                            │
│  GetCertificate(domain) → tls.Certificate                 │
│                                                            │
│  Wraps certmagic or custom ACME handling                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

## Key Types

### Decision

```go
type RouteAction int

const (
    ActionTerminate RouteAction = iota
    ActionPassthrough
)

type Decision struct {
    Action   RouteAction
    Backend  string  // "ip:port"
    Domain   string  // SNI from ClientHello
    ALPN     string  // Selected ALPN
}
```

### Router

```go
type Router interface {
    Route(sni string, alpns []string) (Decision, error)
}
```

### Handler

```go
type Handler struct {
    Router  Router
    Certs   CertProvider
    Dialer  Dialer
}

func (h *Handler) Handle(conn net.Conn) error
```

## Flow

```
1. Accept connection
2. Handler.Handle(conn)
   │
   ├─→ Wrap connection with trackingConn
   │
   ├─→ Create TLS server with GetConfigForClient:
   │       Router.Route(sni, alpns) → Decision
   │       if ActionPassthrough: return ErrPassthrough
   │       else: return tls.Config
   │
   ├─→ Handshake()
   │       │
   │       ├─→ ErrPassthrough: tunnel(tracking.Bytes(), backend)
   │       │
   │       └─→ Success: proxyHTTP(tlsConn, backend)
   │
   └─→ Close connection
```

## Why This is Cleaner

1. **Single Responsibility**: Router only routes, Handler only handles connections
2. **No State Mutation in Callback**: GetConfigForClient returns a decision, doesn't create backend connections
3. **Explicit Action**: Decision.Action explicitly says what to do
4. **Testable**: Router can be tested independently with mock inputs
5. **Composable**: LayeredRouter can combine static and dynamic routing
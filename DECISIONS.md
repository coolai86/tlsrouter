# TLSrouter v2 Design Decisions

**Last Updated:** 2026-04-03

## Core Architecture

### Decision: Clean-room rewrite

**Rationale:** The original tlsrouter.go was a monolithic 1000+ line file with complex interdependencies. A clean-room rewrite allows:

1. **Clear interfaces** - Router, CertProvider, Dialer are now explicit
2. **Testability** - Each component can be unit tested in isolation
3. **Maintainability** - Smaller files with single responsibility
4. **Extensibility** - Easy to add new Router implementations

**Trade-off:** Requires re-implementation of existing functionality, but the improved maintainability is worth it.

---

## ACME-TLS/1 Challenge Handling

### Decision: Check active challenge before passthrough

**Problem:** When both TLSrouter and a passthrough backend (e.g., Caddy) need certificates for the same domain, they share ACME-TLS/1 challenges. But not simultaneously - the race happens once per ~30 days.

**Example:**
```
example.com>http/1.1 → passthrough to Caddy:443 (Caddy's TLS)
example.com>ssh      → terminate at TLSrouter (TLSrouter's TLS)
```

**Solution:** Check if TLSrouter's CertMagic has an **active challenge** before routing:

```go
// Priority for ACME-TLS/1:
// 1. CertMagic has active challenge → TLSrouter handles (terminate)
// 2. Per-domain ACMEBackend → passthrough to backend
// 3. Global ACMEPassthrough → passthrough
// 4. No route → error
```

**Implementation:** `HasActiveChallenge(domain)` checks:

1. **In-memory**: `certmagic.GetACMEChallenge(domain)` - this process initiated
2. **Distributed**: `Storage.Exists(challengeTokensKey(domain))` - another process initiated

**Trade-off:** Requires shared storage between TLSrouter instances (not with Caddy). Caddy handles its own ACME independently.

---

### Decision: Three ACME cases from original code

The original tlsrouter had three distinct ACME cases that we preserved:

1. **Certmagic handles internally** - handshake succeeds, no backend needed
2. **Dedicated ACME backend** - `ACMEBackends[domain]` → passthrough to specific backend
3. **Global ACME backend** - `ACMEPassthrough` → passthrough to global backend

**Implementation:**
```go
// GetConfigForClient priority:
if snialpn.SNI() == "acme-tls/1" {
    // 1. Check if CertMagic has active challenge
    if cp.IsManaged(domain) && cp.HasActiveChallenge(domain) {
        return cp.GetMagic().GetCertificate(hello)
    }
    // 2. Check per-domain ACME backend
    if backend, ok := cfg.ACMEBackends[domain]; ok {
        return nil, ErrPassthrough(backend)
    }
    // 3. Check global ACME backend
    if cfg.ACMEPassthrough != "" {
        return nil, ErrPassthrough(cfg.ACMEPassthrough)
    }
    // 4. No route
    return nil, ErrNoRoute(domain)
}
```

---

## Config Management

### Decision: Atomic config swaps

**Problem:** Dynamic API needs to add/remove routes at runtime. Concurrent reads during routing must be safe.

**Solution:** `atomic.Value` for lock-free reads:

```go
type atomicConfig struct {
    value atomic.Value
}

func (ac *atomicConfig) LoadConfig() Config {
    return ac.value.Load().(Config)
}

func (ac *atomicConfig) ReplaceConfig(newCfg Config) Config {
    oldCfg := ac.value.Load().(Config)
    ac.value.Store(newCfg)
    return oldCfg
}
```

**Rule:** All Config instances are **IMMUTABLE**. Use `Config.Copy()` to modify, then atomic swap.

**Trade-off:** Higher memory usage (full copies), but no lock contention on hot path.

---

### Decision: Config mutation methods return new instances

```go
// Safe way to modify config - create copy, modify, then swap
func (c *Config) AddStaticRoute(key string, route StaticRoute) *Config {
    newCfg := c.Copy()
    newCfg.StaticRoutes[key] = route
    return newCfg
}
```

**Rationale:** Prevents accidental modification of in-use config.

---

## Certificate Management

### Decision: certmagic.NewACMEIssuer() instead of direct struct

**Problem:** Direct `&certmagic.ACMEIssuer{}` initialization causes nil mutex panic.

**Solution:**
```go
// WRONG:
issuer := &certmagic.ACMEIssuer{Email: email, Agreed: true}

// CORRECT:
issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
    Email:  email,
    Agreed: true,
})
```

**Rationale:** `NewACMEIssuer` properly initializes internal mutex and state.

---

### Decision: Certificate.PrivateKey as crypto.PrivateKey

```go
type Certificate struct {
    Certificate [][]byte
    PrivateKey  crypto.PrivateKey  // Was: any
    Leaf        *x509.Certificate
}
```

**Rationale:**
- Type safety - matches `crypto/tls.Certificate` design
- Still flexible - ECDSA, RSA, Ed25519 all implement the interface
- Better IDE support with proper documentation hints

---

## Routing

### Decision: LayeredRouter for static + dynamic

```go
type LayeredRouter struct {
    static  Router   // Static routes (CSV)
    dynamic Router   // Dynamic IP-in-hostname routing
}

func (r *LayeredRouter) Route(ctx context.Context, snialpn SNIALPN) (Decision, error) {
    // 1. Try static routes first
    if decision, err := r.static.Route(ctx, snialpn); err == nil {
        return decision, nil
    }
    // 2. Fall back to dynamic
    return r.dynamic.Route(ctx, snialpn)
}
```

**Priority:** Static routes win over dynamic.

---

### Decision: SNIALPN struct for routing key

```go
type SNIALPN struct {
    sni  string
    alpn string
}

func (s SNIALPN) SNI() string  { return s.sni }
func (s SNIALPN) ALPN() string { return s.alpn }

// Routing key: "example.com>http/1.1"
func ParseRouteKey(key string) (sni, alpn string) {
    parts := strings.SplitN(key, ">", 2)
    return parts[0], parts[1]
}
```

**Rationale:** Explicit, type-safe, easy to parse.

---

## Testing

### Decision: No real network I/O in unit tests

All unit tests use mocks:
- `MockCertProvider` - generates self-signed certs
- `MockDialer` - returns fake connections
- `MockListener` - simulates connections

**Rationale:** Fast, deterministic tests that don't depend on external services.

### Decision: Integration tests with `-tags=integration`

```bash
# Unit tests (fast, no network)
go test -v ./v2/

# Integration tests (real ACME, Let's Encrypt Staging)
go test -v -tags=integration ./v2/
```

**Rationale:** Separates fast unit tests from slow integration tests.

---

## Port Mapping

### Decision: Standard port mappings

| Protocol | Terminate | Passthrough |
|----------|-----------|-------------|
| HTTP/1.1 | 3080 | 443 |
| HTTP/2 | 3080 | 443 |
| SSH | 22 | 44322 |
| PostgreSQL | 15432 | 5432 |
| MySQL | 13306 | 3306 |

**Rationale:** Match common conventions. Terminate ports avoid conflicts with local services.

---

## Wildcard Subdomains

### Decision: `.example.com` matches subdomains

```go
// Route key: ".example.com>http/1.1"
// Matches: "foo.example.com>http/1.1", "bar.example.com>http/1.1"
// Does NOT match: "example.com>http/1.1" (exact)
```

**Implementation:** Leading dot indicates wildcard.

---

## Error Handling

### Decision: Sentinel errors for routing

```go
var (
    ErrNoRoute      = errors.New("no route")
    ErrNoCertificate = errors.New("no certificate")
)

type ErrPassthrough struct {
    Backend string
}

func (e ErrPassthrough) Error() string {
    return fmt.Sprintf("passthrough to %s", e.Backend)
}
```

**Rationale:** Explicit error types allow precise handling.

---

## Context Propagation

### Decision: Per-connection context with 5-minute timeout

```go
func (s *Server) ListenAndServe() error {
    // ...
    s.wg.Go(func() {
        connCtx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
        defer cancel()
        s.Handler.Handle(connCtx, conn)
    })
}
```

**Rationale:** Prevents slow backends from blocking forever. Cancellable on server shutdown.

---

## Multiple Peaked Buffers

### Decision: `[][]byte` for peeked data

```go
type trackingConn struct {
    net.Conn
    peeked [][]byte  // Multiple buffers, not just one
}
```

**Rationale:** Matches original's `Passthru()` interface, allows for multi-buffer peek scenarios.

---

## Connection Statistics & Monitoring

### Decision: StatsRegistry with atomic updates

**Problem:** Need real-time visibility into connections without blocking hot path.

**Solution:** `sync.Map` for connections, atomic counters for bytes:

```go
type StatsRegistry struct {
    connections sync.Map // string -> *ConnectionStats
    routes      sync.Map // string -> *RouteAggregate
    subscribers sync.Map // string -> chan StatsEvent
}
```

**Memory:** ~200 bytes per connection. 10k connections = ~2MB.

**Rate calculation:** Global 1-second ticker walks all connections, calculates deltas. No per-connection rate storage.

---

### Decision: Per-connection and per-route statistics

**ConnectionStats** tracks:
- Identity: ID, SrcAddr, DstAddr
- Routing: SNI, ALPN, RouteKey, RouteType, PROXYProto, Terminated, BackendAddr
- TLS: TLSVersion, CipherSuite, CertIssuer (terminated only)
- Timing: Started, LastRead, LastWrite, BackendMs
- Bytes: BytesIn, BytesOut, BackendBytesIn, BackendBytesOut
- Rates: RateInBps, RateOutBps (5s rolling)
- State: State, CloseReason, Errors

**RouteAggregate** tracks:
- Totals: TotalConns, ActiveConns, TotalBytesIn, TotalBytesOut
- Rates: RateInBps, RateOutBps, ConnsPerSec
- Health: BackendErrors, AvgLatencyMs

---

### Decision: HTTP API + SSE for real-time streaming

**Endpoints:**
- `GET /api/connections` — List all active connections
- `GET /api/connections/:id` — Single connection details
- `POST /api/connections/:id/close` — Admin close connection
- `GET /api/routes` — Route aggregates
- `GET /api/stats/stream` — SSE real-time updates

**SSE Events:**
- `connect` — New connection established
- `update` — Periodic bandwidth update
- `disconnect` — Connection closed
- `route` — Route aggregate update

---

### Decision: Optional JSONL retention

**Format:** One JSON object per line (JSONL)

**Rotation:** Daily files: `connections-2026-04-03.jsonl`

**Compression:** Gzip after rotation (configurable)

**Retention:** 7 days default (configurable)

---

## Loop Detection

### Decision: Listener registry + hop headers

**Problem:** Proxy chains can create loops:
1. **Self-routing** — API/UI requests accidentally going to backends
2. **Proxy loops** — TLSrouter A → B → A (or longer chains)

**Solution:** Two-layer detection:

**Layer 1: Socket-level (all traffic)**
```go
type ListenerRegistry struct {
    listeners map[string]struct{} // "host:port" -> exists
    instance  InstanceID           // UUID at startup
}

func (r *ListenerRegistry) CheckLoop(backendAddr string, incomingID InstanceID, hops int) error {
    // 1. Backend matches our listeners → direct loop
    // 2. Backend host matches our listeners → same host, different port
    // 3. Incoming ID matches our instance → chain loop
    // 4. Hop count exceeded (default: 10) → too many hops
}
```

**Layer 2: Header-level (terminated HTTP only)**
```go
// Headers added to outgoing requests:
X-Tlsrouter-Id:    <instance-uuid>
X-Tlsrouter-Hops:  <incremented-count>
X-Tlsrouter-Via:   <comma-separated-instance-ids>
```

**For passthrough (encrypted TCP):**
- Can't add headers — relies on socket-level detection only
- Check backend address against listener registry before dialing

**Implementation:**
- `loop.go` — ListenerRegistry, CheckLoop, HopInfo parsing
- `handler.go` — Check before dialing backend in `tunnelTCP()` and `proxyHTTP()`
- `server.go` — Register listeners on startup

**Trade-off:** Passthrough can't detect chains through other proxies (only loops back to self). HTTP traffic can detect longer chains via hop headers.

---

## Integration Test Results

### ACME-TLS/1 Passthrough Test (PASSED)

Both instances obtained certificates via ACME-TLS/1 (not DNS-01):

```
Certificate A (SSH) serial: 2cf966070cc17c80bdaf410205d5d2ba16cb
Certificate B (HTTP passthrough) serial: 2cda022f880cb65993c0b013e7e393ccb437
```

Domain: `tcp-10-11-8-202.a.bnna.net`

**Flow:**
1. TLSrouter A on `:443` handles SSH cert challenge directly
2. TLSrouter B on `:8443` gets cert via ACME-TLS/1 passthrough from A
3. A checks: `HasActiveChallenge(domain)` → NO → passthrough to B
4. B handles challenge, returns cert
5. Let's Encrypt validates, issues cert to B
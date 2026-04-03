# Go Security Review - tlsrouter v2

**Reviewed:** 2026-04-03
**Go Version:** 1.25.6 (modern practices apply)
**Status:** ✅ Fixes implemented

---

## ✅ Fixed Issues

### 1. **HIGH: TLS MinVersion** (FIXED)

**Location:** `handler.go`

**Original Problem:** No explicit `MinVersion` - relied on Go defaults.

**Fix:** Added explicit `MinVersion: tls.VersionTLS12` in all TLS configs:
```go
baseTLSConfig := &tls.Config{
    MinVersion: tls.VersionTLS12, // SECURITY: Require TLS 1.2+
}
```

**Impact:** Prevents TLS 1.0/1.1 downgrade attacks.

---

### 2. **MEDIUM: Dial Timeout** (FIXED)

**Location:** `handler.go` - `dialContext()`

**Original Problem:** `dial()` had no timeout - could hang indefinitely.

**Fix:** Implemented proper dialer with timeout and keepalive:
```go
d := net.Dialer{
    Timeout:       5 * time.Second,     // Default timeout
    FallbackDelay: 300 * time.Millisecond,
    KeepAlive:     15 * time.Second,
    KeepAliveConfig: net.KeepAliveConfig{
        Enable:   true,
        Idle:     15 * time.Second,
        Interval: 15 * time.Second,
        Count:    2,  // 2 probes = ~30s total
    },
}
```

**Configurable via:** `Handler.DialTimeout` and `Handler.KeepAlive`

---

### 3. **MEDIUM: HTTP Reverse Proxy with X-Forwarded Headers** (FIXED)

**Location:** `handler.go` - `proxyHTTPWithForwardedHeaders()`

**Original Problem:** Direct TCP tunneling didn't set X-Forwarded headers for HTTP traffic.

**Fix:** Implemented proper HTTP proxying using `httputil.ReverseProxy`:
```go
proxy := &httputil.ReverseProxy{
    Rewrite: func(r *httputil.ProxyRequest) {
        r.SetURL(backendURL)
        r.Out.Host = r.In.Host
        r.SetXForwarded()
        r.Out.Header.Set("X-Forwarded-Proto", "https")
        r.Out.Header.Set("X-Forwarded-SNI", decision.Domain)
        r.Out.Header.Set("X-Forwarded-ALPN", decision.ALPN)
    },
}
```

**Headers added:**
- `X-Forwarded-For` - Client IP
- `X-Forwarded-Proto` - "https"
- `X-Forwarded-Host` - Original host
- `X-Forwarded-SNI` - TLS SNI from certificate
- `X-Forwarded-ALPN` - Negotiated ALPN protocol

---

### 4. **MEDIUM: PROXY Protocol Support** (FIXED)

**Location:** `proxyproto/proxyproto.go`

**Original Problem:** No PROXY protocol support - backend couldn't see real client IP.

**Fix:** Implemented PROXY protocol v1 and v2:
```go
// In routing decision:
type Decision struct {
    // ...
    PROXYProto int  // 0=disabled, 1=v1, 2=v2
}

// In StaticRoute:
type StaticRoute struct {
    // ...
    PROXYProto int
}
```

**Usage:** Set `PROXYProto: 1` or `PROXYProto: 2` on routes that need client IP preservation.

---

## 📋 Remaining Recommendations

### LOW: Connection Registry for Admin API

**Current:** No tracking of active connections.

**Recommendation:** Add `sync.Map` connection registry:
```go
type Handler struct {
    // ...
    conns sync.Map // string -> *trackingConn
}
```

This would enable:
- `/api/connections` - List active connections
- `/api/connections/{id}/close` - Close specific connection
- Idle timeout detection via `LastRead`/`LastWrite`

---

### LOW: HTTP/80 Redirect Server

**Status:** Planned (on TODO list)

**Recommendation:** Implement separate HTTP server that redirects to HTTPS:
```go
func ListenAndRedirectPlainHTTP(addr string) error {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        httpsURL := "https://" + r.Host + r.URL.Path
        http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
    })
    return http.ListenAndServe(addr, mux)
}
```

---

## Architecture Notes

### Clean Separation

The v2 implementation has clean interfaces:

| Component | Interface | Purpose |
|-----------|-----------|---------|
| Router | `Route(sni, alpns)` | Make routing decisions |
| CertProvider | `GetCertificate(domain)` | Provide TLS certs |
| Dialer | `Dial(network, addr)` | Create backend connections |

### Immutable Config Pattern

Config uses atomic swaps:
```go
func (h *Handler) SetConfig(cfg *Config) {
    h.config.Store(cfg)  // Atomic replace
}
```

All config changes create new `Config` instances - no mutation of existing configs.

### ACME Priority Chain

1. **Certmagic active challenge** → Handle locally
2. **Per-domain ACME backend** → Passthrough
3. **Global ACME backend** → Passthrough
4. **Error** → No route

---

## Files Changed

| File | Changes |
|------|---------|
| `v2/handler.go` | TLS MinVersion, dial timeout, HTTP proxy, X-Forwarded headers |
| `v2/router.go` | Added `PROXYProto` to `Decision` |
| `v2/static_router.go` | Added `PROXYProto` to `StaticRoute` |
| `v2/proxyproto/proxyproto.go` | **NEW** - PROXY protocol v1/v2 implementation |
| `v2/tun/tunnel.go` | **NEW** - InjectListener for HTTP proxy pattern |

---

## Test Results

```
=== RUN   TestStaticRouter
    --- PASS: TestStaticRouter/exact_match
    --- PASS: TestStaticRouter/ssh_match
    --- PASS: TestStaticRouter/wildcard_subdomain
    --- PASS: TestStaticRouter/passthrough
    --- PASS: TestStaticRouter/no_match

=== RUN   TestHandler_ACMECases
    --- PASS: TestHandler_ACMECases/Per-domain_ACME_backend
    --- PASS: TestHandler_ACMECases/Global_ACME_backend
    --- PASS: TestHandler_ACMECases/Normal_HTTP_traffic_(not_ACME)

=== RUN   TestACMEChallengePriority
    --- PASS: All priority tests
```

All tests passing ✅

---

## Next Steps

1. **Add connection registry** for admin API
2. **Implement HTTP/80 redirect** server
3. **Add integration tests** for PROXY protocol
4. **Add integration tests** for X-Forwarded headers
5. **Consider connection limits** per backend
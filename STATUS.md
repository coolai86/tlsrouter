# TLSrouter v2 Status

**Branch:** `tron-tls`
**Last Updated:** 2026-04-03
**Status:** Integration tests passing ✅

## Test Results

### ACME-TLS/1 Integration Test (PASSED)

```
--- PASS: TestACMETLS1PassthroughIntegration (11.58s)
    --- PASS: TLSrouter A obtains SSH cert via ACME-TLS/1
    --- PASS: TLSrouter B obtains HTTP cert via ACME-TLS/1 passthrough
    --- PASS: Verify ACME-TLS/1 passthrough configuration
    --- PASS: Certificates are independent (8.58s)
    --- PASS: Simulate ACME-TLS/1 challenge passthrough
```

### DuckDNS Integration Test (PASSED)

```
--- PASS: TestACMEDuckDNSIntegration (7.68s)
    --- PASS: No challenge before managing
    --- PASS: Manage domain
    --- PASS: Domain is managed
    --- PASS: Get certificate
    --- PASS: Unmanage domain
```

### Unit Tests (ALL PASSING)

```
=== RUN   TestStaticRouter_ACME
--- PASS: TestStaticRouter_ACME (0.00s)
=== RUN   TestDynamicRouter_ACME
--- PASS: TestDynamicRouter_ACME (0.00s)
=== RUN   TestHandler_ACMECases
--- PASS: TestHandler_ACMECases (0.00s)
=== RUN   TestHandler_ACMEDetectionOrder
--- PASS: TestHandler_ACMEDetectionOrder (0.00s)
=== RUN   TestHandler_ACMEWithMixedALPN
--- PASS: TestHandler_ACMEWithMixedALPN (0.00s)
=== RUN   TestHandler_ConfigAtomicSwap
--- PASS: TestHandler_ConfigAtomicSwap (0.00s)
=== RUN   TestHandler_PostHandshakeACMEDetection
--- PASS: TestHandler_PostHandshakeACMEDetection (0.00s)
=== RUN   TestHandler_ACMELayeredRouting
--- PASS: TestHandler_ACMELayeredRouting (0.00s)
=== RUN   TestCertmagicCertProvider_HasActiveChallenge
--- PASS: TestCertmagicCertProvider_HasActiveChallenge (0.00s)
=== RUN   TestACMEChallengePriority
--- PASS: TestACMEChallengePriority (0.00s)
=== RUN   TestACMESharedDomain
--- PASS: TestACMESharedDomain (0.00s)
PASS
ok  	github.com/bnnanet/tlsrouter/v2	0.006s
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     TLSrouter v2                             │
├─────────────────────────────────────────────────────────────┤
│  Handler (handler.go)                                       │
│  ├── GetConfigForClient (routing callback)                  │
│  ├── ACME-TLS/1 detection (ALPN="acme-tls/1")              │
│  └── Post-handshake ACME check                              │
├─────────────────────────────────────────────────────────────┤
│  Router (router.go, static_router.go)                       │
│  ├── Static routes (domain>alpn → backend)                  │
│  ├── Dynamic IP routing (IP-in-hostname)                    │
│  └── LayeredRouter (static → dynamic fallback)              │
├─────────────────────────────────────────────────────────────┤
│  Config (config.go)                                         │
│  ├── Atomic config swaps (atomic.Value)                     │
│  ├── ACMEBackends map (per-domain ACME routing)             │
│  └── ACMEPassthrough (global ACME backend)                  │
├─────────────────────────────────────────────────────────────┤
│  CertProvider (cert_provider.go)                            │
│  ├── MockCertProvider (testing)                             │
│  ├── StaticCertProvider (static certs)                      │
│  └── CertmagicCertProvider (real ACME)                      │
├─────────────────────────────────────────────────────────────┤
│  Server (server.go)                                         │
│  ├── TCP listener with graceful shutdown                    │
│  └── Per-connection context with 5-min timeout              │
└─────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose | Tests |
|------|---------|-------|
| `v2/router.go` | Core interfaces (Router, CertProvider, Dialer) | ✅ |
| `v2/handler.go` | TLS handshake with routing callback | ✅ |
| `v2/server.go` | TCP server with graceful shutdown | ✅ |
| `v2/config.go` | Atomic config wrapper | ✅ |
| `v2/cert_provider.go` | Mock and static cert providers | ✅ |
| `v2/certmagic_provider.go` | Real ACME integration | ✅ |
| `v2/static_router.go` | Static + dynamic routing | ✅ |
| `v2/acme_test.go` | ACME unit tests | ✅ |
| `v2/handler_test.go` | Handler tests | ✅ |
| `v2/handler_acme_test.go` | ACME handler tests | ✅ |
| `v2/certmagic_acme_test.go` | Certmagic tests | ✅ |
| `v2/acme_duckdns_test.go` | DuckDNS integration test | ✅ |
| `v2/acme_passthrough_test.go` | ACME-TLS/1 passthrough test | ✅ |

## Commits

| Commit | Description |
|--------|-------------|
| `44dd432` | test(acme-tls1): Full integration test PASSED |
| `2d3f122` | fix(test): Use ACME-TLS/1 for passthrough test |
| `b60c321` | test(acme): Add ACME-TLS/1 passthrough integration test |
| `3ea3a5a` | test(acme): Add DuckDNS integration test |
| `b5946bc` | feat(acme): Check active challenge before ACME passthrough |
| `c1e340e` | v2: High-priority fixes - Context & concurrency |
| `98410f0` | v2: Add certmagic ACME integration |
| `f581e22` | v2: Clean-room TLS router implementation |

## Next Steps

- [ ] Dynamic API for add/remove routes
- [ ] HTTP/80 redirect handler
- [ ] PROXY protocol support (v1/v2)
- [ ] Metrics/Prometheus endpoint
- [ ] Connection pooling for backends
- [ ] Rate limiting per backend
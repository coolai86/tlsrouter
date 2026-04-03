# TLSrouter v2 Status

**Branch:** `tron-tls`
**Updated:** 2026-04-03
**Status:** All tests passing ✅ | Stats tracking implemented ✅ | PR open (#5)

## Directories

| Path | Purpose |
|------|---------|
| `/root/dev/projects/tlsrouter/worktrees/tron-tls/` | Primary workspace |
| `/root/dev/projects/tlsrouter/worktrees/tron-tls/v2/` | Clean-room implementation |
| `/root/dev/projects/tlsrouter/worktrees/tron-tls/v2/proxyproto/` | PROXY protocol v1/v2 |
| `/root/dev/projects/tlsrouter/worktrees/tron-tls/v2/tun/` | HTTP tunnel listener |

## Current State

| Component | Status | Notes |
|-----------|--------|-------|
| Core routing (Router, Handler) | ✅ Complete | Static + dynamic + layered |
| ACME-TLS/1 handling | ✅ Complete | Challenge priority + passthrough |
| Certmagic integration | ✅ Complete | Auto-cert with Let's Encrypt |
| Security fixes | ✅ Complete | TLS 1.2+, dial timeout, X-Forwarded |
| PROXY protocol | ✅ Complete | v1 and v2 support |
| Stats tracking | ✅ Complete | Connection + route aggregates |
| HTTP API | ✅ Complete | `/api/connections`, `/api/routes`, SSE |
| Retention logging | ✅ Complete | JSONL with rotation + gzip |
| Stats wired into Server | ⏳ TODO | Need `Server.Stats` field |
| HTTP/80 redirect | ⏳ TODO | From original code |
| Prometheus metrics | ⏳ TODO | Future work |

## Recent Commits

| Hash | Message |
|------|---------|
| `ff931e2` | feat(stats): Add connection statistics, HTTP API, and retention logging |
| `11c60fe` | Security fixes: TLS MinVersion, dial timeout, HTTP proxy with X-Forwarded headers |
| `54cd825` | docs: Add STATUS.md and DECISIONS.md |
| `44dd432` | test(acme-tls1): Full integration test PASSED |
| `2d3f122` | fix(test): Use ACME-TLS/1 (TLS-ALPN-01) for passthrough integration test |

## Unpushed Commits

1 commit ahead of `origin/tron-tls`:
- `ff931e2` - Stats implementation (not yet pushed)

## Next Steps

1. [ ] Push stats commit to origin
2. [ ] Wire `StatsRegistry` into `Server` (add `Stats` field to `Server` struct)
3. [ ] Wire `APIServer` into Server startup (admin HTTP endpoint)
4. [ ] Add HTTP/80 redirect handler
5. [ ] Add Prometheus metrics endpoint
6. [ ] Add connection pooling for backends
7. [ ] Add rate limiting per backend

## Open PR

- https://github.com/coolai86/tlsrouter/pull/5

## Blockers

None - ready to continue.

## Test Results

All unit tests pass. Integration tests require environment setup (TEST_DOMAIN, DUCKDNS_TOKEN).
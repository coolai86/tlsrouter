# Security Considerations for TLSrouter v2

**Last Updated:** 2026-04-03

This document outlines attack vectors specific to a multi-tenant TLS router and proposed mitigations. Read alongside `DECISIONS.md` for implementation details.

---

## 1. Loop Detection & Prevention

### Attack: The Loop Bomb

A malicious customer registers `evil.example.com` → points to the router's own IP:443.

**Impact:**
- Client connects to router
- Router sees SNI, dials itself
- Infinite recursion until FD exhaustion or OOM
- **Single customer can take down all traffic**

### Mitigation: Multi-Layer Detection

#### Layer 1: Direct IP Domain Validation

For `tls-10-11-0-101.vms.example.com` → `10.11.0.101:443` routing:

```go
func ValidateTarget(ip net.IP, port int) error {
    // 1. Check allowed networks (RFC1918, your VPC)
    if !allowedNets.Contains(ip) {
        return fmt.Errorf("ip not in allowed networks")
    }
    
    // 2. Hard block: must not be router's own listeners
    for _, addr := range routerAddrs {
        if addr.IP.Equal(ip) && addr.Port == port {
            return fmt.Errorf("loop detected: target is router itself")
        }
    }
    
    // 3. Soft block: infrastructure blacklist
    if infraBlacklist.Contains(ip) {
        return fmt.Errorf("target is infrastructure")
    }
    
    return nil
}
```

**Key:** Resolve *before* dialing. Validate actual bind addresses, not just `0.0.0.0`.

#### Layer 2: Listener Registry

See `loop.go` — tracks all listener addresses:
- Check backend against registered listeners
- UUID per instance to detect chain loops
- Max hop count (default: 10)

#### Layer 3: Port Architecture

Design out loops by convention:
- **Ingress**: `:443` (public-facing)
- **Egress**: `:8443` or `:4443` (backend-facing)

Router never dials `:443` directly. Backends use alternate ports.

---

## 2. Certificate Starvation

### Attack: Rate Limit Exhaustion

Customer requests TLS for `*.com`, `*.net`, `*.org` or thousands of random domains.

**Impact:**
- Let's Encrypt rate limits: 20 certs/week per domain
- Legitimate customers can't get certs
- **ACME account gets banned**

### Mitigation: Domain Validation & Quotas

```go
type BackendLimiter struct {
    domainsPerBackend int  // e.g., 10 domains → 1 backend
    domainsPerAccount int  // e.g., 100 domains/customer
    labelsPerDomain   int  // e.g., max 5 labels
}
```

**Rules:**
1. Validate domain ownership *before* certmagic sees the request
2. Reject wildcards that don't match customer identity
3. Rate limit cert requests per customer (token bucket)
4. Limit domains per backend (prevents backend saturation)

---

## 3. Slowloris & Resource Exhaustion

### Attack: Connection Starvation

Customer opens thousands of TLS handshakes but never completes them:
- Send ClientHello, wait
- Send empty TLS records, wait
- Each connection = 1 goroutine + TLS state machine

### Attack: The Backend Tarpit

Customer's container accepts TCP, sends 1 byte/minute:
- Keeps connections "alive" indefinitely
- Router holds goroutine + backend connection
- **FD exhaustion**

### Mitigation: Aggressive Timeouts

For local VPC networks:

```go
// TCP connect: 500ms (should be <10ms, margin for GC)
dialer := &net.Dialer{
    Timeout: 500 * time.Millisecond,
}

// TLS handshake: 1-2s
tlsConn.SetDeadline(time.Now().Add(2 * time.Second))

// Read/write idle: protocol-dependent
// HTTP: 30s (keep-alive)
// SSH/long-lived: 5m with TCP keepalive
```

**TCP Keepalive for idle detection:**
```go
conn.(*net.TCPConn).SetKeepAlive(true)
conn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)
```

---

## 4. SSRF to Internal Infrastructure

### Attack: Metadata Service Access

Customer registers `tcp-10-0-0-1.internal.local`:
- Router dials `10.0.0.1:443` (cloud metadata endpoint)
- **Exposes internal APIs**

### Mitigation: Network Allowlisting

```go
// Block these by default:
// - 169.254.169.254 (AWS/GCP/Azure metadata)
// - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918)
// - Link-local addresses (169.254.0.0/16)
// - Multicast

// Allow only customer-assigned VPC ranges
allowedNets := []net.IPNet{
    customerVPC1,
    customerVPC2,
    // etc.
}
```

**Additional:** Explicit allowlist for dynamic routes. No open-ended "dial anything."

---

## 5. SNI/ALPN Confusion

### Attack: ALPN Smashing

Send invalid ALPN: `h2,http/1.1,<10KB garbage>`
- Memory pressure from parsing
- Matching logic churn

### Mitigation: Strict Validation

```go
// ALPN length limits
if len(alpn) > 256 {
    return error
}

// Validate against known protocols only
knownALPNs := []string{
    "h2", "http/1.1", "ssh", "postgresql", // ...
}
```

---

## 6. Certificate Cache Poisoning

### Attack: Cross-Protocol Cert Reuse

If caching by SNI only (not SNI+ALPN):
1. Register `bank.example.com>h2` → phishing backend
2. Later request `bank.example.com>http/1.1`
3. **Same cert reused, wrong backend served**

### Mitigation: Composite Cache Key

Cache key must include: `SNI + ALPN + RouteType`

```go
key := fmt.Sprintf("%s>%s>%s", sni, alpn, routeType)
```

---

## 7. DNS Rebinding

### Attack: IP Switching

1. Register `attacker.com` → their IP (passes validation)
2. Change DNS to `127.0.0.1` or internal LB
3. Router now dials internal services

### Mitigation: Re-resolve Before Dial

```go
// Don't trust stored IP from initial validation
// Re-resolve at dial time, check against allowlist
addrs, err := net.LookupIP(domain)
for _, ip := range addrs {
    if !allowedNets.Contains(ip) {
        return error
    }
}
```

---

## 8. Active vs. Zombie Connection Detection

### Problem: Distinguish
- **Active but idle**: SSH session, no typing (keepalive OK)
- **Zombie**: Backend died, RST not received

### Detection Strategy

**TCP Keepalive (kernel-level):**
```go
conn.(*net.TCPConn).SetKeepAlive(true)
conn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)
// Kernel probes, tells us if other side vanished
```

**Application-level (if possible):**
- Protocol heartbeats (SSH ignore, HTTP/2 PING)
- Passthrough can't see these

**Heuristic:**
- No bytes either direction for > idleTimeout
- No TCP keepalive ACK received
→ Close connection

---

## Summary Table

| Threat | Severity | Status | Implementation |
|--------|----------|--------|---------------|
| Loop bomb | Critical | ✅ Done | `loop.go` — Listener registry |
| Slowloris | High | ✅ Done | `handler.go` — 500ms default dial timeout |
| SSRF | High | ✅ Done | `security.go` — BlockedNetworks + AllowedNetworks |
| ALPN smashing | Medium | ✅ Done | `security.go` — ValidateALPNList() |
| Cert starvation | High | ⏳ TODO | Need domain quotas |
| DNS rebinding | Medium | ⏳ TODO | Re-resolve before dial |
| Zombie connections | Low | ✅ Done | TCP keepalive configured |
| Cache poisoning | Medium | ✅ N/A | Composite keys in routing |

---

## Implemented Mitigations

### 1. Loop Detection (`loop.go`)

- `ListenerRegistry` tracks all listening addresses
- `CheckLoop()` blocks routing to self
- Hop headers (`X-Tlsrouter-*`) detect proxy chains in HTTP

### 2. SSRF Protection (`security.go`)

Two-layer validation:

**Layer 1: DynamicRouter.Networks (allowlist for IP-in-hostname)**
- Customer defines their VPC ranges: `10.0.0.0/8`, `192.168.0.0/16`
- `tls-10-11-0-101.vm.example.com` → validates `10.11.0.101` is in allowed networks

**Layer 2: SecurityValidator.BlockedNetworks (blocklist for all backends)**
- Always blocks: metadata endpoints (`169.254.169.254`), loopback (`127.0.0.0/8`), link-local
- Applied to ALL backends, not just dynamic routes
- Prevents SSRF via static routes to malicious backends

**Layer 3: SecurityValidator.AllowedNetworks (optional explicit allowlist)**
- If set, ONLY these networks are permitted
- Supercedes BlockedNetworks
- Use for high-security deployments

```go
// Example: Allow only customer VPC ranges
v := NewSecurityValidator(&SecurityConfig{
    AllowedNetworks: []net.IPNet{
        parseCIDR("10.0.0.0/8"),
        parseCIDR("192.168.0.0/16"),
    },
})
handler.Security = v
```

### 3. Aggressive Timeouts (`handler.go`)

- Dial timeout: **500ms** (down from 5s) for VPC networks
- TCP keepalive: 15s idle, 15s interval, 2 probes
- Connection timeout: 5 minutes per connection

### 4. ALPN Validation (`security.go`)

- Max length: 256 bytes per protocol
- Max total: 1024 bytes for ALPN extension
- Empty ALPN rejected
- Known protocols tracked for monitoring (not blocking)

---

## Open Questions

1. Should we implement connection marking with `SO_MARK` for iptables-level blocking?
2. Do we need distributed state for cross-instance loop detection?
3. What are acceptable rate limits per customer? (need telemetry)

---

**See Also:**
- `loop.go` — Loop detection implementation
- `DECISIONS.md` — Architecture decisions
- `README.md` — Design overview

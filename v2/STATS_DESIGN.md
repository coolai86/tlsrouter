# Connection Stats & Monitoring Design

**Status:** Draft
**Created:** 2026-04-03

---

## Overview

Real-time visibility into TLSrouter connections: bandwidth, state, routing decisions, and backend health.

---

## Goals

1. **Per-connection stats** — Source/dest, bytes in/out, state, ALPN, TLS info
2. **Per-route aggregates** — Totals and rates per routing key
3. **Efficient memory** — ~200 bytes per connection, not megabytes
4. **Real-time streaming** — SSE for live dashboards
5. **Optional retention** — JSONL/CSV for historical analysis

---

## Data Model

### ConnectionStats (per-connection, in-memory)

```go
type ConnectionStats struct {
    // Identity (48 bytes)
    ID           string    // UUID, 16 bytes as string: "a1b2c3d4-..."
    SrcAddr      string    // "1.2.3.4:12345" — up to 21 bytes for IPv6
    DstAddr      string    // Local address, up to 21 bytes
    
    // Routing (32 bytes)
    SNI          string    // Domain from TLS handshake
    ALPN         string    // Negotiated protocol: "h2", "http/1.1", "ssh", etc.
    RouteKey     string    // "example.com>h2" or "dynamic" for IP routing
    RouteType    uint8     // 0=static, 1=dynamic, 2=acme-passthrough
    PROXYProto   uint8     // 0=none, 1=v1, 2=v2
    Terminated   bool      // TLS terminated at router vs passthrough
    BackendAddr  string    // Where we connected to
    
    // TLS (32 bytes, terminated only)
    TLSVersion   uint16    // 0x0303=TLS1.2, 0x0304=TLS1.3
    CipherSuite  uint16    // TLS cipher ID
    CertIssuer   string    // "Let's Encrypt" or CN from cert
    
    // Timing (24 bytes)
    Started      time.Time // Connection established
    LastRead     time.Time // For idle detection
    LastWrite    time.Time
    
    // Bytes (32 bytes) — atomic, updated via AddUint64
    BytesIn      uint64    // From client → router
    BytesOut     uint64    // From router → client
    BackendIn    uint64    // From backend → router (for passthrough)
    BackendOut   uint64    // From router → backend
    
    // Rates (16 bytes) — rolling 5s window
    RateInBps    uint64    // Bytes/sec in (5s avg)
    RateOutBps   uint64    // Bytes/sec out (5s avg)
    
    // State (8 bytes)
    State        uint8     // 0=handshaking, 1=established, 2=closing, 3=closed
    Errors       uint8     // Read/write error count
    BackendMs    uint16    // Backend connect latency in ms
    
    // Total: ~192 bytes per connection
}
```

### RouteAggregate (per-route-key, in-memory)

```go
type RouteAggregate struct {
    RouteKey     string    // "example.com>h2"
    
    // Totals (lifetime)
    TotalConns   uint64    // Connections ever routed here
    ActiveConns  uint64    // Currently active
    TotalBytesIn  uint64
    TotalBytesOut uint64
    
    // Rates (5s rolling)
    RateInBps    uint64
    RateOutBps   uint64
    ConnsPerSec  float64   // New connections per second (5s avg)
    
    // Backend health
    BackendErrors uint64   // Failed backend dials
    AvgLatencyMs uint32    // Average backend connect latency
}
```

### Rolling Rate Calculation

```go
type RateTracker struct {
    samples    [5]int64   // Last 5 samples (1s each)
    current    int        // Index into samples
    timestamps [5]time.Time
}

func (r *RateTracker) Add(bytes int64) {
    now := time.Now()
    r.samples[r.current] += bytes
}

func (r *RateTracker) Tick() {
    // Called every second
    r.current = (r.current + 1) % 5
    r.samples[r.current] = 0
    r.timestamps[r.current] = time.Now()
}

func (r *RateTracker) Rate() uint64 {
    // Sum last 5 samples, divide by 5
    var total int64
    for i := 0; i < 5; i++ {
        total += r.samples[i]
    }
    return uint64(total / 5)
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TLSrouter v2                              │
├─────────────────────────────────────────────────────────────────┤
│  Handler                                                          │
│  ├── trackingConn wraps each connection                          │
│  ├── Updates stats on every Read/Write                           │
│  └── Notifies Registry on connect/disconnect                     │
├─────────────────────────────────────────────────────────────────┤
│  StatsRegistry (thread-safe, lock-free reads)                    │
│  ├── sync.Map[connID] → *ConnectionStats                          │
│  ├── sync.Map[routeKey] → *RouteAggregate                         │
│  ├── RateUpdater goroutine (1s tick for rolling windows)         │
│  └── Subscribers []chan StatsEvent (SSE clients)                  │
├─────────────────────────────────────────────────────────────────┤
│  API Server                                                       │
│  ├── GET /api/connections         → JSON list                     │
│  ├── GET /api/connections/:id    → JSON single                    │
│  ├── GET /api/routes             → Route aggregates              │
│  ├── GET /api/stats/stream       → SSE real-time updates         │
│  └── POST /api/connections/:id/close → Close connection          │
├─────────────────────────────────────────────────────────────────┤
│  Retention (optional)                                            │
│  ├── FileWriter goroutine                                         │
│  ├── Format: JSONL (one object per line)                         │
│  └── Rotation: daily files, compress after N days               │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Endpoints

### GET /api/connections

```json
{
  "connections": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "src_addr": "192.168.1.100:54321",
      "dst_addr": "10.0.0.1:443",
      "sni": "example.com",
      "alpn": "h2",
      "route_key": "example.com>h2",
      "route_type": "static",
      "terminated": true,
      "backend_addr": "127.0.0.1:3080",
      "tls_version": "TLS1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "proxy_proto": 0,
      "started": "2026-04-03T15:00:00Z",
      "duration_ms": 45000,
      "bytes_in": 524288,
      "bytes_out": 1048576,
      "rate_in_bps": 10240,
      "rate_out_bps": 20480,
      "state": "established",
      "errors": 0,
      "backend_ms": 12
    }
  ],
  "total": 1
}
```

### GET /api/routes

```json
{
  "routes": [
    {
      "route_key": "example.com>h2",
      "total_conns": 1523,
      "active_conns": 5,
      "total_bytes_in": 1073741824,
      "total_bytes_out": 2147483648,
      "rate_in_bps": 524288,
      "rate_out_bps": 1048576,
      "conns_per_sec": 2.3,
      "backend_errors": 0,
      "avg_latency_ms": 15
    }
  ]
}
```

### GET /api/stats/stream (SSE)

```
event: connect
data: {"id":"...","sni":"example.com","alpn":"h2","route_key":"example.com>h2"}

event: update
data: {"id":"...","bytes_in":1024,"bytes_out":2048,"rate_in_bps":512,"rate_out_bps":1024}

event: disconnect
data: {"id":"...","duration_ms":45000,"total_bytes_in":524288,"total_bytes_out":1048576}
```

### POST /api/connections/:id/close

```json
{
  "status": "closed",
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

---

## Memory Efficiency

### Per-Connection Overhead

| Field | Size | Notes |
|-------|------|-------|
| Identity | 48 bytes | ID + addresses |
| Routing | 32 bytes | SNI, ALPN, route info |
| TLS | 32 bytes | Version, cipher, issuer |
| Timing | 24 bytes | Timestamps |
| Bytes | 32 bytes | 4x uint64 counters |
| Rates | 16 bytes | Rolling averages |
| State | 8 bytes | State + errors + latency |
| **Total** | **~200 bytes** | Per active connection |

### 10,000 concurrent connections = ~2MB

### Rate Tracking

- 5 int64 samples per direction = 80 bytes per connection
- Alternatively: global rate calculator that samples all connections every second
- Global approach: O(n) per tick, but no per-connection rate storage

---

## Implementation Plan

### Phase 1: Core Stats (handler.go, stats.go)

1. Add `StatsRegistry` struct with sync.Map for connections
2. Add `trackingConn` wrapper that updates stats on Read/Write
3. Wire into `Handler.Handle()`
4. Add rate calculation goroutine (1s tick)

### Phase 2: API Server (api.go)

1. Add `/api/connections` endpoint
2. Add `/api/routes` endpoint  
3. Add `/api/connections/:id/close` endpoint
4. Wire into Server startup

### Phase 3: SSE Streaming (sse.go)

1. Add subscriber registry to StatsRegistry
2. Broadcast connect/update/disconnect events
3. Add `/api/stats/stream` endpoint

### Phase 4: Retention (retention.go, optional)

1. Add file writer for JSONL output
2. Daily rotation
3. Configurable retention period

---

## Open Questions

1. **Rate sampling frequency** — 1s is standard, but could be configurable
2. **SSE vs WebSocket** — SSE is simpler for server-to-client; WebSocket if we need client-to-server
3. **Historical query API** — For now, just raw files; could add SQLite later
4. **Connection close reason** — Track why (client close, error, timeout, admin)?

---

## Files to Create/Modify

| File | Changes |
|------|---------|
| `v2/stats.go` | **NEW** — StatsRegistry, ConnectionStats, RouteAggregate |
| `v2/handler.go` | Wire trackingConn, update stats |
| `v2/server.go` | Add StatsRegistry field |
| `v2/api.go` | **NEW** — HTTP API handlers |
| `v2/sse.go` | **NEW** — SSE streaming |
| `v2/config.go` | Add retention config options |

---

## Testing Strategy

1. **Unit tests** — Stats tracking with mock connections
2. **Benchmark** — Memory per connection, rate calculation overhead
3. **Integration** — API endpoint tests with real connections
4. **Load test** — 10k concurrent connections, verify ~2MB overhead
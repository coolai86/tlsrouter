package tlsrouter

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionState represents the current state of a connection.
type ConnectionState uint8

const (
	StateHandshaking ConnectionState = iota
	StateEstablished
	StateClosing
	StateClosed
)

func (s ConnectionState) String() string {
	switch s {
	case StateHandshaking:
		return "handshaking"
	case StateEstablished:
		return "established"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// CloseReason represents why a connection was closed.
type CloseReason uint8

const (
	CloseReasonNone CloseReason = iota
	CloseReasonClientClose
	CloseReasonTimeout
	CloseReasonError
	CloseReasonAdmin
)

func (r CloseReason) String() string {
	switch r {
	case CloseReasonNone:
		return "none"
	case CloseReasonClientClose:
		return "client_close"
	case CloseReasonTimeout:
		return "timeout"
	case CloseReasonError:
		return "error"
	case CloseReasonAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// RouteType indicates how the route was determined.
type RouteType uint8

const (
	RouteTypeStatic RouteType = iota
	RouteTypeDynamic
	RouteTypeACMEPassthrough
)

func (t RouteType) String() string {
	switch t {
	case RouteTypeStatic:
		return "static"
	case RouteTypeDynamic:
		return "dynamic"
	case RouteTypeACMEPassthrough:
		return "acme_passthrough"
	default:
		return "unknown"
	}
}

// ConnectionStats tracks statistics for a single connection.
// Approximately 200 bytes per connection.
type ConnectionStats struct {
	// Identity
	ID      string    // UUID
	SrcAddr string    // "1.2.3.4:12345"
	DstAddr string    // Local address

	// Routing
	SNI       string    // Domain from TLS handshake
	ALPN      string    // Negotiated protocol
	RouteKey  string    // "example.com>h2" or "dynamic"
	RouteType RouteType // static, dynamic, acme_passthrough
	PROXYProto uint8    // 0=none, 1=v1, 2=v2
	Terminated bool     // TLS terminated at router
	BackendAddr string  // Where we connected to

	// TLS (terminated only)
	TLSVersion  uint16 // 0x0303=TLS1.2, 0x0304=TLS1.3
	CipherSuite uint16 // TLS cipher ID
	CertIssuer  string // "Let's Encrypt" or CN

	// Timing
	Started    time.Time
	LastRead   time.Time
	LastWrite  time.Time
	BackendMs  uint16 // Backend connect latency in ms

	// Bytes (client side)
	BytesIn  uint64 // From client → router
	BytesOut uint64 // From router → client

	// Bytes (backend side, for passthrough)
	BackendBytesIn  uint64 // From backend → router
	BackendBytesOut uint64 // From router → backend

	// Rates (5s rolling average)
	RateInBps  uint64 // Bytes/sec in
	RateOutBps uint64 // Bytes/sec out

	// State
	State       ConnectionState
	CloseReason CloseReason
	Errors      uint8 // Read/write error count

	// Rate tracking (internal)
	rateWindow [5]int64 // Last 5 samples (1s each)
	rateIdx    int
}

// MarshalJSON implements json.Marshaler for ConnectionStats.
func (s *ConnectionStats) MarshalJSON() ([]byte, error) {
	type Alias ConnectionStats
	return json.Marshal(&struct {
		*Alias
		DurationMs   int64  `json:"duration_ms"`
		TLSVersionStr string `json:"tls_version,omitempty"`
		CipherStr     string `json:"cipher_suite,omitempty"`
		StateStr      string `json:"state"`
		CloseReasonStr string `json:"close_reason"`
		RouteTypeStr  string `json:"route_type"`
	}{
		Alias: (*Alias)(s),
		DurationMs: time.Since(s.Started).Milliseconds(),
		TLSVersionStr: tlsVersionString(s.TLSVersion),
		CipherStr:     cipherSuiteString(s.CipherSuite),
		StateStr:      s.State.String(),
		CloseReasonStr: s.CloseReason.String(),
		RouteTypeStr:  s.RouteType.String(),
	})
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return ""
	}
}

func cipherSuiteString(v uint16) string {
	// Common cipher suites
	switch v {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	default:
		return ""
	}
}

// RouteAggregate tracks statistics for all connections on a route.
type RouteAggregate struct {
	RouteKey string

	// Totals (lifetime)
	TotalConns    uint64 // Connections ever routed here
	ActiveConns   uint64 // Currently active
	TotalBytesIn  uint64 // From clients
	TotalBytesOut uint64 // To clients

	// Rates (5s rolling)
	RateInBps    uint64
	RateOutBps   uint64
	ConnsPerSec  float64 // New connections per second (5s avg)

	// Backend health
	BackendErrors uint64 // Failed backend dials
	AvgLatencyMs  uint32 // Average backend connect latency

	// Internal tracking
	connCount [5]uint64 // Connections per second window
	rateWindow [5]int64  // Bytes per second window
	rateIdx   int
	lastUpdate time.Time
}

// StatsEvent is an event sent to SSE subscribers.
type StatsEvent struct {
	Type      string          `json:"type"` // "connect", "update", "disconnect"
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// StatsRegistry tracks all connection and route statistics.
type StatsRegistry struct {
	connections sync.Map // string -> *ConnectionStats
	routes      sync.Map // string -> *RouteAggregate

	// Subscribers for SSE
	subscribers sync.Map // string -> chan StatsEvent
	subID       atomic.Uint64

	// Rate update ticker
	ticker     *time.Ticker
	tickerDone chan struct{}

	// Historical logging (optional)
	retention  RetentionWriter
	retentionMu sync.Mutex
}

// RetentionWriter is an optional interface for logging connection history.
type RetentionWriter interface {
	Write(stats *ConnectionStats) error
	Close() error
}

// NewStatsRegistry creates a new registry.
func NewStatsRegistry() *StatsRegistry {
	r := &StatsRegistry{
		tickerDone: make(chan struct{}),
	}
	r.ticker = time.NewTicker(time.Second)
	go r.rateUpdater()
	return r
}

// SetRetention sets the retention writer for historical logging.
func (r *StatsRegistry) SetRetention(w RetentionWriter) {
	r.retentionMu.Lock()
	defer r.retentionMu.Unlock()
	r.retention = w
}

// TrackConnection registers a new connection.
func (r *StatsRegistry) TrackConnection(id string, srcAddr, dstAddr net.Addr) *ConnectionStats {
	stats := &ConnectionStats{
		ID:        id,
		SrcAddr:   srcAddr.String(),
		DstAddr:   dstAddr.String(),
		Started:   time.Now(),
		State:     StateHandshaking,
	}
	r.connections.Store(id, stats)
	return stats
}

// SetRouteInfo sets routing information for a connection.
func (r *StatsRegistry) SetRouteInfo(id string, decision Decision, routeType RouteType, terminated bool, backendAddr string, tlsVersion, cipherSuite uint16) {
	if v, ok := r.connections.Load(id); ok {
		stats := v.(*ConnectionStats)
		stats.SNI = decision.Domain
		stats.ALPN = decision.ALPN
		stats.RouteKey = decision.Domain + ">" + decision.ALPN
		stats.RouteType = routeType
		stats.Terminated = terminated
		stats.BackendAddr = backendAddr
		stats.PROXYProto = uint8(decision.PROXYProto)
		stats.TLSVersion = tlsVersion
		stats.CipherSuite = cipherSuite
		stats.State = StateEstablished

		// Update route aggregate
		r.updateRouteAggregate(stats)
	}
}

// SetBackendLatency records the backend connection latency.
func (r *StatsRegistry) SetBackendLatency(id string, latency time.Duration) {
	if v, ok := r.connections.Load(id); ok {
		stats := v.(*ConnectionStats)
		stats.BackendMs = uint16(latency.Milliseconds())
	}
}

// UpdateBytes updates byte counters for a connection.
func (r *StatsRegistry) UpdateBytes(id string, bytesIn, bytesOut, backendIn, backendOut int64) {
	if v, ok := r.connections.Load(id); ok {
		stats := v.(*ConnectionStats)
		atomic.AddUint64(&stats.BytesIn, uint64(bytesIn))
		atomic.AddUint64(&stats.BytesOut, uint64(bytesOut))
		atomic.AddUint64(&stats.BackendBytesIn, uint64(backendIn))
		atomic.AddUint64(&stats.BackendBytesOut, uint64(backendOut))
		now := time.Now()
		stats.LastRead = now
		stats.LastWrite = now
	}
}

// CloseConnection marks a connection as closed.
func (r *StatsRegistry) CloseConnection(id string, reason CloseReason) {
	if v, ok := r.connections.Load(id); ok {
		stats := v.(*ConnectionStats)
		stats.State = StateClosed
		stats.CloseReason = reason

		// Update route aggregate
		r.decrementRouteActive(stats.RouteKey)

		// Write to retention if configured
		r.retentionMu.Lock()
		if r.retention != nil {
			_ = r.retention.Write(stats)
		}
		r.retentionMu.Unlock()

		// Broadcast disconnect event
		r.broadcast(StatsEvent{
			Type:      "disconnect",
			Timestamp: time.Now(),
			Data:      mustMarshal(stats),
		})

		// Remove from active connections after a short delay
		// (allows API to query closed connections briefly)
		go func() {
			time.Sleep(5 * time.Second)
			r.connections.Delete(id)
		}()
	}
}

// GetConnection returns stats for a single connection.
func (r *StatsRegistry) GetConnection(id string) *ConnectionStats {
	if v, ok := r.connections.Load(id); ok {
		return v.(*ConnectionStats)
	}
	return nil
}

// ListConnections returns all active connections.
func (r *StatsRegistry) ListConnections() []*ConnectionStats {
	var result []*ConnectionStats
	r.connections.Range(func(_, v any) bool {
		stats := v.(*ConnectionStats)
		if stats.State != StateClosed {
			result = append(result, stats)
		}
		return true
	})
	return result
}

// ListAllConnections returns all connections including recently closed.
func (r *StatsRegistry) ListAllConnections() []*ConnectionStats {
	var result []*ConnectionStats
	r.connections.Range(func(_, v any) bool {
		result = append(result, v.(*ConnectionStats))
		return true
	})
	return result
}

// GetRoute returns aggregate stats for a route.
func (r *StatsRegistry) GetRoute(routeKey string) *RouteAggregate {
	if v, ok := r.routes.Load(routeKey); ok {
		return v.(*RouteAggregate)
	}
	return nil
}

// ListRoutes returns all route aggregates.
func (r *StatsRegistry) ListRoutes() []*RouteAggregate {
	var result []*RouteAggregate
	r.routes.Range(func(_, v any) bool {
		result = append(result, v.(*RouteAggregate))
		return true
	})
	return result
}

// Subscribe returns a channel for SSE updates.
func (r *StatsRegistry) Subscribe() (string, <-chan StatsEvent) {
	id := strconv.FormatUint(r.subID.Add(1), 10)
	ch := make(chan StatsEvent, 100)
	r.subscribers.Store(id, ch)
	return id, ch
}

// Unsubscribe removes a subscriber.
func (r *StatsRegistry) Unsubscribe(id string) {
	if v, ok := r.subscribers.Load(id); ok {
		close(v.(chan StatsEvent))
		r.subscribers.Delete(id)
	}
}

// rateUpdater runs every second to update rolling averages.
func (r *StatsRegistry) rateUpdater() {
	for {
		select {
		case <-r.ticker.C:
			r.updateRates()
		case <-r.tickerDone:
			return
		}
	}
}

// updateRates recalculates rates for all connections.
func (r *StatsRegistry) updateRates() {
	// Update per-connection rates
	r.connections.Range(func(_, v any) bool {
		stats := v.(*ConnectionStats)
		if stats.State == StateClosed {
			return true
		}

		// Store current byte counts
		currentIn := int64(atomic.LoadUint64(&stats.BytesIn))
		currentOut := int64(atomic.LoadUint64(&stats.BytesOut))

		// Calculate delta from last sample
		idx := stats.rateIdx % 5
		lastIn := stats.rateWindow[idx*2]
		lastOut := stats.rateWindow[idx*2+1]

		deltaIn := currentIn - lastIn
		deltaOut := currentOut - lastOut

		// Store for next delta
		stats.rateWindow[idx*2] = currentIn
		stats.rateWindow[idx*2+1] = currentOut
		stats.rateIdx++

		// Calculate rate (delta bytes / 1 second = bytes per second)
		// We use a simple rolling average over 5 samples
		stats.RateInBps = uint64(deltaIn)
		stats.RateOutBps = uint64(deltaOut)

		return true
	})

	// Update route aggregates
	r.routes.Range(func(_, v any) bool {
		agg := v.(*RouteAggregate)

		// Roll connection count window
		idx := agg.rateIdx % 5
		agg.connCount[idx] = agg.TotalConns - agg.ActiveConns // New connections in this second
		agg.rateWindow[idx] = int64(agg.RateInBps)
		agg.rateIdx++

		// Calculate averages
		var totalConns uint64
		var totalRate int64
		for i := 0; i < 5; i++ {
			totalConns += agg.connCount[i]
			totalRate += agg.rateWindow[i]
		}
		agg.ConnsPerSec = float64(totalConns) / 5.0
		agg.RateInBps = uint64(totalRate / 5)
		agg.lastUpdate = time.Now()

		return true
	})
}

// updateRouteAggregate increments counters for a route.
func (r *StatsRegistry) updateRouteAggregate(stats *ConnectionStats) {
	if stats.RouteKey == "" {
		return
	}

	// Load or create aggregate
	var agg *RouteAggregate
	if v, ok := r.routes.Load(stats.RouteKey); ok {
		agg = v.(*RouteAggregate)
	} else {
		agg = &RouteAggregate{RouteKey: stats.RouteKey}
		r.routes.Store(stats.RouteKey, agg)
	}

	atomic.AddUint64(&agg.TotalConns, 1)
	atomic.AddUint64(&agg.ActiveConns, 1)
}

// decrementRouteActive decrements the active connection count for a route.
func (r *StatsRegistry) decrementRouteActive(routeKey string) {
	if routeKey == "" {
		return
	}

	if v, ok := r.routes.Load(routeKey); ok {
		agg := v.(*RouteAggregate)
		if agg.ActiveConns > 0 {
			atomic.AddUint64(&agg.ActiveConns, ^uint64(0)) // Decrement
		}
	}
}

// broadcast sends an event to all subscribers.
func (r *StatsRegistry) broadcast(event StatsEvent) {
	r.subscribers.Range(func(_, v any) bool {
		ch := v.(chan StatsEvent)
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
		return true
	})
}

// Close stops the rate updater and retention writer.
func (r *StatsRegistry) Close() error {
	close(r.tickerDone)
	r.ticker.Stop()

	r.retentionMu.Lock()
	defer r.retentionMu.Unlock()
	if r.retention != nil {
		return r.retention.Close()
	}
	return nil
}

func mustMarshal(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// StatsContextKey is used to store stats ID in context.
type StatsContextKey struct{}

// StatsIDFromContext retrieves the stats ID from context.
func StatsIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(StatsContextKey{}).(string); ok {
		return id
	}
	return ""
}

// ContextWithStatsID returns a context with stats ID.
func ContextWithStatsID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, StatsContextKey{}, id)
}
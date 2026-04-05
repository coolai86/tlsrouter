package tlsrouter

import (
	"net"
	"sort"
	"sync"

	"github.com/google/uuid"
)

// InstanceID is a unique identifier for this TLSrouter instance.
// Generated at startup, used for loop detection.
type InstanceID string

// NewInstanceID generates a new unique instance ID.
func NewInstanceID() InstanceID {
	return InstanceID(uuid.New().String())
}

// ListenerRegistry tracks all listening addresses for loop detection.
type ListenerRegistry struct {
	mu        sync.RWMutex
	listeners map[string]struct{} // "host:port" -> exists
	instance  InstanceID
}

// NewListenerRegistry creates a new registry.
func NewListenerRegistry() *ListenerRegistry {
	return &ListenerRegistry{
		listeners: make(map[string]struct{}),
		instance:  NewInstanceID(),
	}
}

// Register adds a listener address.
func (r *ListenerRegistry) Register(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners[addr] = struct{}{}
}

// Unregister removes a listener address.
func (r *ListenerRegistry) Unregister(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.listeners, addr)
}

// IsSelf checks if an address is one of our listeners.
func (r *ListenerRegistry) IsSelf(addr string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.listeners[addr]
	return ok
}

// IsSelfHost checks if the host matches any listener (ignoring port).
func (r *ListenerRegistry) IsSelfHost(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for addr := range r.listeners {
		h, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if h == host {
			return true
		}
	}
	return false
}

// InstanceID returns the instance ID.
func (r *ListenerRegistry) InstanceID() InstanceID {
	return r.instance
}

// Listeners returns all registered listener addresses, sorted for consistency.
func (r *ListenerRegistry) Listeners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]string, 0, len(r.listeners))
	for addr := range r.listeners {
		result = append(result, addr)
	}
	sort.Strings(result)
	return result
}

// LoopError indicates a routing loop was detected.
type LoopError struct {
	Backend   string
	Instance  InstanceID
	Reason    string
}

func (e *LoopError) Error() string {
	return "loop detected: " + e.Reason
}

// IsLoopError checks if an error is a loop detection error.
func IsLoopError(err error) bool {
	_, ok := err.(*LoopError)
	return ok
}

// HopCountHeaders are used for loop detection in terminated HTTP.
const (
	HeaderTLSrouterID    = "X-Tlsrouter-Id"
	HeaderTLSrouterHops  = "X-Tlsrouter-Hops"
	HeaderTLSrouterVia   = "X-Tlsrouter-Via" // Comma-separated instance IDs
	HeaderTLSrouterError = "X-Tlsrouter-Error"
)

// MaxHops is the maximum number of TLSrouter hops allowed.
const MaxHops = 10

// CheckLoop checks if routing to a backend would create a loop.
// Returns a LoopError if a loop is detected.
func (r *ListenerRegistry) CheckLoop(backendAddr string, incomingID InstanceID, incomingHops int) error {
	// Check 1: Backend is one of our listeners (direct loop)
	if r.IsSelf(backendAddr) {
		return &LoopError{
			Backend:  backendAddr,
			Instance: r.instance,
			Reason:   "backend address matches local listener",
		}
	}

	// Check 2: Backend host matches one of our listeners (different port)
	backendHost, _, err := net.SplitHostPort(backendAddr)
	if err == nil && r.IsSelfHost(backendHost) {
		return &LoopError{
			Backend:  backendAddr,
			Instance: r.instance,
			Reason:   "backend host matches local listener host",
		}
	}

	// Check 3: Incoming request already came from us (chain loop)
	if incomingID != "" && incomingID == r.instance {
		return &LoopError{
			Backend:  backendAddr,
			Instance: r.instance,
			Reason:   "request already passed through this instance",
		}
	}

	// Check 4: Hop count exceeded
	if incomingHops >= MaxHops {
		return &LoopError{
			Backend:  backendAddr,
			Instance: r.instance,
			Reason:   "hop count exceeded",
		}
	}

	return nil
}

// HopInfo contains incoming hop information from headers.
type HopInfo struct {
	ID   InstanceID
	Hops int
	Via  []InstanceID
}

// ParseHopInfo extracts hop information from HTTP headers.
// Used for loop detection in terminated HTTP.
func ParseHopInfo(headers map[string][]string) HopInfo {
	info := HopInfo{}

	if ids := headers[HeaderTLSrouterID]; len(ids) > 0 {
		info.ID = InstanceID(ids[0])
	}

	if hops := headers[HeaderTLSrouterHops]; len(hops) > 0 {
		// Parse hop count
		h := 0
		for _, c := range hops[0] {
			if c >= '0' && c <= '9' {
				h = h*10 + int(c-'0')
			}
		}
		info.Hops = h
	}

	if via := headers[HeaderTLSrouterVia]; len(via) > 0 {
		// Parse comma-separated instance IDs
		// Format: "id1,id2,id3"
		for _, v := range via {
			start := 0
			for i := 0; i <= len(v); i++ {
				if i == len(v) || v[i] == ',' {
					if i > start {
						info.Via = append(info.Via, InstanceID(v[start:i]))
					}
					start = i + 1
				}
			}
		}
	}

	return info
}

// AddHopHeaders adds loop detection headers to outgoing HTTP requests.
// Call this before proxying to a backend.
func AddHopHeaders(headers map[string][]string, instance InstanceID, incoming HopInfo) map[string][]string {
	// Copy headers to avoid mutating input
	result := make(map[string][]string)
	for k, v := range headers {
		result[k] = append([]string{}, v...)
	}

	// Set our instance ID
	result[HeaderTLSrouterID] = []string{string(instance)}

	// Increment hop count
	hops := incoming.Hops + 1
	result[HeaderTLSrouterHops] = []string{intToStr(hops)}

	// Build Via chain: previous instances + the one that forwarded to us + us
	via := incoming.Via
	if incoming.ID != "" {
		via = append(via, incoming.ID)
	}
	via = append(via, instance)
	viaStr := ""
	for i, id := range via {
		if i > 0 {
			viaStr += ","
		}
		viaStr += string(id)
	}
	result[HeaderTLSrouterVia] = []string{viaStr}

	return result
}

func intToStr(n int) string {
	if n <= 0 {
		return "0"
	}
	// Handle numbers
	var buf [12]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = '0' + byte(n%10)
		n /= 10
	}
	return string(buf[pos:])
}